/**
 * Dual-layer classifier merge logic with ARP signature verification and
 * Registry L2 threshold/block logic (Section 3.1, lines 239-263).
 *
 * Both the regex classifier and Guard classifier must return CLEAN
 * for content to pass. If either flags a violation, the result is VIOLATION.
 * If either returns DENY, the result is DENY (highest severity wins).
 *
 * Parse-to-deny (CR-001): unsigned, invalid-signature, or missing Guard
 * output is treated as DENY when Guard is available. In V1 (Guard
 * unavailable), regex-only classification is used.
 *
 * Registry L2 logic (AC-002, AC-005):
 *   - fleetAnomalySignal > 0.30 => classification threshold lowered by 0.15
 *   - Any active supply-chain alert on the source package => hard block (DENY)
 *   - Cache miss / error => treat as unknown, do NOT treat as clean
 */

import { classifyWithRegex } from '../regex';
import { GuardClient } from '../guard-client';
import { verifyClassification } from '../../arp/verify';
import { RegistryIntelligenceCache } from '../../registry';
import { assembleRiskContext } from '../../risk';
import { normalize } from '../../normalize';
import type { ClassifierResult, ComplyResult, PolicyPack, RiskContext, Violation, ViolationView } from '../../types';
import type {
  NanoMindGuardResult,
  NanoMindGuardVerifyOptions,
} from '../../arp/types';

const guardClient = new GuardClient();

export interface DualLayerOptions {
  guardVerifyOptions?: NanoMindGuardVerifyOptions;
  guardResult?: NanoMindGuardResult;
  /**
   * Registry cache instance. When provided, L2 threshold/block logic runs
   * against the pre-warmed cache (AC-005: synchronous lookup only).
   */
  registryCache?: RegistryIntelligenceCache;
  /**
   * Package/agent name to look up in the Registry. Required for L2 logic.
   * Typically the source agent identifier from the message envelope.
   */
  sourcePackage?: string;
  /**
   * Loaded policy pack to enforce after regex+Guard merge and Registry L2.
   * DENY rules hard-block (verdict → DENY). WARN rules append a violation.
   * REDACT rules are skipped in V1.
   */
  policyPack?: PolicyPack;
  /**
   * Caller-supplied risk context. When provided, Registry L2 uses the
   * trust tier (0–4) to scale the fleet anomaly score via a sensitivity
   * multiplier before comparing against the anomaly threshold.
   */
  riskContext?: RiskContext;
}

// ---------------------------------------------------------------------------
// Registry L2 constants (Section 3.1, lines 239-263)
// ---------------------------------------------------------------------------
const FLEET_ANOMALY_THRESHOLD = 0.30;
const THRESHOLD_DELTA = -0.15;

/**
 * Map a Registry trust tier (0–4) to an anomaly-score sensitivity multiplier.
 *
 * A higher multiplier means the effective anomaly score is amplified before
 * comparison against the threshold — making classification more sensitive
 * for lower-trust tiers. A lower multiplier dampens the score for
 * well-verified packages.
 *
 * trustLevel 0 (Blocked): ARP's responsibility; L2 defers → 1.00
 * trustLevel 1 (Warning): 1.35  — heightened sensitivity
 * trustLevel 2 (Listed):  1.15  — mildly elevated
 * trustLevel 3 (Scanned): 1.00  — baseline (current behaviour)
 * trustLevel 4 (Verified): 0.80 — verified packages get a grace margin
 * Out-of-range / missing:  1.00  — safe default
 */
function sensitivityMultiplier(trustLevel: number | undefined): number {
  switch (trustLevel) {
    case 1: return 1.35;
    case 2: return 1.15;
    case 3: return 1.00;
    case 4: return 0.80;
    default: return 1.00; // covers 0 (Blocked, ARP handles) and out-of-range
  }
}

/**
 * Run content through both classification layers and merge results.
 *
 * When guardResult and guardVerifyOptions are provided, the Guard
 * classification is signature-verified before being trusted. Invalid
 * signatures trigger parse-to-deny (CR-001).
 *
 * When registryCache and sourcePackage are provided, Registry L2 logic
 * is applied after classification (AC-005: synchronous cache lookup only).
 */
export async function classifyDualLayer(
  content: string,
  options?: DualLayerOptions,
): Promise<ComplyResult> {
  // Pre-regex adversarial normalization (CHIEF-CSR 2026-05-28).
  // NFKC + zero-width strip produce normalizedContent; the compact form
  // and any Base64/URL-decoded segments are scanned in addition.
  const norm = normalize(content);
  const regexResult = scanAllViews(norm);

  let baseResult: Omit<ComplyResult, 'registrySignals'>;

  // If Guard result and verification options are provided, verify the signature
  if (options?.guardResult && options?.guardVerifyOptions) {
    const verifyResult = await verifyClassification(
      options.guardResult,
      options.guardVerifyOptions,
    );

    if (!verifyResult.valid) {
      // Parse-to-deny: invalid signature means we cannot trust the classification
      baseResult = {
        verdict: 'DENY',
        violations: regexResult.violations,
        classifierResults: { regex: regexResult },
        signatureValid: false,
        verifyError: { code: verifyResult.code, reason: verifyResult.reason },
      };
    } else {
      // Signature valid — build Guard classifier result from the verified classification
      const guardClassifierResult: ClassifierResult = {
        classifier: 'guard',
        verdict: verifyResult.classification === 'documentation' ||
                 verifyResult.classification === 'code-analysis' ||
                 verifyResult.classification === 'data-read'
          ? 'CLEAN' : 'VIOLATION',
        violations: verifyResult.classification !== 'documentation' &&
                    verifyResult.classification !== 'code-analysis' &&
                    verifyResult.classification !== 'data-read'
          ? [{
              type: verifyResult.classification,
              value: verifyResult.classification,
              start: 0,
              end: content.length,
              confidence: verifyResult.confidence,
              classifier: 'guard',
            }]
          : [],
      };

      const allViolations: Violation[] = [
        ...regexResult.violations,
        ...guardClassifierResult.violations,
      ];

      baseResult = {
        verdict: mergeVerdicts(regexResult, guardClassifierResult),
        violations: allViolations,
        classifierResults: {
          regex: regexResult,
          guard: guardClassifierResult,
        },
        signatureValid: true,
      };
    }
  } else {
    // Attempt Guard classifier via IPC (V1: always returns null)
    const guardResult = await guardClient.classify(content);

    const allViolations: Violation[] = [...regexResult.violations];
    if (guardResult) {
      allViolations.push(...guardResult.violations);
    }

    baseResult = {
      verdict: mergeVerdicts(regexResult, guardResult),
      violations: allViolations,
      classifierResults: {
        regex: regexResult,
        guard: guardResult ?? undefined,
      },
    };
  }

  // ---------------------------------------------------------------------------
  // Registry L2 threshold/block logic (Section 3.1, lines 239-263)
  // AC-005: synchronous cache lookup only — never fetch in the hot path.
  // ---------------------------------------------------------------------------
  let result: ComplyResult;
  if (options?.registryCache && options?.sourcePackage) {
    const assembled = options.riskContext !== undefined
      ? assembleRiskContext(options.riskContext)
      : undefined;
    result = applyRegistryL2(
      baseResult,
      options.registryCache,
      options.sourcePackage,
      assembled?.trustLevel,
    );
  } else {
    result = baseResult;
  }

  // ---------------------------------------------------------------------------
  // Policy pack enforcement: DENY rules hard-block, WARN rules add violations.
  // Applied after Registry L2 so policy sees the fully-resolved verdict.
  // REDACT is out of scope in V1 — skipped silently.
  // ---------------------------------------------------------------------------
  if (options?.policyPack) {
    result = applyPolicyPack(result, options.policyPack);
  }

  // Attach normalization metadata to every result so consumers have an
  // audit trail of what canonicalization the input went through.
  result.originalContent = norm.originalContent;
  result.normalizedContent = norm.normalizedContent;
  result.normalizations = norm.steps;

  return result;
}

/**
 * Run the regex classifier across every content view produced by the
 * normalization pipeline: the canonical normalized stream, the compact
 * whitespace-removed view, and any Base64/URL-decoded extractions.
 *
 * Findings are tagged with the view they came from. Duplicates are
 * suppressed when a match in a non-normalized view points at the same
 * (type, originalStart, originalEnd) range as one already found in
 * the normalized view — avoids double-reporting the same SSN that's
 * detected both raw and via the compact-form pass.
 */
function scanAllViews(norm: ReturnType<typeof normalize>): ClassifierResult {
  const normalizedScan = classifyWithRegex(norm.normalizedContent, {
    view: 'normalized',
    offsetMap: norm.offsetMap,
  });

  const all: Violation[] = [...normalizedScan.violations];
  const seen = new Set<string>();
  for (const v of all) {
    seen.add(`${v.type}@${v.originalStart}-${v.originalEnd}`);
  }

  for (const ext of norm.decodedExtractions) {
    const viewTag: ViolationView =
      ext.source === 'base64' ? 'decoded-base64' : 'decoded-url';
    // The compact-form view (whitespace-stripped) is also carried as a
    // DecodedExtraction with source='url'; distinguish by checking
    // whether the decoded text contains percent-escapes the original
    // would have had. Compact form has no percent-escapes; URL-decoded
    // content does (otherwise tryUrlDecode would have rejected it).
    const isCompactForm = ext.source === 'url' && !ext.decoded.includes('%');
    const taggedView: ViolationView = isCompactForm ? 'compact' : viewTag;

    const scan = classifyWithRegex(ext.decoded, {
      view: taggedView,
      originalAnchor: { start: ext.originalStart, end: ext.originalEnd },
    });
    for (const v of scan.violations) {
      const key = `${v.type}@${v.originalStart}-${v.originalEnd}`;
      if (seen.has(key)) continue;
      seen.add(key);
      all.push(v);
    }
  }

  return {
    classifier: 'regex',
    verdict: all.length === 0 ? 'CLEAN' : 'VIOLATION',
    violations: all,
  };
}

/**
 * Apply Registry L2 logic to an already-classified result.
 *
 *   - Hard block (DENY) if any active supply-chain alert exists for the package.
 *   - Fleet anomaly score > 0.30 lowers the effective classification threshold
 *     by 0.15 — implemented here as: if the current verdict is CLEAN but the
 *     anomaly score is elevated, re-evaluate with the lowered threshold and
 *     promote to VIOLATION.
 *   - Cache miss / error => treat as unknown, not clean (AC-002). We do NOT
 *     promote CLEAN to VIOLATION on a miss alone, but we record the delta so
 *     callers can decide. A subsequent warm() + re-classify is the correct path.
 */
function applyRegistryL2(
  base: Omit<ComplyResult, 'registrySignals'>,
  cache: RegistryIntelligenceCache,
  packageName: string,
  trustLevel?: number,
): ComplyResult {
  const lookup = cache.lookup(packageName);
  const mult = sensitivityMultiplier(trustLevel);

  if (lookup.status === 'error' || lookup.status === 'miss') {
    // AC-002: unknown is NOT clean. Surface the signal; do not silently pass.
    return {
      ...base,
      registrySignals: {
        fleetAnomalyScore: null,
        effectiveAnomalyScore: null,
        trustSensitivityMultiplier: mult,
        thresholdDelta: 0,
        supplyChainBlock: false,
        packageName,
      },
    };
  }

  const { intelligence } = lookup;
  const fleetScore = intelligence.fleetAnomalySignal?.anomalyScore ?? null;
  const activeAlerts = intelligence.supplyChainAlerts ?? [];
  const hasSupplyChainAlert = activeAlerts.length > 0;

  // Hard block: any active supply-chain alert => DENY regardless of prior verdict.
  // The sensitivity multiplier does not apply here — supply-chain blocks are absolute.
  if (hasSupplyChainAlert) {
    const effectiveScore = fleetScore !== null ? fleetScore * mult : null;
    const blockViolation: Violation = {
      type: 'SUPPLY_CHAIN_ALERT',
      value: activeAlerts.map(a => a.id).join(','),
      start: 0,
      end: 0,
      confidence: 1.0,
      classifier: 'regex',
    };
    return {
      ...base,
      verdict: 'DENY',
      violations: [...base.violations, blockViolation],
      registrySignals: {
        fleetAnomalyScore: fleetScore,
        effectiveAnomalyScore: effectiveScore,
        trustSensitivityMultiplier: mult,
        thresholdDelta: 0,
        supplyChainBlock: true,
        packageName,
      },
    };
  }

  // Apply trust-level sensitivity: scale the raw anomaly score by the multiplier
  // before comparing against the threshold. Higher-trust packages (tier 4) get a
  // grace margin; lower-trust packages (tier 1–2) are evaluated more strictly.
  const effectiveScore = fleetScore !== null ? fleetScore * mult : null;

  const thresholdDelta =
    effectiveScore !== null && effectiveScore > FLEET_ANOMALY_THRESHOLD
      ? THRESHOLD_DELTA
      : 0;

  // If effective anomaly is elevated and the current verdict is CLEAN, promote to VIOLATION.
  const adjustedVerdict =
    thresholdDelta < 0 && base.verdict === 'CLEAN' ? 'VIOLATION' : base.verdict;

  const violations = [...base.violations];
  if (adjustedVerdict === 'VIOLATION' && base.verdict === 'CLEAN') {
    violations.push({
      type: 'FLEET_ANOMALY_ELEVATED',
      value: `anomalyScore=${fleetScore},effectiveScore=${effectiveScore}`,
      start: 0,
      end: 0,
      confidence: effectiveScore ?? 0,
      classifier: 'regex',
    });
  }

  return {
    ...base,
    verdict: adjustedVerdict,
    violations,
    registrySignals: {
      fleetAnomalyScore: fleetScore,
      effectiveAnomalyScore: effectiveScore,
      trustSensitivityMultiplier: mult,
      thresholdDelta,
      supplyChainBlock: false,
      packageName,
    },
  };
}

/**
 * Apply policy pack rules to an already-classified result.
 *
 *   - DENY rule: if any detected violation type matches a rule pattern → verdict = DENY
 *     and a POLICY_DENY violation is appended for auditability.
 *   - WARN rule: if any detected violation type matches a rule pattern → a POLICY_WARN
 *     violation is appended; verdict is not escalated by WARN alone.
 *   - REDACT rule: out of scope in V1 — skipped silently.
 *
 * Policy is applied after Registry L2 so it sees the fully-resolved verdict and
 * violation set (including SUPPLY_CHAIN_ALERT and FLEET_ANOMALY_ELEVATED entries).
 */
function applyPolicyPack(result: ComplyResult, pack: PolicyPack): ComplyResult {
  const detectedTypes = new Set(result.violations.map(v => v.type));

  let verdict = result.verdict;
  const additionalViolations: Violation[] = [];

  for (const rule of pack.rules) {
    if (rule.action === 'REDACT') continue; // V1: out of scope

    const matched = rule.patterns.some(p => detectedTypes.has(p));
    if (!matched) continue;

    if (rule.action === 'DENY') {
      verdict = 'DENY';
      additionalViolations.push({
        type: `POLICY_DENY:${rule.id}`,
        value: rule.name,
        start: 0,
        end: 0,
        confidence: 1.0,
        classifier: 'regex',
      });
    } else if (rule.action === 'WARN') {
      additionalViolations.push({
        type: `POLICY_WARN:${rule.id}`,
        value: rule.name,
        start: 0,
        end: 0,
        confidence: 1.0,
        classifier: 'regex',
      });
    }
  }

  if (additionalViolations.length === 0) return result;

  return {
    ...result,
    verdict,
    violations: [...result.violations, ...additionalViolations],
  };
}

function mergeVerdicts(
  regex: ClassifierResult,
  guard: ClassifierResult | null,
): ComplyResult['verdict'] {
  const verdicts = [regex.verdict];
  if (guard) verdicts.push(guard.verdict);

  if (verdicts.includes('DENY')) return 'DENY';
  if (verdicts.includes('VIOLATION')) return 'VIOLATION';
  return 'CLEAN';
}
