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
 *   - Cache miss / error => reported as registrySignals.status, never as a
 *     hit; changes the verdict only when the caller sets onRegistryUnknown
 */

import { classifyWithRegex } from '../regex';
import { packIdentity } from '../regex/pack';
import { classifyWithNanoMindDaemon } from '../guard-client/nanomind-adapter';
import type { NanoMindAdapterOptions } from '../guard-client/nanomind-adapter';
import { verifyClassification } from '../../arp/verify';
import { RegistryIntelligenceCache } from '../../registry';
import type { RegistryLookupResult } from '../../registry';
import { assembleRiskContext } from '../../risk';
import { normalize } from '../../normalize';
import type { ClassifierResult, ComplyLayer, ComplyResult, PolicyPack, RegistryUnknownAction, RiskContext, Violation, ViolationView } from '../../types';
import type {
  NanoMindGuardResult,
  NanoMindGuardVerifyOptions,
} from '../../arp/types';

// The Guard layer is invoked via the nanomind-daemon adapter
// (classifyWithNanoMindDaemon). The adapter is a stateless function so
// nothing is constructed at module-top — the daemon base URL is
// resolved at call time so the MOCK_NANOMIND_URL test override takes
// effect even when it changes between classify() calls.

export interface DualLayerOptions {
  guardVerifyOptions?: NanoMindGuardVerifyOptions;
  guardResult?: NanoMindGuardResult;
  /**
   * Connection settings for the nanomind daemon (`baseUrl`, `timeoutMs`,
   * `agentId`). Used when no pre-computed `guardResult` is supplied.
   * Defaults to `http://127.0.0.1:47200`.
   */
  guardOptions?: NanoMindAdapterOptions;
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
  /**
   * Whether to attempt the nanomind-daemon when no signed Guard result is
   * supplied. Defaults to true. The attempt is one POST carrying the content
   * verbatim to the daemon address; set to false to make no such request and
   * classify with the regex layer alone.
   */
  useGuard?: boolean;
  /**
   * Verdict to give when the Registry lookup for sourcePackage is a miss or
   * an error. Unset, the verdict is left as the classifiers set it. With
   * sourcePackage set and no registryCache, or set to an empty string, the
   * lookup counts as an error.
   */
  onRegistryUnknown?: RegistryUnknownAction;
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
 * comparison against the threshold - making classification more sensitive
 * for lower-trust tiers. A lower multiplier dampens the score for
 * well-verified packages.
 *
 * trustLevel 0 (Blocked): ARP's responsibility; L2 defers → 1.00
 * trustLevel 1 (Warning): 1.35  - heightened sensitivity
 * trustLevel 2 (Listed):  1.15  - mildly elevated
 * trustLevel 3 (Scanned): 1.00  - baseline (current behaviour)
 * trustLevel 4 (Verified): 0.80 - verified packages get a grace margin
 * Out-of-range / missing:  1.00  - safe default
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
 * Reject an onRegistryUnknown value that is neither action. Read as unset, a
 * JavaScript caller's typo would leave the verdict alone on a miss or error.
 */
export function assertRegistryUnknownAction(
  value: unknown,
): asserts value is RegistryUnknownAction | undefined {
  if (value !== undefined && value !== 'violation' && value !== 'deny') {
    const got = typeof value === 'string' ? JSON.stringify(value) : value === null ? 'null' : typeof value;
    throw new TypeError(`onRegistryUnknown must be 'violation' or 'deny' (got ${got})`);
  }
}

/**
 * Reject a sourcePackage that is set but not a string. Read as unset, a
 * JavaScript caller's null or number would skip the Registry lookup that
 * onRegistryUnknown was set to fail closed on.
 */
export function assertSourcePackage(value: unknown): asserts value is string | undefined {
  if (value !== undefined && typeof value !== 'string') {
    const got = value === null ? 'null' : typeof value;
    throw new TypeError(`sourcePackage must be a string (got ${got})`);
  }
}

/**
 * Reject a guardOptions that is set but not an object. A misplaced URL string
 * (guardOptions: 'http://...') would otherwise be read as an object with no
 * baseUrl and the default address used instead. `name` is how the error
 * refers to the value, e.g. 'comply: options.guardOptions'.
 */
export function assertGuardOptions(
  value: unknown,
  name: string,
): asserts value is NanoMindAdapterOptions | undefined {
  if (value !== undefined && (value === null || typeof value !== 'object' || Array.isArray(value))) {
    const got = value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
    throw new TypeError(`${name} must be an object like { baseUrl: 'http://host:port' }, got ${got}`);
  }
}

/**
 * Apply the Registry L2 step to a classified result when the caller named a
 * source package and gave a cache to look it up in or an onRegistryUnknown
 * action. Exported so comply() runs the same step on empty content, which it
 * does not classify: the lookup depends on the source, not the content.
 */
export function applyRegistry(
  base: Omit<ComplyResult, 'registrySignals'>,
  options?: DualLayerOptions,
): ComplyResult {
  // A caller who set onRegistryUnknown gets it for a source package with no
  // cache to look it up in as well: that lookup is an error, not a skipped
  // check. The same holds for an empty name, which no Registry entry has.
  if (options?.sourcePackage === undefined || !(options.registryCache || options.onRegistryUnknown)) {
    return base;
  }
  const assembled = options.riskContext !== undefined
    ? assembleRiskContext(options.riskContext)
    : undefined;
  let lookup: RegistryLookupResult;
  if (options.sourcePackage === '') {
    lookup = { status: 'error', reason: 'empty source package name' };
  } else if (options.registryCache) {
    lookup = options.registryCache.lookup(options.sourcePackage);
  } else {
    lookup = { status: 'error', reason: 'no registry cache supplied' };
  }
  return applyRegistryL2(
    base,
    lookup,
    options.sourcePackage,
    assembled?.trustLevel,
    options.onRegistryUnknown,
  );
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
  // `useGuard: false` is how a caller keeps content off the Guard request, so
  // a near miss such as the string 'false' must not be read as "attempt it".
  if (options?.useGuard !== undefined && typeof options.useGuard !== 'boolean') {
    throw new TypeError(
      `classifyDualLayer: options.useGuard must be a boolean (got ${typeof options.useGuard})`,
    );
  }
  assertRegistryUnknownAction(options?.onRegistryUnknown);
  assertSourcePackage(options?.sourcePackage);
  assertGuardOptions(options?.guardOptions, 'classifyDualLayer: options.guardOptions');

  // Pre-regex adversarial normalization (threat-model scope 2026-05-28).
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
      // Signature valid - build Guard classifier result from the verified classification
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
    // Attempt Guard classification via the nanomind-daemon adapter.
    // Returns null when the daemon is unreachable, the response is
    // malformed, or the response times out — silent fallback to
    // regex-only is the documented contract. The attempt sends the content
    // to the daemon address, so `useGuard: false` skips it entirely.
    const guardResult = options?.useGuard === false
      ? null
      : await classifyWithNanoMindDaemon(content, options?.guardOptions);

    const allViolations: Violation[] = [...regexResult.violations];
    if (guardResult) {
      allViolations.push(...guardResult.violations);
    }

    baseResult = {
      verdict: mergeVerdicts(regexResult, guardResult),
      violations: allViolations,
      // Only set `guard` when an actual result exists, so the key is
      // absent (not `undefined`) on the regex-only fallback path. This
      // matches the declared `guard?: ClassifierResult` optional shape
      // and lets consumers use `'guard' in classifierResults` reliably.
      classifierResults: guardResult
        ? { regex: regexResult, guard: guardResult }
        : { regex: regexResult },
    };
  }

  // ---------------------------------------------------------------------------
  // Registry L2 threshold/block logic (Section 3.1, lines 239-263)
  // AC-005: synchronous cache lookup only - never fetch in the hot path.
  // ---------------------------------------------------------------------------
  let result = applyRegistry(baseResult, options);

  // ---------------------------------------------------------------------------
  // Policy pack enforcement: DENY rules hard-block, WARN rules add violations.
  // Applied after Registry L2 so policy sees the fully-resolved verdict.
  // REDACT is out of scope in V1 - skipped silently.
  // ---------------------------------------------------------------------------
  if (options?.policyPack) {
    result = applyPolicyPack(result, options.policyPack);
  }

  // Attach normalization metadata so consumers have an audit trail of
  // what canonicalization the input went through. On ANY DENY verdict
  // (parse-to-deny on invalid signature, Registry supply-chain block,
  // policy-pack DENY) we omit originalContent and normalizedContent:
  // by definition the input has been flagged as harmful, may carry
  // attacker-controlled bytes (ANSI escapes, log-injection newlines,
  // null bytes), and downstream log pipelines should not echo it back
  // into operator dashboards without redaction. The structured
  // `normalizations` array is safe to keep - it carries counts, not
  // raw bytes - and lets auditors see which transforms ran.
  const isDeny = result.verdict === 'DENY';
  if (!isDeny) {
    result.originalContent = norm.originalContent;
    result.normalizedContent = norm.normalizedContent;
  }
  result.normalizations = norm.steps;

  // Name the pack the regex layer ran and the layers that ran. Guard is
  // listed only when its classification was accepted into classifierResults:
  // a regex-only fallback or a rejected signature must not claim it ran.
  const layers: ComplyLayer[] = ['normalize', 'regex'];
  if (result.classifierResults.guard !== undefined) layers.push('guard');
  result.pack = packIdentity();
  result.layers = layers;

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
 * the normalized view - avoids double-reporting the same SSN that's
 * detected both raw and via the compact-form pass.
 */
export function scanAllViews(norm: ReturnType<typeof normalize>): ClassifierResult {
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
    // ext.source matches ViolationView 1:1 - use it directly. When
    // ext.offsetMap is present (compact view), classifyWithRegex projects
    // each match back to its precise original range; otherwise it falls
    // back to the whole-token originalAnchor (decoded-base64 / decoded-url).
    const scan = classifyWithRegex(ext.decoded, {
      view: ext.source,
      ...(ext.offsetMap !== undefined
        ? { offsetMap: ext.offsetMap }
        : { originalAnchor: { start: ext.originalStart, end: ext.originalEnd } }),
    });
    // Dedup key:
    //  - For findings with a precise offsetMap (compact + normalized
    //    views): the originalStart/End pair uniquely identifies the
    //    finding. Cross-view dedup against the normalized scan works.
    //  - For decoded views (originalAnchor): every match in the same
    //    encoded blob shares the same originalStart/End, so we must
    //    also include the in-view start/end (and the view source) to
    //    keep multiple credentials inside one blob from collapsing
    //    onto a single dedup key.
    const hasOffsetMap = ext.offsetMap !== undefined;
    for (const v of scan.violations) {
      const key = hasOffsetMap
        ? `${v.type}@${v.originalStart}-${v.originalEnd}`
        : `${v.type}@${v.originalStart}-${v.originalEnd}#${v.view}:${v.start}-${v.end}`;
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
 *     by 0.15 - implemented here as: if the current verdict is CLEAN but the
 *     anomaly score is elevated, re-evaluate with the lowered threshold and
 *     promote to VIOLATION.
 *   - Cache miss / error => reported as registrySignals.status, never as a
 *     hit (AC-002). The verdict is left alone unless the caller set
 *     onRegistryUnknown: 'violation' raises CLEAN to VIOLATION, 'deny' sets
 *     DENY, and either appends a REGISTRY_UNKNOWN violation. Without it, a
 *     subsequent warm() + re-classify is the correct path.
 */
function applyRegistryL2(
  base: Omit<ComplyResult, 'registrySignals'>,
  lookup: RegistryLookupResult,
  packageName: string,
  trustLevel?: number,
  onUnknown?: RegistryUnknownAction,
): ComplyResult {
  const mult = sensitivityMultiplier(trustLevel);

  if (lookup.status === 'error' || lookup.status === 'miss') {
    // AC-002: unknown is never reported as a hit. The status says which kind.
    const registrySignals: ComplyResult['registrySignals'] = {
      status: lookup.status,
      fleetAnomalyScore: null,
      effectiveAnomalyScore: null,
      trustSensitivityMultiplier: mult,
      thresholdDelta: 0,
      supplyChainBlock: false,
      packageName,
    };
    if (onUnknown === undefined) {
      return { ...base, registrySignals };
    }
    const unknownViolation: Violation = {
      type: 'REGISTRY_UNKNOWN',
      value: `status=${lookup.status}`,
      start: 0,
      end: 0,
      confidence: 1.0,
      classifier: 'regex',
    };
    return {
      ...base,
      // 'violation' never lowers a DENY the classifiers already reached.
      verdict: onUnknown === 'deny' || base.verdict === 'DENY' ? 'DENY' : 'VIOLATION',
      violations: [...base.violations, unknownViolation],
      registrySignals,
    };
  }

  const { intelligence } = lookup;
  const fleetScore = intelligence.fleetAnomalySignal?.anomalyScore ?? null;
  const activeAlerts = intelligence.supplyChainAlerts ?? [];
  const hasSupplyChainAlert = activeAlerts.length > 0;

  // Hard block: any active supply-chain alert => DENY regardless of prior verdict.
  // The sensitivity multiplier does not apply here - supply-chain blocks are absolute.
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
        status: 'hit',
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
      status: 'hit',
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
 *   - REDACT rule: out of scope in V1 - skipped silently.
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
