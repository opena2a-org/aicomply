/**
 * Tests for policy pack enforcement in classifyDualLayer.
 *
 * Policy rules are applied after the regex+Guard merge and Registry L2:
 *   - DENY rule: hard-blocks (verdict → DENY), appends POLICY_DENY violation
 *   - WARN rule: appends POLICY_WARN violation, does not escalate verdict
 *   - REDACT rule: skipped silently (V1 out-of-scope)
 *   - No policy: behaviour unchanged
 */

import { classifyDualLayer } from '..';
import { comply } from '../../..';
import type { PolicyPack } from '../../../types';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SSN_CONTENT = 'Patient SSN: 123-45-6789';
const NPI_CONTENT = 'Provider NPI: 1234567893';
const SAFE_CONTENT = 'No sensitive information here.';

const DENY_PACK: PolicyPack = {
  name: 'test-deny',
  version: '1.0.0',
  rules: [
    {
      id: 'block-ssn',
      name: 'Block SSN',
      description: 'Hard-block on SSN detection',
      patterns: ['SSN'],
      action: 'DENY',
      severity: 'critical',
    },
  ],
};

const WARN_PACK: PolicyPack = {
  name: 'test-warn',
  version: '1.0.0',
  rules: [
    {
      id: 'warn-npi',
      name: 'Warn on NPI',
      description: 'Add a warning violation for NPI detection',
      patterns: ['NPI'],
      action: 'WARN',
      severity: 'medium',
    },
  ],
};

const REDACT_PACK: PolicyPack = {
  name: 'test-redact',
  version: '1.0.0',
  rules: [
    {
      id: 'redact-ssn',
      name: 'Redact SSN',
      description: 'REDACT is V1 out-of-scope — skipped silently',
      patterns: ['SSN'],
      action: 'REDACT',
      severity: 'critical',
    },
  ],
};

const MIXED_PACK: PolicyPack = {
  name: 'test-mixed',
  version: '1.0.0',
  rules: [
    {
      id: 'deny-ssn',
      name: 'Deny SSN',
      description: 'Hard-block SSN',
      patterns: ['SSN'],
      action: 'DENY',
      severity: 'critical',
    },
    {
      id: 'warn-npi',
      name: 'Warn NPI',
      description: 'Warn on NPI',
      patterns: ['NPI'],
      action: 'WARN',
      severity: 'medium',
    },
  ],
};

// ---------------------------------------------------------------------------
// DENY rule
// ---------------------------------------------------------------------------

describe('Policy pack: DENY rule', () => {
  it('hard-blocks when DENY rule pattern matches a detected violation', async () => {
    const result = await classifyDualLayer(SSN_CONTENT, { policyPack: DENY_PACK });

    expect(result.verdict).toBe('DENY');
  });

  it('appends a POLICY_DENY violation with the rule id', async () => {
    const result = await classifyDualLayer(SSN_CONTENT, { policyPack: DENY_PACK });

    const policyViolation = result.violations.find(v => v.type === 'POLICY_DENY:block-ssn');
    expect(policyViolation).toBeDefined();
    expect(policyViolation?.value).toBe('Block SSN');
    expect(policyViolation?.confidence).toBe(1.0);
  });

  it('preserves the original regex violations alongside the policy violation', async () => {
    const result = await classifyDualLayer(SSN_CONTENT, { policyPack: DENY_PACK });

    expect(result.violations.some(v => v.type === 'SSN')).toBe(true);
    expect(result.violations.some(v => v.type === 'POLICY_DENY:block-ssn')).toBe(true);
  });

  it('does not hard-block when DENY rule pattern does not match detected violations', async () => {
    // DENY_PACK targets SSN; safe content has no violations → rule does not fire
    const result = await classifyDualLayer(SAFE_CONTENT, { policyPack: DENY_PACK });

    expect(result.verdict).toBe('CLEAN');
    expect(result.violations.some(v => v.type.startsWith('POLICY_DENY'))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// WARN rule
// ---------------------------------------------------------------------------

describe('Policy pack: WARN rule', () => {
  it('appends a POLICY_WARN violation when WARN rule pattern matches', async () => {
    const result = await classifyDualLayer(NPI_CONTENT, { policyPack: WARN_PACK });

    const warnViolation = result.violations.find(v => v.type === 'POLICY_WARN:warn-npi');
    expect(warnViolation).toBeDefined();
    expect(warnViolation?.value).toBe('Warn on NPI');
  });

  it('does not escalate verdict beyond VIOLATION for a WARN-only rule', async () => {
    const result = await classifyDualLayer(NPI_CONTENT, { policyPack: WARN_PACK });

    // NPI detected → VIOLATION from regex. WARN should not elevate to DENY.
    expect(result.verdict).toBe('VIOLATION');
    expect(result.verdict).not.toBe('DENY');
  });

  it('does not add WARN violation when pattern does not match', async () => {
    // WARN_PACK targets NPI; SSN content has no NPI violation
    const result = await classifyDualLayer(SSN_CONTENT, { policyPack: WARN_PACK });

    expect(result.violations.some(v => v.type.startsWith('POLICY_WARN'))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// REDACT rule (V1 out-of-scope — skipped silently)
// ---------------------------------------------------------------------------

describe('Policy pack: REDACT rule (V1 no-op)', () => {
  it('does not change verdict or add violations for REDACT action', async () => {
    const result = await classifyDualLayer(SSN_CONTENT, { policyPack: REDACT_PACK });

    // Regex still produces VIOLATION for SSN; REDACT rule adds nothing
    expect(result.verdict).toBe('VIOLATION');
    expect(result.violations.every(v => !v.type.startsWith('POLICY_DENY'))).toBe(true);
    expect(result.violations.every(v => !v.type.startsWith('POLICY_WARN'))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// No policy pack
// ---------------------------------------------------------------------------

describe('Policy pack: no policy provided', () => {
  it('leaves verdict and violations unchanged when no policyPack option', async () => {
    const withPolicy = await classifyDualLayer(SSN_CONTENT, { policyPack: DENY_PACK });
    const withoutPolicy = await classifyDualLayer(SSN_CONTENT);

    // With policy → DENY; without → VIOLATION (regex only)
    expect(withPolicy.verdict).toBe('DENY');
    expect(withoutPolicy.verdict).toBe('VIOLATION');
    expect(withoutPolicy.violations.every(v => !v.type.startsWith('POLICY_'))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Mixed pack (multiple rules)
// ---------------------------------------------------------------------------

describe('Policy pack: multiple rules', () => {
  it('fires DENY for SSN and WARN for NPI when both are detected', async () => {
    const content = `SSN: 123-45-6789 and NPI: 1234567893`;
    const result = await classifyDualLayer(content, { policyPack: MIXED_PACK });

    expect(result.verdict).toBe('DENY');
    expect(result.violations.some(v => v.type === 'POLICY_DENY:deny-ssn')).toBe(true);
    expect(result.violations.some(v => v.type === 'POLICY_WARN:warn-npi')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// End-to-end: policyPack passed via comply()
// ---------------------------------------------------------------------------

describe('comply(): policyPack threading end-to-end', () => {
  it('threads policyPack name through comply() and enforces DENY rule', async () => {
    // loadPolicyPack ignores the name in V1 and returns the default pack.
    // The default pack has SSN → DENY. Verify the full pipeline enforces it.
    const result = await comply({
      content: SSN_CONTENT,
      policyPack: 'default',
    });

    expect(result.verdict).toBe('DENY');
    expect(result.violations.some(v => v.type.startsWith('POLICY_DENY'))).toBe(true);
  });

  it('returns CLEAN with no policy violations when content is safe', async () => {
    const result = await comply({
      content: SAFE_CONTENT,
      policyPack: 'default',
    });

    expect(result.verdict).toBe('CLEAN');
    expect(result.violations.every(v => !v.type.startsWith('POLICY_'))).toBe(true);
  });

  it('does not add policy violations when policyPack option is omitted', async () => {
    const result = await comply({ content: SSN_CONTENT });

    // Should be VIOLATION (from regex), not DENY (from policy)
    expect(result.verdict).toBe('VIOLATION');
    expect(result.violations.every(v => !v.type.startsWith('POLICY_'))).toBe(true);
  });
});
