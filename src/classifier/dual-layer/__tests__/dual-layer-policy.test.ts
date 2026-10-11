/**
 * Tests for policy pack enforcement in classifyDualLayer.
 *
 * Policy rules are applied after the regex+Guard merge and Registry L2:
 *   - DENY rule: hard-blocks (verdict → DENY), appends POLICY_DENY violation
 *   - WARN rule: appends POLICY_WARN violation, does not escalate verdict
 *   - REDACT rule: skipped silently (V1 out-of-scope)
 *   - No policy: behaviour unchanged
 *   - Empty content via comply(): the pack still sees the Registry step's violations
 *   - A pack the step cannot apply, or a first-argument name that is not a
 *     built-in pack, is rejected with a TypeError that names the parameter
 */

import { classifyDualLayer } from '..';
import { comply, loadPolicyPack, validatePolicyConfig } from '../../..';
import { policyStepProblems } from '../../../policy';
import { showString } from '../../../show-string';
import type { RegistryIntelligenceCache } from '../../../registry';
import type { ComplyOptions, PolicyPack } from '../../../types';

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
      description: 'REDACT is V1 out-of-scope - skipped silently',
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
// REDACT rule (V1 out-of-scope - skipped silently)
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

// ---------------------------------------------------------------------------
// Empty content: comply() does not classify it, but the Registry step can
// still add a violation, and the policy pack has to see that one too.
// ---------------------------------------------------------------------------

describe('comply(): policy pack on empty content', () => {
  const UNKNOWN_PACKAGE = {
    useGuard: false,
    sourcePackage: 'any-package',
    registryCache: { lookup: () => ({ status: 'miss' }) } as unknown as RegistryIntelligenceCache,
    onRegistryUnknown: 'violation',
  } as const;

  const policyOn = (action: 'DENY' | 'WARN'): PolicyPack => ({
    name: 'test-registry',
    version: '1.0.0',
    rules: [
      {
        id: 'unknown-package',
        name: 'Unknown package',
        description: 'Acts on a package the Registry has no data for',
        patterns: ['REGISTRY_UNKNOWN'],
        action,
        severity: 'high',
      },
    ],
  });

  it('applies a DENY rule to empty content, as to any other content', async () => {
    const policyPack = policyOn('DENY');
    const empty = await comply({ content: '', ...UNKNOWN_PACKAGE }, { policyPack });
    const text = await comply({ content: SAFE_CONTENT, ...UNKNOWN_PACKAGE }, { policyPack });

    expect(text.verdict).toBe('DENY');
    expect(empty.verdict).toBe('DENY');
    expect(empty.violations.map(v => v.type)).toEqual(['REGISTRY_UNKNOWN', 'POLICY_DENY:unknown-package']);
    expect(empty.violations).toEqual(text.violations);
    // Every DENY drops the content echo, a policy DENY on empty content included.
    expect(empty.originalContent).toBeUndefined();
    expect(empty.normalizedContent).toBeUndefined();
  });

  it('applies a WARN rule to empty content without raising the verdict', async () => {
    const policyPack = policyOn('WARN');
    const empty = await comply({ content: '', ...UNKNOWN_PACKAGE }, { policyPack });
    const text = await comply({ content: SAFE_CONTENT, ...UNKNOWN_PACKAGE }, { policyPack });

    expect(empty.verdict).toBe('VIOLATION');
    expect(empty.violations.map(v => v.type)).toEqual(['REGISTRY_UNKNOWN', 'POLICY_WARN:unknown-package']);
    expect(empty.violations).toEqual(text.violations);
    expect(empty.originalContent).toBe('');
  });

  it('applies the pack named on the options object in place of the one on the second argument', async () => {
    // The default pack has no rule on a Registry finding. Named on the first
    // argument it takes the place of the DENY pack on the second, so nothing
    // is added: for empty content as for any other content.
    const policyPack = policyOn('DENY');
    const empty = await comply({ content: '', ...UNKNOWN_PACKAGE, policyPack: 'default' }, { policyPack });
    const text = await comply(
      { content: SAFE_CONTENT, ...UNKNOWN_PACKAGE, policyPack: 'default' },
      { policyPack },
    );

    for (const result of [empty, text]) {
      expect(result.verdict).toBe('VIOLATION');
      expect(result.violations.map(v => v.type)).toEqual(['REGISTRY_UNKNOWN']);
    }
  });

  it('leaves empty content CLEAN when the Registry step added nothing', async () => {
    const result = await comply({ content: '' }, { policyPack: policyOn('DENY') });

    expect(result.verdict).toBe('CLEAN');
    expect(result.violations).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// A pack the policy step cannot apply is rejected up front, with the
// parameter named, for empty content as for any other content.
// ---------------------------------------------------------------------------

describe('policy pack validation', () => {
  const withRule = (rule: Record<string, unknown>): PolicyPack =>
    ({ ...DENY_PACK, rules: [{ ...DENY_PACK.rules[0], ...rule }] }) as unknown as PolicyPack;

  it.each([
    ['an empty object', {}, 'Policy pack rules must be an array (got undefined)'],
    ['null', null, 'Policy pack must be an object (got null)'],
    ['a pack name', 'default', 'Policy pack must be an object (got string)'],
    ['a lower-case action', withRule({ action: 'deny' }), "Rule 'block-ssn': invalid action 'deny'"],
    ['patterns that are not an array', withRule({ patterns: 'SSN' }), "Rule 'block-ssn': patterns must be an array of strings"],
    ['a rule with no id', withRule({ id: undefined }), 'Rule 0: missing id'],
    ['a rule with an empty id', withRule({ id: '' }), "Rule 0: id must be a non-empty string (got '')"],
  ])('rejects %s on the second argument of comply()', async (_label, policyPack, problem) => {
    const options = { policyPack } as unknown as { policyPack: PolicyPack };
    for (const content of [SAFE_CONTENT, '']) {
      const call = comply({ content, useGuard: false }, options);
      await expect(call).rejects.toThrow(TypeError);
      await expect(call).rejects.toThrow('comply: dualLayerOptions.policyPack is not a valid policy pack');
      await expect(call).rejects.toThrow(problem);
    }
  });

  it('names the option when classifyDualLayer() is given a pack it cannot apply', async () => {
    const call = classifyDualLayer(SSN_CONTENT, { policyPack: withRule({ action: 'deny' }) });
    await expect(call).rejects.toThrow(
      "classifyDualLayer: options.policyPack is not a valid policy pack: Rule 'block-ssn': invalid action 'deny'",
    );
  });

  it.each([
    ['a number', 'number', 5],
    ['zero', 'number', 0],
    ['a boolean', 'boolean', true],
    ['null', 'null', null],
    ['an empty string', "''", ''],
  ])('reports an id that is %s as (got %s), instead of calling the id missing', async (_label, got, id) => {
    const policyPack = withRule({ id });
    const problem = `Rule 0: id must be a non-empty string (got ${got})`;

    expect(validatePolicyConfig(policyPack)).toEqual([problem]);
    const call = comply({ content: SSN_CONTENT, useGuard: false }, { policyPack });
    await expect(call).rejects.toThrow(TypeError);
    await expect(call).rejects.toThrow(
      new TypeError(`comply: dualLayerOptions.policyPack is not a valid policy pack: ${problem}`),
    );
  });

  it('rejects an empty slot in a sparse rules array, which the policy step would read as undefined', async () => {
    // Slots 0 and 2 are holes: forEach() skips them, an index loop does not.
    const rules: unknown[] = [];
    rules[1] = DENY_PACK.rules[0];
    rules.length = 3;
    const policyPack = { ...DENY_PACK, rules } as unknown as PolicyPack;
    const problems = ['Rule 0: must be an object (got undefined)', 'Rule 2: must be an object (got undefined)'];

    expect(validatePolicyConfig(policyPack)).toEqual(problems);
    for (const content of [SSN_CONTENT, '']) {
      const call = comply({ content, useGuard: false }, { policyPack });
      await expect(call).rejects.toThrow(TypeError);
      await expect(call).rejects.toThrow(
        new TypeError(`comply: dualLayerOptions.policyPack is not a valid policy pack: ${problems.join('; ')}`),
      );
    }
    await expect(classifyDualLayer(SSN_CONTENT, { useGuard: false, policyPack })).rejects.toThrow(
      new TypeError(`classifyDualLayer: options.policyPack is not a valid policy pack: ${problems.join('; ')}`),
    );
  });

  it('reports a run of empty slots as one problem, so a long sparse rules array gives a short list', async () => {
    // Five million slots hold three rules. One message a slot made a list of
    // millions and a rejection message hundreds of megabytes long.
    const rules: unknown[] = [];
    rules.length = 5000000;
    rules[2] = DENY_PACK.rules[0];
    rules[3] = DENY_PACK.rules[0];
    rules[5] = DENY_PACK.rules[0];
    const policyPack = { ...DENY_PACK, rules } as unknown as PolicyPack;
    const problems = [
      'Rules 0 to 1: must be objects (got undefined)',
      'Rule 4: must be an object (got undefined)',
      'Rules 6 to 4999999: must be objects (got undefined)',
    ];

    // The length first, so a list of millions fails here and is not printed.
    const found = validatePolicyConfig(policyPack);
    expect(found).toHaveLength(3);
    expect(found).toEqual(problems);
    const call = comply({ content: SSN_CONTENT, useGuard: false }, { policyPack });
    await expect(call).rejects.toThrow(
      new TypeError(`comply: dualLayerOptions.policyPack is not a valid policy pack: ${problems.join('; ')}`),
    );

    const holes: unknown[] = [];
    holes.length = 5000000;
    const holesFound = validatePolicyConfig({ name: 'p', version: '1', rules: holes });
    expect(holesFound).toHaveLength(1);
    expect(holesFound).toEqual(['Rules 0 to 4999999: must be objects (got undefined)']);
  });

  it('finds the end of a run of empty slots without testing each slot, so the time does not grow with the length', async () => {
    // Testing each of 500 million empty slots took seconds; the longest
    // array, 2 ** 32 - 1 slots, took close to a minute.
    for (const length of [500000000, 2 ** 32 - 1]) {
      const rules: unknown[] = [];
      rules.length = length;
      rules[1] = DENY_PACK.rules[0];
      const policyPack = { ...DENY_PACK, rules } as unknown as PolicyPack;
      const problems = ['Rule 0: must be an object (got undefined)', `Rules 2 to ${length - 1}: must be objects (got undefined)`];

      const start = performance.now();
      expect(validatePolicyConfig(policyPack)).toEqual(problems);
      await expect(comply({ content: SSN_CONTENT, useGuard: false }, { policyPack })).rejects.toThrow(
        new TypeError(`comply: dualLayerOptions.policyPack is not a valid policy pack: ${problems.join('; ')}`),
      );
      expect(performance.now() - start).toBeLessThan(1000);
    }
  });

  it('reads a slot the prototype chain fills as the policy step reads it, and a run of empty slots ends there', () => {
    const rules: unknown[] = [];
    rules.length = 6;
    rules[0] = DENY_PACK.rules[0];
    Object.setPrototypeOf(rules, Object.assign(Object.create(Array.prototype), { 3: 'block-ssn' }));
    const policyPack = { ...DENY_PACK, rules } as unknown as PolicyPack;

    expect(validatePolicyConfig(policyPack)).toEqual([
      'Rules 1 to 2: must be objects (got undefined)',
      'Rule 3: must be an object (got string)',
      'Rules 4 to 5: must be objects (got undefined)',
    ]);
  });

  it('reports each element set to undefined on its own, and only empty slots as a run', async () => {
    const rule = DENY_PACK.rules[0];
    const rules: unknown[] = [undefined, undefined, rule, undefined];
    rules.length = 7;
    rules[5] = undefined;
    const policyPack = { ...DENY_PACK, rules } as unknown as PolicyPack;
    const problems = [
      'Rule 0: must be an object (got undefined)',
      'Rule 1: must be an object (got undefined)',
      'Rule 3: must be an object (got undefined)',
      'Rule 4: must be an object (got undefined)',
      'Rule 5: must be an object (got undefined)',
      'Rule 6: must be an object (got undefined)',
    ];

    expect(validatePolicyConfig({ name: 'p', version: '1', rules: [undefined, undefined, rule, undefined] })).toEqual(
      problems.slice(0, 3),
    );
    expect(validatePolicyConfig(policyPack)).toEqual(problems);
    await expect(comply({ content: SSN_CONTENT, useGuard: false }, { policyPack })).rejects.toThrow(
      new TypeError(`comply: dualLayerOptions.policyPack is not a valid policy pack: ${problems.join('; ')}`),
    );
  });

  it('applies a rules array behind a Proxy whose elements `in` does not report, as the policy step reads each one', async () => {
    const rule = { id: 'r', name: 'R', action: 'DENY', patterns: ['SSN'] };
    // `in` reports no element; `get` supplies the length and the elements.
    const hidden = new Proxy([rule], { has: () => false });
    const supplied = new Proxy([], {
      get: (target, key) => (key === 'length' ? 2 : key === '0' || key === '1' ? rule : Reflect.get(target, key)),
    });

    for (const rules of [hidden, supplied]) {
      const policyPack = { name: 'p', version: '1', rules } as unknown as PolicyPack;
      expect(validatePolicyConfig(policyPack)).toEqual([]);
      const result = await comply({ content: 'My SSN is 123-45-6789.', useGuard: false }, { policyPack });
      expect(result.verdict).toBe('DENY');
      expect(result.violations.map(v => v.type)).toContain('POLICY_DENY:r');
    }
  });

  it('reads a rules array behind a Proxy slot by slot, so a run of empty slots ends at an element only `get` supplies', () => {
    const rule = { id: 'r', action: 'DENY', patterns: ['SSN'] };
    // The Proxy holds no index key; `get` supplies the length and element 1.
    const rules = new Proxy([], {
      get: (target, key) => (key === 'length' ? 4 : key === '1' ? rule : Reflect.get(target, key)),
    });

    expect(validatePolicyConfig({ name: 'p', version: '1', rules })).toEqual([
      'Rule 0: must be an object (got undefined)',
      'Rules 2 to 3: must be objects (got undefined)',
    ]);
  });

  it('ends a run of empty slots only at an index key, not at a prototype key that reads as a number', () => {
    const rules: unknown[] = [];
    rules.length = 4;
    rules[0] = DENY_PACK.rules[0];
    // Element 2 is read at the key '2', never at '02', '2e0' or '-0'.
    Object.setPrototypeOf(rules, Object.assign(Object.create(Array.prototype), { '02': 'x', '2e0': 'x', '-0': 'x' }));

    expect(validatePolicyConfig({ name: 'p', version: '1', rules })).toEqual([
      'Rules 1 to 3: must be objects (got undefined)',
    ]);
  });

  it('rejects an empty slot in patterns at once, which every() and the policy step pass over one by one', async () => {
    // A rule whose patterns is [] with a length of 50 million passed in about
    // half a second and made each comply() call take more than a second.
    const patterns: string[] = [];
    patterns.length = 2 ** 32 - 1;
    const sparse: string[] = ['SSN'];
    sparse[2] = 'PAN';
    const problem = (index: number): string =>
      `Rule 'block-ssn': patterns must be an array of strings (got an empty slot at index ${index})`;

    for (const [rulePatterns, index] of [[sparse, 1], [patterns, 0]] as const) {
      const policyPack = withRule({ patterns: rulePatterns });
      const start = performance.now();
      expect(validatePolicyConfig(policyPack)).toEqual([problem(index)]);
      await expect(comply({ content: SSN_CONTENT, useGuard: false }, { policyPack })).rejects.toThrow(
        new TypeError(`comply: dualLayerOptions.policyPack is not a valid policy pack: ${problem(index)}`),
      );
      expect(performance.now() - start).toBeLessThan(1000);
    }
    // An element set to undefined is not a string either.
    expect(validatePolicyConfig(withRule({ patterns: ['SSN', undefined] }))).toEqual([
      "Rule 'block-ssn': patterns must be an array of strings",
    ]);
  });

  it('rejects a name on the first argument that is not a built-in pack, a pack object there included', async () => {
    const cases: Array<[unknown, string]> = [
      ['hipaa', '"hipaa"'],
      [DENY_PACK, 'object'],
      [null, 'null'],
    ];
    for (const [policyPack, got] of cases) {
      for (const content of [SSN_CONTENT, '']) {
        const call = comply({ content, useGuard: false, policyPack } as unknown as ComplyOptions);
        await expect(call).rejects.toThrow(TypeError);
        await expect(call).rejects.toThrow(
          `comply: options.policyPack must name a built-in pack ('default'), got ${got}. ` +
            'Pass a pack object on the second argument: comply({ content }, { policyPack })',
        );
      }
    }
  });

  it('applies the default pack named on the first argument and a pack object on the second', async () => {
    const named = await comply({ content: SSN_CONTENT, useGuard: false, policyPack: 'default' });
    const passed = await comply({ content: SSN_CONTENT, useGuard: false }, { policyPack: DENY_PACK });

    expect(named.violations.map(v => v.type)).toEqual(['SSN', 'POLICY_DENY:pii-ssn']);
    expect(passed.violations.map(v => v.type)).toEqual(['SSN', 'POLICY_DENY:block-ssn']);
  });

  it('applies a pack with no name or version, or with no rules, which the policy step does not need', async () => {
    const noRules: PolicyPack = { name: 'p', version: '1', rules: [] };
    const unnamed = { rules: DENY_PACK.rules } as unknown as PolicyPack;

    const none = await comply({ content: SSN_CONTENT, useGuard: false }, { policyPack: noRules });
    const denied = await comply({ content: SSN_CONTENT, useGuard: false }, { policyPack: unnamed });
    const direct = await classifyDualLayer(SSN_CONTENT, { useGuard: false, policyPack: noRules });
    // The name on the first argument takes the place of the pack on the second.
    const named = await comply(
      { content: SSN_CONTENT, useGuard: false, policyPack: 'default' },
      { policyPack: noRules },
    );
    const empty = await comply({ content: '', useGuard: false }, { policyPack: noRules });

    expect(none.verdict).toBe('VIOLATION');
    expect(none.violations.map(v => v.type)).toEqual(['SSN']);
    expect(denied.verdict).toBe('DENY');
    expect(denied.violations.map(v => v.type)).toEqual(['SSN', 'POLICY_DENY:block-ssn']);
    expect(direct.verdict).toBe('VIOLATION');
    expect(direct.violations.map(v => v.type)).toEqual(['SSN']);
    expect(named.verdict).toBe('DENY');
    expect(named.violations.map(v => v.type)).toEqual(['SSN', 'POLICY_DENY:pii-ssn']);
    expect(empty.verdict).toBe('CLEAN');
    expect(empty.violations).toEqual([]);
  });

  it('applies a pack whose REDACT rule has no id or patterns, as the policy step skips REDACT rules', async () => {
    const redact = (rule: Record<string, unknown>): PolicyPack =>
      ({ ...REDACT_PACK, rules: [{ ...REDACT_PACK.rules[0], ...rule }] }) as unknown as PolicyPack;

    for (const policyPack of [redact({ patterns: 'SSN' }), redact({ id: undefined, patterns: undefined })]) {
      const result = await comply({ content: SSN_CONTENT, useGuard: false }, { policyPack });

      expect(result.verdict).toBe('VIOLATION');
      expect(result.violations.map(v => v.type)).toEqual(['SSN']);
    }
  });

  it('names each problem the policy step has with a pack, and none with its name, version or rule count', async () => {
    const policyPack = {
      rules: [
        'block-ssn',
        { action: 'WARN', patterns: 'NPI' },
        { id: 'r', action: 'deny', patterns: ['SSN'] },
        { action: 'REDACT' },
      ],
    } as unknown as PolicyPack;

    const call = comply({ content: SSN_CONTENT, useGuard: false }, { policyPack });
    await expect(call).rejects.toThrow(TypeError);
    await expect(call).rejects.toThrow(
      new TypeError(
        'comply: dualLayerOptions.policyPack is not a valid policy pack: ' +
          'Rule 0: must be an object (got string); Rule 1: missing id; ' +
          'Rule 1: patterns must be an array of strings; ' +
          "Rule 'r': invalid action 'deny', expected one of DENY, REDACT, WARN",
      ),
    );
  });

  it('lists the first ten problems and counts the rest, so the message does not grow with the pack', async () => {
    // Each rule is missing its id and action and has no patterns: three
    // problems per rule.
    const packOf = (count: number): PolicyPack =>
      ({ name: 'p', version: '1', rules: new Array(count).fill({}) }) as unknown as PolicyPack;
    const prefix = 'comply: dualLayerOptions.policyPack is not a valid policy pack: ';
    const firstTen =
      'Rule 0: missing id; Rule 0: missing action; Rule 0: patterns must be an array of strings; ' +
      'Rule 1: missing id; Rule 1: missing action; Rule 1: patterns must be an array of strings; ' +
      'Rule 2: missing id; Rule 2: missing action; Rule 2: patterns must be an array of strings; ' +
      'Rule 3: missing id';

    const withLastRule = (rule: Record<string, unknown>): PolicyPack =>
      ({ name: 'p', version: '1', rules: [{}, {}, {}, rule] }) as unknown as PolicyPack;
    const cases: Array<[PolicyPack, string]> = [
      // Ten problems are listed in full, with no count after them.
      [withLastRule({ action: 'DENY', patterns: [] }), firstTen],
      [withLastRule({ patterns: [] }), `${firstTen}; and 1 more problem, which validatePolicyConfig() lists`],
      [packOf(4), `${firstTen}; and 2 more problems, which validatePolicyConfig() lists`],
    ];
    for (const [policyPack, problems] of cases) {
      await expect(comply({ content: SSN_CONTENT, useGuard: false }, { policyPack })).rejects.toThrow(
        new TypeError(prefix + problems),
      );
    }

    const large = packOf(45000);
    const rest = '; and 134990 more problems, which validatePolicyConfig() lists';
    expect(validatePolicyConfig(large)).toHaveLength(135000);
    for (const content of [SSN_CONTENT, '']) {
      const call = comply({ content, useGuard: false }, { policyPack: large });
      await expect(call).rejects.toThrow(new TypeError(`${prefix}${firstTen}${rest}`));
    }
    await expect(classifyDualLayer(SSN_CONTENT, { useGuard: false, policyPack: large })).rejects.toThrow(
      new TypeError(`classifyDualLayer: options.policyPack is not a valid policy pack: ${firstTen}${rest}`),
    );
  });

  it('builds the messages of the first ten problems only, and counts the rest', () => {
    // A million rules that are each {} have three million problems. Building
    // a message for each held hundreds of megabytes to show ten of them.
    const rules = new Array(1000000).fill({});
    const found = policyStepProblems({ name: 'p', version: '1', rules }, 10);

    expect(found.total).toBe(3000000);
    expect(found.messages).toHaveLength(10);
    expect(found.messages[9]).toBe('Rule 3: missing id');
    expect(policyStepProblems({ rules: [{}] })).toEqual({
      messages: ['Rule 0: missing id', 'Rule 0: missing action', 'Rule 0: patterns must be an array of strings'],
      total: 3,
    });
  });

  it('cuts a long id, action or pack name short and escapes its control characters, so the message stays short', async () => {
    const long = 'i'.repeat(5000000);
    const shown = `'${'i'.repeat(64)}...' (length 5000000)`;
    const invalid = (rules: unknown[]): Promise<unknown> =>
      comply({ content: 'x', useGuard: false }, { policyPack: { rules } as unknown as PolicyPack });
    const prefix = 'comply: dualLayerOptions.policyPack is not a valid policy pack: ';

    await expect(invalid([{ id: long, action: 'nope', patterns: [] }])).rejects.toThrow(
      new TypeError(`${prefix}Rule ${shown}: invalid action 'nope', expected one of DENY, REDACT, WARN`),
    );
    await expect(invalid([{ id: 'a\nb', action: `no '${long}`, patterns: [] }])).rejects.toThrow(
      new TypeError(
        `${prefix}Rule 'a\\nb': invalid action 'no\\u2028\\'${'i'.repeat(60)}...' (length 5000004), ` +
          'expected one of DENY, REDACT, WARN',
      ),
    );
    // Ten problems with a long id each, and five thousand more, make a
    // message of about a thousand characters, not of tens of megabytes.
    const many = invalid([{ id: long, action: 'nope', patterns: 'SSN' }, ...new Array(5000).fill({})]);
    await expect(many).rejects.toThrow(TypeError);
    const message = await many.then(() => '', (error: Error) => error.message);
    expect(message.length).toBeLessThan(2000);
    expect(validatePolicyConfig({ name: 'p', version: '1', rules: [{ id: long, patterns: [] }] })).toEqual([
      `Rule ${shown}: missing action`,
    ]);

    const name = `\u0007${long}`;
    await expect(comply({ content: 'x', useGuard: false, policyPack: name } as unknown as ComplyOptions)).rejects.toThrow(
      new TypeError(
        `comply: options.policyPack must name a built-in pack ('default'), got "\\u0007${'i'.repeat(63)}..." ` +
          '(length 5000001). Pass a pack object on the second argument: comply({ content }, { policyPack })',
      ),
    );
    expect(() => loadPolicyPack('a"b\\c\n')).toThrow(
      new TypeError('loadPolicyPack: unknown policy pack "a\\"b\\\\c\\n"; the built-in packs are \'default\''),
    );
  });

  it('cuts a long value before a surrogate pair rather than inside it', () => {
    const shown = showString(`${'x'.repeat(63)}\u{1F600}tail`);

    expect(shown).toBe(`${'x'.repeat(63)}... (length 69)`);
    expect(shown).not.toMatch(/[\ud800-\udbff]/);
  });

  it('quotes a rule id, so an id cannot read as the end of one problem and the start of another', async () => {
    const rules = [{ id: "x; Rule 9: it's", action: 'nope', patterns: [] }];
    const policyPack = { name: 'p', version: '1', rules } as unknown as PolicyPack;
    const problem = "Rule 'x; Rule 9: it\\'s': invalid action 'nope', expected one of DENY, REDACT, WARN";

    expect(validatePolicyConfig(policyPack)).toEqual([problem]);
    await expect(comply({ content: 'x', useGuard: false }, { policyPack })).rejects.toThrow(
      new TypeError(`comply: dualLayerOptions.policyPack is not a valid policy pack: ${problem}`),
    );
  });

  it('names validatePolicyConfig() after the count of the problems it leaves out', async () => {
    const policyPack = { rules: new Array(5).fill({}) } as unknown as PolicyPack;
    const message = await comply({ content: 'x', useGuard: false }, { policyPack }).catch((error: Error) => error.message);

    expect(message).toMatch(/; and 5 more problems, which validatePolicyConfig\(\) lists$/);
  });
});

describe('loadPolicyPack() and validatePolicyConfig()', () => {
  it('loads the default pack with no name or its own name, and throws on any other name', () => {
    expect(loadPolicyPack().name).toBe('default');
    expect(loadPolicyPack('default')).toBe(loadPolicyPack());
    expect(() => loadPolicyPack('hipaa')).toThrow(
      "loadPolicyPack: unknown policy pack \"hipaa\"; the built-in packs are 'default'",
    );
    // A name inherited from Object.prototype is not a pack.
    expect(() => loadPolicyPack('toString')).toThrow(TypeError);
  });

  it('reports every problem in a pack without throwing on one that is not an object', () => {
    expect(validatePolicyConfig(DENY_PACK)).toEqual([]);
    expect(validatePolicyConfig(loadPolicyPack())).toEqual([]);
    expect(validatePolicyConfig(undefined)).toEqual(['Policy pack must be an object (got undefined)']);
    expect(validatePolicyConfig({ rules: 3 })).toEqual([
      'Policy pack name is required',
      'Policy pack version is required',
      'Policy pack rules must be an array (got number)',
    ]);
    expect(validatePolicyConfig({ name: 'p', version: '1', rules: [] })).toEqual([
      'Policy pack must have at least one rule',
    ]);
    expect(validatePolicyConfig({ name: 'p', version: '1', rules: ['r', { id: 'x', patterns: [1] }] })).toEqual([
      'Rule 0: must be an object (got string)',
      "Rule 'x': missing action",
      "Rule 'x': patterns must be an array of strings",
    ]);
  });

  it('reports the problems of 50,000 rules that are each {} without throwing', () => {
    // Three problems a rule make 150,000, more than fit in the arguments of
    // one call on Node's default stack, so the list is not spread into push().
    const problems = validatePolicyConfig({ rules: new Array(50000).fill({}) });

    // The pack's own two problems come first, then those of the rules.
    expect(problems.length).toBe(150002);
    expect(problems.slice(0, 3)).toEqual([
      'Policy pack name is required',
      'Policy pack version is required',
      'Rule 0: missing id',
    ]);
    expect(problems[150001]).toBe('Rule 49999: patterns must be an array of strings');
  });

  it('reports the missing id and patterns of a REDACT rule, which comply() does not read', async () => {
    const policyPack = { name: 'p', version: '1', rules: [{ action: 'REDACT' }] };

    expect(validatePolicyConfig(policyPack)).toEqual([
      'Rule 0: missing id',
      'Rule 0: patterns must be an array of strings',
    ]);
    // The same pack is applied by comply(), where the REDACT rule is skipped.
    const result = await comply(
      { content: SSN_CONTENT, useGuard: false },
      { policyPack: policyPack as unknown as PolicyPack },
    );
    expect(result.violations.map(v => v.type)).toEqual(['SSN']);
  });
});
