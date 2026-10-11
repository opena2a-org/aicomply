/**
 * Policy pack loader.
 *
 * Loads YAML-based policy packs that define compliance rules
 * for different regulatory contexts (HIPAA, PCI-DSS, etc.).
 *
 * V1 has one built-in pack, 'default'. YAML loading in V2.
 */

import type { PolicyPack } from '../types';
import type { PolicyPackConfig } from './types';

const DEFAULT_POLICY: PolicyPack = {
  name: 'default',
  version: '1.0.0',
  rules: [
    {
      id: 'pii-ssn',
      name: 'Social Security Number',
      description: 'Detects US Social Security Numbers',
      patterns: ['SSN'],
      action: 'DENY',
      severity: 'critical',
    },
    {
      id: 'pii-pan',
      name: 'Payment Card Number',
      description: 'Detects payment card numbers (PCI-DSS)',
      patterns: ['PAN'],
      action: 'DENY',
      severity: 'critical',
    },
    {
      id: 'credential-leak',
      name: 'Credential Exposure',
      description: 'Detects exposed API keys and tokens',
      patterns: ['CREDENTIAL'],
      action: 'DENY',
      severity: 'critical',
    },
    {
      id: 'cui-marking',
      name: 'CUI Marking',
      description: 'Detects Controlled Unclassified Information markings',
      patterns: ['CUI'],
      action: 'DENY',
      severity: 'high',
    },
    {
      id: 'financial-iban',
      name: 'IBAN',
      description: 'Detects International Bank Account Numbers',
      patterns: ['IBAN'],
      action: 'DENY',
      severity: 'high',
    },
    {
      id: 'healthcare-mrn',
      name: 'Medical Record Number',
      description: 'Detects medical record numbers (HIPAA)',
      patterns: ['MRN'],
      action: 'DENY',
      severity: 'high',
    },
    {
      id: 'healthcare-npi',
      name: 'National Provider Identifier',
      description: 'Detects NPI numbers',
      patterns: ['NPI'],
      action: 'WARN',
      severity: 'medium',
    },
  ],
};

/** The built-in packs, by the name `loadPolicyPack()` takes. */
const BUILT_IN_PACKS: Readonly<Record<string, PolicyPack>> = { default: DEFAULT_POLICY };

const POLICY_ACTIONS: readonly string[] = ['DENY', 'REDACT', 'WARN'];

/** True when `name` names a built-in pack. */
export function isBuiltInPolicyPackName(name: unknown): name is string {
  return typeof name === 'string' && Object.prototype.hasOwnProperty.call(BUILT_IN_PACKS, name);
}

/** The built-in pack names, quoted, for an error message. */
export function builtInPolicyPackNames(): string {
  return Object.keys(BUILT_IN_PACKS).map((name) => `'${name}'`).join(', ');
}

/**
 * Load a built-in policy pack by name. With no name, returns the default pack.
 * Any other name throws a TypeError: a pack that was asked for and is not
 * built in is never replaced by the default one. YAML loading is planned for
 * V2.
 */
export function loadPolicyPack(name?: string): PolicyPack {
  if (name === undefined) return DEFAULT_POLICY;
  if (!isBuiltInPolicyPackName(name)) {
    const got = typeof name === 'string' ? JSON.stringify(name) : name === null ? 'null' : typeof name;
    throw new TypeError(
      `loadPolicyPack: unknown policy pack ${got}; the built-in packs are ${builtInPolicyPackNames()}`,
    );
  }
  return BUILT_IN_PACKS[name];
}

/**
 * Validate a policy pack. Returns one message per problem, and an empty array
 * for a pack whose name and version are non-empty strings and whose `rules`
 * holds at least one rule, each with an id that is a non-empty string, an
 * action of DENY, REDACT or WARN, and `patterns` that is an array of strings.
 * Accepts any value, so a caller can check input it has not typed:
 * a value that is not an object, a `rules` that is not an array, or a rule
 * whose `patterns` is not an array of strings is reported, never thrown on.
 * comply() rejects fewer packs: see policyStepProblems().
 */
export function validatePolicyConfig(config: PolicyPackConfig | unknown): string[] {
  if (!isObject(config)) {
    return [`Policy pack must be an object (got ${describe(config)})`];
  }
  const errors: string[] = [];
  const { name, version, rules } = config as Record<string, unknown>;

  if (typeof name !== 'string' || name === '') errors.push('Policy pack name is required');
  if (typeof version !== 'string' || version === '') errors.push('Policy pack version is required');
  if (!Array.isArray(rules)) {
    errors.push(`Policy pack rules must be an array (got ${describe(rules)})`);
    return errors;
  }
  if (rules.length === 0) errors.push('Policy pack must have at least one rule');

  rules.forEach((rule: unknown, index) => {
    errors.push(...ruleProblems(rule, index, false));
  });

  return errors;
}

/**
 * The problems comply() rejects a policy pack for, one message per problem in
 * the words validatePolicyConfig() uses, and an empty array when there are
 * none: a value that is not an object, a `rules` that is not an array, a rule
 * that is not an object or whose action is not DENY, REDACT or WARN, and a
 * rule other than a REDACT rule, which the policy step skips, whose id is not
 * a non-empty string or whose `patterns` is not an array of strings. A
 * missing name or version and an empty `rules` array, which
 * validatePolicyConfig() reports, are not problems here: the policy step
 * reads neither the name nor the version, and an empty `rules` array adds
 * nothing.
 */
export function policyStepProblems(pack: unknown): string[] {
  if (!isObject(pack)) {
    return [`Policy pack must be an object (got ${describe(pack)})`];
  }
  const { rules } = pack as Record<string, unknown>;
  if (!Array.isArray(rules)) {
    return [`Policy pack rules must be an array (got ${describe(rules)})`];
  }
  const errors: string[] = [];
  rules.forEach((rule: unknown, index) => {
    errors.push(...ruleProblems(rule, index, true));
  });
  return errors;
}

/**
 * The problems with rule `index` of a pack. With `redactSkipped` set, only
 * the action of a REDACT rule is checked, as the policy step reads nothing
 * else of it.
 */
function ruleProblems(rule: unknown, index: number, redactSkipped: boolean): string[] {
  if (!isObject(rule)) return [`Rule ${index}: must be an object (got ${describe(rule)})`];
  const { id, action, patterns } = rule as Record<string, unknown>;
  const label = typeof id === 'string' && id !== '' ? id : String(index);
  const readsRule = !(redactSkipped && action === 'REDACT');
  const errors: string[] = [];
  if (readsRule && (typeof id !== 'string' || id === '')) errors.push(`Rule ${index}: missing id`);
  if (action === undefined || action === '') {
    errors.push(`Rule ${label}: missing action`);
  } else if (typeof action !== 'string' || !POLICY_ACTIONS.includes(action)) {
    const got = typeof action === 'string' ? `'${action}'` : describe(action);
    errors.push(`Rule ${label}: invalid action ${got}, expected one of ${POLICY_ACTIONS.join(', ')}`);
  }
  if (readsRule && (!Array.isArray(patterns) || !patterns.every((p) => typeof p === 'string'))) {
    errors.push(`Rule ${label}: patterns must be an array of strings`);
  }
  return errors;
}

function isObject(value: unknown): value is object {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function describe(value: unknown): string {
  if (value === null) return 'null';
  return Array.isArray(value) ? 'array' : typeof value;
}
