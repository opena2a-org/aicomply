/**
 * Policy pack loader.
 *
 * Loads YAML-based policy packs that define compliance rules
 * for different regulatory contexts (HIPAA, PCI-DSS, etc.).
 *
 * V1 has one built-in pack, 'default'. YAML loading in V2.
 */

import { types as utilTypes } from 'util';
import { showString } from '../show-string';
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
    const got = typeof name === 'string' ? showString(name, '"') : name === null ? 'null' : typeof name;
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
 * action of DENY, REDACT or WARN, and `patterns` that is an array of strings
 * with no empty slots.
 * Accepts any value, so a caller can check input it has not typed:
 * a value that is not an object, a `rules` that is not an array, or a rule
 * whose `patterns` is not an array of strings is reported, never thrown on.
 * An id that is present and not a string is reported with its type, an empty
 * id is shown as `''`, and an empty slot in a sparse `rules` array is reported
 * as a rule that is not an object;
 * a run of empty slots is one problem that names its first and last index.
 * An id or action longer than 64 characters is cut short in the message, and
 * its control characters are escaped.
 * comply() rejects fewer packs: see policyStepProblems().
 */
export function validatePolicyConfig(config: PolicyPackConfig | unknown): string[] {
  const problems = new Problems(Infinity);
  if (!isObject(config)) {
    problems.add(() => `Policy pack must be an object (got ${describe(config)})`);
    return problems.messages;
  }
  const { name, version, rules } = config as Record<string, unknown>;

  if (typeof name !== 'string' || name === '') problems.add(() => 'Policy pack name is required');
  if (typeof version !== 'string' || version === '') problems.add(() => 'Policy pack version is required');
  if (!Array.isArray(rules)) {
    problems.add(() => `Policy pack rules must be an array (got ${describe(rules)})`);
    return problems.messages;
  }
  if (rules.length === 0) problems.add(() => 'Policy pack must have at least one rule');
  addRulesProblems(rules, false, problems);
  return problems.messages;
}

/** The problems policyStepProblems() found, of which it built `messages`. */
export interface PolicyPackProblems {
  /** The messages of the first problems, as many as the limit allows. */
  messages: string[];
  /** How many problems there are, those without a message included. */
  total: number;
}

/**
 * The problems comply() rejects a policy pack for, in the words
 * validatePolicyConfig() uses: a value that is not an object, a `rules` that
 * is not an array, a rule that is not an object or whose action is not DENY,
 * REDACT or WARN, and a rule other than a REDACT rule, which the policy step
 * skips, whose id is not a non-empty string or whose `patterns` is not an
 * array of strings with no empty slots. A missing name or version and an
 * empty `rules` array, which validatePolicyConfig() reports, are not problems
 * here: the policy step reads neither the name nor the version, and an empty
 * `rules` array adds nothing. Only the first `limit` messages are built; the
 * problems after them are counted, so a pack of a million invalid rules does
 * not cost millions of strings.
 */
export function policyStepProblems(pack: unknown, limit = Infinity): PolicyPackProblems {
  const problems = new Problems(limit);
  if (!isObject(pack)) {
    problems.add(() => `Policy pack must be an object (got ${describe(pack)})`);
  } else {
    const { rules } = pack as Record<string, unknown>;
    if (Array.isArray(rules)) {
      addRulesProblems(rules, true, problems);
    } else {
      problems.add(() => `Policy pack rules must be an array (got ${describe(rules)})`);
    }
  }
  return { messages: problems.messages, total: problems.total };
}

/**
 * The problems found with a pack: the messages of the first `limit` of them,
 * and how many there are. A problem past the limit is counted and its message
 * never built.
 */
class Problems {
  readonly messages: string[] = [];
  total = 0;

  constructor(private readonly limit: number) {}

  add(message: () => string): void {
    if (this.total < this.limit) this.messages.push(message());
    this.total++;
  }
}

/**
 * Add the problems with each rule of `rules`, in index order. Every element
 * is read, as the policy step reads it, so an empty slot in a sparse array is
 * reported as a rule that is not an object. A slot is empty only when it
 * reads as `undefined` and `in` does not report it: a Proxy whose `has` trap
 * hides the elements its `get` trap supplies is checked as the step reads it,
 * and an element set to `undefined` is a problem of its own. A run of two or
 * more empty slots is one problem naming its first and last index, and its
 * end is found from the index keys the array holds, so the time and the list
 * grow with the rules the array holds and not with its length (a Proxy is
 * read slot by slot, as the policy step reads it).
 */
function addRulesProblems(rules: unknown[], redactSkipped: boolean, problems: Problems): void {
  const { length } = rules;
  let filled: FilledIndexes | undefined;
  for (let index = 0; index < length; index++) {
    const rule = rules[index];
    if (rule !== undefined || index in rules) {
      addRuleProblems(rule, index, redactSkipped, problems);
      continue;
    }
    const first = index;
    filled ??= new FilledIndexes(rules, length);
    index = filled.lastEmptyFrom(index);
    problems.add(() =>
      first === index
        ? `Rule ${first}: must be an object (got undefined)`
        : `Rules ${first} to ${index}: must be objects (got undefined)`,
    );
  }
}

/**
 * The indexes below `length` that an array reads an element at, found from
 * the index keys the array and the objects on its prototype chain hold. When
 * one of them is a Proxy, whose traps can supply an element no key shows,
 * each index is read in turn instead.
 */
class FilledIndexes {
  private readonly keys: number[] | undefined;
  private next = 0;

  constructor(
    private readonly array: unknown[],
    private readonly length: number,
  ) {
    this.keys = indexKeys(array, length);
  }

  /**
   * The last index of the run of empty slots that starts at `index`. Called
   * with increasing indexes.
   */
  lastEmptyFrom(index: number): number {
    const { array, keys, length } = this;
    if (keys === undefined) {
      while (index + 1 < length && array[index + 1] === undefined && !(index + 1 in array)) index++;
      return index;
    }
    while (this.next < keys.length && keys[this.next] <= index) this.next++;
    return (this.next < keys.length ? keys[this.next] : length) - 1;
  }
}

/**
 * The index keys below `length` of `array` and of the objects on its
 * prototype chain, in ascending order, or undefined when one of them is a
 * Proxy.
 */
function indexKeys(array: object, length: number): number[] | undefined {
  const keys: number[] = [];
  for (let object: object | null = array; object !== null; object = Object.getPrototypeOf(object)) {
    if (utilTypes.isProxy(object)) return undefined;
    for (const key of Object.getOwnPropertyNames(object)) {
      const index = Number(key);
      if (Number.isInteger(index) && index >= 0 && index < length && String(index) === key) keys.push(index);
    }
  }
  return keys.sort((a, b) => a - b);
}

/**
 * Add the problems with rule `index` of a pack. With `redactSkipped` set, only
 * the action of a REDACT rule is checked, as the policy step reads nothing
 * else of it.
 */
function addRuleProblems(rule: unknown, index: number, redactSkipped: boolean, problems: Problems): void {
  if (!isObject(rule)) {
    problems.add(() => `Rule ${index}: must be an object (got ${describe(rule)})`);
    return;
  }
  const { id, action, patterns } = rule as Record<string, unknown>;
  const label = (): string => (typeof id === 'string' && id !== '' ? showString(id) : String(index));
  const readsRule = !(redactSkipped && action === 'REDACT');
  if (readsRule && id === undefined) {
    problems.add(() => `Rule ${index}: missing id`);
  } else if (readsRule && (typeof id !== 'string' || id === '')) {
    // An id that is present is named with its type, or shown as '' when it
    // is empty, so `id: 5` is not reported as an id that was left out.
    problems.add(() => `Rule ${index}: id must be a non-empty string (got ${id === '' ? "''" : describe(id)})`);
  }
  if (action === undefined || action === '') {
    problems.add(() => `Rule ${label()}: missing action`);
  } else if (typeof action !== 'string' || !POLICY_ACTIONS.includes(action)) {
    problems.add(() => {
      const got = typeof action === 'string' ? showString(action, "'") : describe(action);
      return `Rule ${label()}: invalid action ${got}, expected one of ${POLICY_ACTIONS.join(', ')}`;
    });
  }
  if (!readsRule) return;
  if (!Array.isArray(patterns)) {
    problems.add(() => `Rule ${label()}: patterns must be an array of strings`);
    return;
  }
  const found = firstNotString(patterns);
  if (found === 'not a string') {
    problems.add(() => `Rule ${label()}: patterns must be an array of strings`);
  } else if (found !== undefined) {
    problems.add(() => `Rule ${label()}: patterns must be an array of strings (got an empty slot at index ${found})`);
  }
}

/**
 * The first element of `patterns` that is not a string: its index when it is
 * an empty slot, one that reads as `undefined` and that `in` does not report,
 * 'not a string' for any other, and undefined when every element is a string.
 * `every()`, and the policy step's `some()`, skip an empty slot, and so pass
 * over a sparse array slot by slot on every call; an empty slot is rejected
 * instead, which ends the check at the first one.
 */
function firstNotString(patterns: unknown[]): number | 'not a string' | undefined {
  for (let index = 0; index < patterns.length; index++) {
    const pattern = patterns[index];
    if (typeof pattern === 'string') continue;
    return pattern === undefined && !(index in patterns) ? index : 'not a string';
  }
  return undefined;
}

function isObject(value: unknown): value is object {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function describe(value: unknown): string {
  if (value === null) return 'null';
  return Array.isArray(value) ? 'array' : typeof value;
}
