/**
 * Tests for a pattern the regex engine cannot run on the content, through
 * comply() and classifyDualLayer().
 *
 * The regex layer contains such an error per pattern:
 *   - the pattern is listed in `unevaluatedPatterns`, in pack order, once
 *     however many content views it could not run on
 *   - the other patterns run, and their matches stand
 *   - a PATTERN_NOT_EVALUATED:<id> finding is added, so the verdict is never
 *     CLEAN; a DENY stays DENY
 */

import { classifyDualLayer } from '..';
import { comply } from '../../..';
import { PATTERNS, type PatternDefinition } from '../../regex/patterns';

afterEach(() => jest.restoreAllMocks());

/** Make pack pattern `id` throw from its regex, as the engine does when it cannot run it. */
function failPattern(id: string): jest.SpyInstance {
  const pattern = PATTERNS.find((p) => p.id === id) as PatternDefinition;
  return jest.spyOn(pattern.regex, 'exec').mockImplementation(() => {
    throw new RangeError('Maximum call stack size exceeded');
  });
}

const FLAGGED = 'Customer SSN 078-05-1120 on file\nMRN: A1234567\n';

describe('comply() with a pattern the regex engine cannot run on the content', () => {
  it('lists the pattern and keeps the findings of the other patterns', async () => {
    failPattern('bearer-token');
    const result = await comply({ content: FLAGGED, useGuard: false });
    expect(result).toMatchObject({ verdict: 'VIOLATION', unevaluatedPatterns: ['bearer-token'] });
    expect(result.violations.map((v) => v.type).sort()).toEqual([
      'MRN',
      'PATTERN_NOT_EVALUATED:bearer-token',
      'SSN',
    ]);
    expect(result.classifierResults.regex).toMatchObject({
      verdict: 'VIOLATION',
      unevaluatedPatterns: ['bearer-token'],
    });
  });

  it('gives VIOLATION, not CLEAN, for content no other pattern flags', async () => {
    failPattern('bearer-token');
    const result = await comply({ content: 'nothing sensitive in this line', useGuard: false });
    expect(result.verdict).toBe('VIOLATION');
    expect(result).toMatchObject({ unevaluatedPatterns: ['bearer-token'] });
    expect(result.violations).toEqual([
      {
        type: 'PATTERN_NOT_EVALUATED:bearer-token',
        value: 'bearer-token',
        start: 0,
        end: 0,
        confidence: 1,
        classifier: 'regex',
      },
    ]);
  });

  it('lists a pattern once when it could not run on two content views', async () => {
    const exec = failPattern('bearer-token');
    // The spaced SSN is found in the compact view, scanned after the normalized one.
    const result = await comply({ content: 'SSN 1 2 3 - 4 5 - 6 7 8 9', useGuard: false });
    expect(exec).toHaveBeenCalledTimes(2);
    expect(result.violations.some((v) => v.type === 'SSN' && v.view === 'compact')).toBe(true);
    expect(result).toMatchObject({ verdict: 'VIOLATION', unevaluatedPatterns: ['bearer-token'] });
    expect(result.violations.filter((v) => v.type === 'PATTERN_NOT_EVALUATED:bearer-token')).toHaveLength(1);
  });

  it('lists the patterns in pack order', async () => {
    failPattern('npi');
    failPattern('ssn');
    const result = await comply({ content: 'nothing sensitive in this line', useGuard: false });
    expect(result).toMatchObject({ unevaluatedPatterns: ['ssn', 'npi'] });
    expect(result.violations.map((v) => v.type)).toEqual([
      'PATTERN_NOT_EVALUATED:ssn',
      'PATTERN_NOT_EVALUATED:npi',
    ]);
  });

  it('keeps a DENY and still lists the pattern', async () => {
    failPattern('bearer-token');
    const result = await comply({
      content: 'nothing sensitive in this line',
      useGuard: false,
      sourcePackage: 'express',
      onRegistryUnknown: 'deny',
    });
    expect(result).toMatchObject({ verdict: 'DENY', unevaluatedPatterns: ['bearer-token'] });
    expect(result.violations.map((v) => v.type)).toEqual([
      'PATTERN_NOT_EVALUATED:bearer-token',
      'REGISTRY_UNKNOWN',
    ]);
  });

  it('carries no unevaluatedPatterns when every pattern ran', async () => {
    const result = await comply({ content: FLAGGED, useGuard: false });
    expect(result.verdict).toBe('VIOLATION');
    expect(result).not.toHaveProperty('unevaluatedPatterns');
    expect(result.classifierResults.regex).not.toHaveProperty('unevaluatedPatterns');
  });
});

describe('classifyDualLayer() with a pattern the regex engine cannot run on the content', () => {
  it('lists the pattern and gives VIOLATION', async () => {
    failPattern('generic-key-assignment');
    const result = await classifyDualLayer('nothing sensitive in this line', { useGuard: false });
    expect(result).toMatchObject({
      verdict: 'VIOLATION',
      unevaluatedPatterns: ['generic-key-assignment'],
      layers: ['normalize', 'regex'],
    });
  });
});
