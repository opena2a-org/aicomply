/**
 * Tests for showString(), the helper error messages use to show a string a
 * caller passed. It escapes control characters and line separators as JSON
 * does, cuts a value longer than 64 characters to its first 64 (never inside a
 * surrogate pair) followed by `...` and its length, and with a quote encloses
 * the value in it and escapes that quote and backslashes inside.
 */

import { showString } from '../show-string';

describe('showString()', () => {
  it('shows a value of up to 64 characters whole', () => {
    expect(showString('')).toBe('');
    expect(showString('i'.repeat(64))).toBe('i'.repeat(64));
  });

  it('cuts a longer value to its first 64 characters, followed by ... and its length', () => {
    expect(showString('i'.repeat(65))).toBe(`${'i'.repeat(64)}... (length 65)`);
    expect(showString('i'.repeat(5000000))).toBe(`${'i'.repeat(64)}... (length 5000000)`);
  });

  it('cuts a long value before a surrogate pair rather than inside it', () => {
    const shown = showString(`${'x'.repeat(63)}\u{1F600}tail`);

    expect(shown).toBe(`${'x'.repeat(63)}... (length 69)`);
    expect(shown).not.toMatch(/[\ud800-\udbff]/);
  });

  it('keeps a surrogate pair that ends at the 64th character', () => {
    expect(showString(`${'x'.repeat(62)}\u{1F600}tail`)).toBe(`${'x'.repeat(62)}\u{1F600}... (length 68)`);
  });

  it('escapes control characters and line separators as JSON does', () => {
    expect(showString('a\bb\tc\nd\fe\rf')).toBe('a\\bb\\tc\\nd\\fe\\rf');
    expect(showString('\u0000\u0007\u001f\u007f\u009f')).toBe('\\u0000\\u0007\\u001f\\u007f\\u009f');
    expect(showString('a b c')).toBe('a\\u2028b\\u2029c');
  });

  it('cuts a value before escaping it, and counts the length of the value as passed', () => {
    expect(showString('\n'.repeat(65))).toBe(`${'\\n'.repeat(64)}... (length 65)`);
  });

  it('leaves quotes and backslashes as they are when no quote is given', () => {
    expect(showString('a"b\'c\\d')).toBe('a"b\'c\\d');
  });

  it('encloses the value in a quote, and escapes that quote and backslashes inside', () => {
    expect(showString('a"b\'c\\d', '"')).toBe('"a\\"b\'c\\\\d"');
    expect(showString('a"b\'c\\d', "'")).toBe('\'a"b\\\'c\\\\d\'');
  });

  it('encloses the cut part of a long value in the quote, before its length', () => {
    expect(showString(`\n${'i'.repeat(99)}`, "'")).toBe(`'\\n${'i'.repeat(63)}...' (length 100)`);
  });
});
