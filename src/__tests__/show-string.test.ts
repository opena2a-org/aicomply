/**
 * Tests for showString(), the helper error messages use to show a string a
 * caller passed. It writes control characters and line separators in JSON's
 * escape notation, cuts a value longer than 64 characters to its first 64
 * (never inside a surrogate pair) followed by `...` and its length, and with a
 * quote encloses the value in it and escapes that quote and backslashes inside.
 */

import { showString } from '../show-string';

describe('showString()', () => {
  it('shows a value of up to 64 characters whole', () => {
    expect(showString('')).toBe('');
    expect(showString('i'.repeat(64))).toBe('i'.repeat(64));
    // A lone high surrogate at the 64th character is not the start of a cut.
    expect(showString(`${'x'.repeat(63)}\ud83d`)).toBe(`${'x'.repeat(63)}\ud83d`);
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

  it("writes control characters and line separators in JSON's escape notation", () => {
    expect(showString('a\bb\tc\nd\fe\rf')).toBe('a\\bb\\tc\\nd\\fe\\rf');
    expect(showString('\u0000\u0007\u001f\u007f\u009f')).toBe('\\u0000\\u0007\\u001f\\u007f\\u009f');
    expect(showString('a\u{2028}b\u{2029}c')).toBe('a\\u2028b\\u2029c');
  });

  it('escapes U+007F to U+009F, U+2028 and U+2029, which JSON.stringify() leaves as they are', () => {
    const unescapedByJson = '\u007f\u0080\u009f\u{2028}\u{2029}';

    expect(JSON.stringify(unescapedByJson)).toBe(`"${unescapedByJson}"`);
    expect(showString(unescapedByJson)).toBe('\\u007f\\u0080\\u009f\\u2028\\u2029');
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
