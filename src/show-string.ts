/** The most characters of a caller's string an error message shows. */
const MAX_SHOWN_LENGTH = 64;

/** Control characters, the two line separators, quotes and the backslash. */
const SPECIAL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029"'\\]/g;

const ESCAPES: Readonly<Record<string, string>> = {
  '\b': '\\b',
  '\t': '\\t',
  '\n': '\\n',
  '\f': '\\f',
  '\r': '\\r',
};

/**
 * A string a caller passed, as an error message shows it. Control characters
 * and line separators are escaped as JSON escapes them (`\n`, `\u0000`), so
 * the value cannot break the message across lines, and a value longer than 64
 * characters is cut to its first 64, followed by `...` and its length, so the
 * message does not grow with the value. With a `quote`, the value is enclosed
 * in it, and that quote and backslashes inside are escaped.
 */
export function showString(value: string, quote: '' | '"' | "'" = ''): string {
  let shown = value;
  if (value.length > MAX_SHOWN_LENGTH) {
    // Cut before a surrogate pair, not inside it.
    const last = value.charCodeAt(MAX_SHOWN_LENGTH - 1);
    shown = value.slice(0, last >= 0xd800 && last <= 0xdbff ? MAX_SHOWN_LENGTH - 1 : MAX_SHOWN_LENGTH);
  }
  const escaped = shown.replace(SPECIAL, (character) => {
    if (character === '"' || character === "'" || character === '\\') {
      return quote !== '' && (character === quote || character === '\\') ? `\\${character}` : character;
    }
    return ESCAPES[character] ?? `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`;
  });
  return shown.length < value.length
    ? `${quote}${escaped}...${quote} (length ${value.length})`
    : `${quote}${escaped}${quote}`;
}
