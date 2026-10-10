/**
 * Named post-match validators referenced by the pattern pack.
 *
 * The pack (`pack/patterns.json`) holds the regexes as data. Checks that a
 * regex cannot express portably (checksums, prefix tables, and the "contains
 * a digit" test that used to be a lookahead) live here as code, and a pack
 * entry names one by its key. Every runtime implements the same names with the
 * same semantics; the conformance suite proves it case by case.
 */

/**
 * Luhn algorithm check for card numbers and NPI.
 * Returns true if the digit sequence passes the Luhn checksum.
 */
export function luhnCheck(digits: string): boolean {
  const cleaned = digits.replace(/[\s-]/g, '');
  if (!/^\d+$/.test(cleaned)) return false;

  let sum = 0;
  let alternate = false;

  for (let i = cleaned.length - 1; i >= 0; i--) {
    let n = parseInt(cleaned[i], 10);
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }

  return sum % 10 === 0;
}

/**
 * Validate SSN: not all zeros in any group, not 000/666/900-999 area.
 */
function validateSsn(match: string): boolean {
  const parts = match.split('-');
  if (parts.length !== 3) return false;

  const [area, group, serial] = parts;
  if (area === '000' || area === '666') return false;
  if (parseInt(area, 10) >= 900) return false;
  if (group === '00') return false;
  if (serial === '0000') return false;

  return true;
}

/**
 * Validate IBAN: length and basic mod-97 check (ISO 13616).
 */
function validateIban(match: string): boolean {
  const cleaned = match.replace(/\s/g, '').toUpperCase();
  if (cleaned.length < 15 || cleaned.length > 34) return false;

  // Move first 4 chars to end
  const rearranged = cleaned.slice(4) + cleaned.slice(0, 4);

  // Convert letters to numbers (A=10, B=11, ..., Z=35)
  let numericStr = '';
  for (const ch of rearranged) {
    const code = ch.charCodeAt(0);
    if (code >= 65 && code <= 90) {
      numericStr += (code - 55).toString();
    } else {
      numericStr += ch;
    }
  }

  // Mod 97 using string-based arithmetic to handle large numbers
  let remainder = 0;
  for (const digit of numericStr) {
    remainder = (remainder * 10 + parseInt(digit, 10)) % 97;
  }

  return remainder === 1;
}

/**
 * Validate PAN: 13-19 digits, must pass Luhn check and have a valid IIN prefix.
 */
function validatePan(match: string): boolean {
  const cleaned = match.replace(/[\s-]/g, '');
  if (cleaned.length < 13 || cleaned.length > 19) return false;
  if (!luhnCheck(cleaned)) return false;

  // Check known IIN prefixes
  const first = cleaned[0];
  const firstTwo = cleaned.slice(0, 2);

  // Visa: starts with 4
  if (first === '4') return true;
  // Mastercard: 51-55 or 2221-2720
  if (parseInt(firstTwo, 10) >= 51 && parseInt(firstTwo, 10) <= 55) return true;
  const firstFour = parseInt(cleaned.slice(0, 4), 10);
  if (firstFour >= 2221 && firstFour <= 2720) return true;
  // Amex: 34 or 37
  if (firstTwo === '34' || firstTwo === '37') return true;
  // Discover: 6011, 644-649, 65
  if (cleaned.startsWith('6011') || firstTwo === '65') return true;
  if (parseInt(cleaned.slice(0, 3), 10) >= 644 && parseInt(cleaned.slice(0, 3), 10) <= 649) return true;

  return false;
}

/**
 * Validate NPI: exactly 10 digits, passes Luhn with prefix 80840.
 */
function validateNpi(match: string): boolean {
  const cleaned = match.replace(/\s/g, '');
  if (!/^\d{10}$/.test(cleaned)) return false;

  // NPI Luhn uses prefix 80840 prepended to the 10-digit NPI
  return luhnCheck('80840' + cleaned);
}

/**
 * Reject a captured "value" that is really the NEXT KEY of an empty
 * assignment, e.g. `OPENAI_API_KEY=` on one line followed by
 * `ANTHROPIC_API_KEY=` on the next.
 *
 * Keyed on UPPER_SNAKE plus a single trailing `=`, which is the environment
 * variable naming convention and not a secret shape. Base64 values are
 * mixed-case, so a legitimate value ending in one padding character
 * (`Ab3dEf6hIj9kLm2nOp5qRs8=`) is untouched, and an all-caps hex secret
 * (`DEADBEEFCAFEBABE1234`, no trailing `=`) still reports.
 */
function notEmptyAssignmentTarget(value: string): boolean {
  return !/^[A-Z][A-Z0-9_]*=$/.test(value);
}

/**
 * Require at least one ASCII digit. Real MRNs are numeric or alphanumeric
 * with a numeric component, never an English word ("MRN system"). This was a
 * lookahead inside the MRN regex; as a validator it is portable to runtimes
 * whose regex engine has no lookaround, with the same matches (the capture is
 * the whole alphanumeric run the lookahead inspected).
 */
function containsDigit(value: string): boolean {
  return /[0-9]/.test(value);
}

export type Validator = (value: string) => boolean;

/** Validator names a pack entry may reference, mapped to their implementation. */
export const VALIDATORS: Readonly<Record<string, Validator>> = Object.freeze({
  ssn: validateSsn,
  pan: validatePan,
  iban: validateIban,
  npi: validateNpi,
  notEmptyAssignmentTarget,
  containsDigit,
});
