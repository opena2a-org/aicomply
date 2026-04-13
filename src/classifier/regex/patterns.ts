/**
 * Deterministic regex patterns for sensitive data classification.
 *
 * Each pattern includes a detection regex and an optional validator
 * for post-match verification (e.g., Luhn check for PANs).
 */

export interface PatternMatch {
  type: PatternType;
  value: string;
  start: number;
  end: number;
  confidence: number;
}

export type PatternType =
  | 'SSN'
  | 'PAN'
  | 'CUI'
  | 'CREDENTIAL'
  | 'IBAN'
  | 'PASSPORT'
  | 'MRN'
  | 'NPI';

export interface PatternDefinition {
  type: PatternType;
  regex: RegExp;
  confidence: number;
  validate?: (match: string) => boolean;
}

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
 * Validate PAN: must pass Luhn check and have valid IIN prefix.
 */
function validatePan(match: string): boolean {
  const cleaned = match.replace(/[\s-]/g, '');
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

export const PATTERNS: PatternDefinition[] = [
  {
    type: 'SSN',
    regex: /\b(\d{3}-\d{2}-\d{4})\b/g,
    confidence: 0.95,
    validate: validateSsn,
  },
  {
    type: 'PAN',
    // 13-19 digit sequences, optionally separated by spaces or dashes
    regex: /\b(\d[\d -]{11,22}\d)\b/g,
    confidence: 0.9,
    validate: (match: string) => {
      const cleaned = match.replace(/[\s-]/g, '');
      if (cleaned.length < 13 || cleaned.length > 19) return false;
      return validatePan(match);
    },
  },
  {
    type: 'CUI',
    regex: /\b(CUI\/\/SP-[A-Z-]+|CONTROLLED\s+UNCLASSIFIED\s+INFORMATION|FOR\s+OFFICIAL\s+USE\s+ONLY|CUI\/\/[A-Z-]+)\b/gi,
    confidence: 0.99,
  },
  {
    type: 'CREDENTIAL',
    // AWS Access Key ID
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    confidence: 0.98,
  },
  {
    type: 'CREDENTIAL',
    // GitHub personal access token (classic)
    regex: /\b(ghp_[A-Za-z0-9]{36})\b/g,
    confidence: 0.98,
  },
  {
    type: 'CREDENTIAL',
    // GitHub fine-grained token
    regex: /\b(github_pat_[A-Za-z0-9_]{82})\b/g,
    confidence: 0.98,
  },
  {
    type: 'CREDENTIAL',
    // Bearer token in header-like context
    regex: /Bearer\s+([A-Za-z0-9._~+/=-]{20,})/g,
    confidence: 0.85,
  },
  {
    type: 'CREDENTIAL',
    // Generic API key patterns (key=..., api_key=..., apikey=...)
    regex: /(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['"]?([A-Za-z0-9._~+/=-]{16,})['"]?/gi,
    confidence: 0.8,
  },
  {
    type: 'IBAN',
    // Two letter country code + two check digits + up to 30 alphanumeric
    regex: /\b([A-Z]{2}\d{2}[\s]?[\dA-Z]{4}[\s]?(?:[\dA-Z]{4}[\s]?){1,7}[\dA-Z]{1,4})\b/g,
    confidence: 0.85,
    validate: validateIban,
  },
  {
    type: 'PASSPORT',
    // Common passport formats: 1-2 letters followed by 6-9 digits, requires context keyword
    regex: /(?:passport|travel\s+document)[:\s#-]*\b([A-Z]{1,2}\d{6,9})\b/gi,
    confidence: 0.75,
  },
  {
    type: 'MRN',
    // Medical Record Number: MRN prefix followed by digits/alphanumeric
    regex: /\bMRN[:\s#-]*([A-Z0-9]{6,12})\b/gi,
    confidence: 0.9,
  },
  {
    type: 'NPI',
    // 10-digit National Provider Identifier
    regex: /\bNPI[:\s#-]*(\d{10})\b/gi,
    confidence: 0.85,
    validate: validateNpi,
  },
];

/**
 * Scan content against all patterns and return validated matches.
 */
export function scanPatterns(content: string): PatternMatch[] {
  const matches: PatternMatch[] = [];

  for (const pattern of PATTERNS) {
    // Reset regex state for global patterns
    pattern.regex.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = pattern.regex.exec(content)) !== null) {
      const fullMatch = match[0];
      const capturedValue = match[1] || fullMatch;

      // Run validator if present
      if (pattern.validate && !pattern.validate(capturedValue)) {
        continue;
      }

      matches.push({
        type: pattern.type,
        value: capturedValue,
        start: match.index,
        end: match.index + fullMatch.length,
        confidence: pattern.confidence,
      });
    }
  }

  // Deduplicate overlapping matches: higher confidence wins
  matches.sort((a, b) => b.confidence - a.confidence);
  const deduped: PatternMatch[] = [];
  for (const m of matches) {
    const overlaps = deduped.some(
      (d) => m.start < d.end && m.end > d.start && m.value === d.value
    );
    if (!overlaps) {
      deduped.push(m);
    }
  }

  return deduped;
}
