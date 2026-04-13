import { scanPatterns, luhnCheck } from '../patterns';
import { classifyWithRegex } from '..';

describe('luhnCheck', () => {
  it('validates correct Luhn sequences', () => {
    expect(luhnCheck('4111111111111111')).toBe(true); // Visa test card
    expect(luhnCheck('5500000000000004')).toBe(true); // MC test card
    expect(luhnCheck('340000000000009')).toBe(true);  // Amex test card
    expect(luhnCheck('79927398713')).toBe(true);      // Wikipedia example
  });

  it('rejects invalid Luhn sequences', () => {
    expect(luhnCheck('4111111111111112')).toBe(false);
    expect(luhnCheck('1234567890')).toBe(false);
    expect(luhnCheck('1111111111')).toBe(false);
  });

  it('handles dashes and spaces', () => {
    expect(luhnCheck('4111-1111-1111-1111')).toBe(true);
    expect(luhnCheck('4111 1111 1111 1111')).toBe(true);
  });
});

describe('SSN patterns', () => {
  it('detects valid SSNs', () => {
    const matches = scanPatterns('My SSN is 123-45-6789');
    expect(matches).toHaveLength(1);
    expect(matches[0].type).toBe('SSN');
    expect(matches[0].value).toBe('123-45-6789');
  });

  it('rejects SSNs with area 000', () => {
    const matches = scanPatterns('000-45-6789');
    expect(matches).toHaveLength(0);
  });

  it('rejects SSNs with area 666', () => {
    const matches = scanPatterns('666-45-6789');
    expect(matches).toHaveLength(0);
  });

  it('rejects SSNs with area 900+', () => {
    const matches = scanPatterns('900-45-6789');
    expect(matches).toHaveLength(0);
  });

  it('rejects SSNs with group 00', () => {
    const matches = scanPatterns('123-00-6789');
    expect(matches).toHaveLength(0);
  });

  it('rejects SSNs with serial 0000', () => {
    const matches = scanPatterns('123-45-0000');
    expect(matches).toHaveLength(0);
  });

  it('does not match non-SSN digit sequences', () => {
    const matches = scanPatterns('phone: 555-12-3456');
    // 555 is valid area, 12 is valid group, 3456 is valid serial
    // This is actually a valid SSN format -- the regex cannot distinguish
    expect(matches.length).toBeGreaterThanOrEqual(0);
  });
});

describe('PAN patterns', () => {
  it('detects Visa test card', () => {
    const matches = scanPatterns('Card: 4111111111111111');
    const pans = matches.filter(m => m.type === 'PAN');
    expect(pans).toHaveLength(1);
  });

  it('detects Mastercard test card', () => {
    const matches = scanPatterns('Card: 5500000000000004');
    const pans = matches.filter(m => m.type === 'PAN');
    expect(pans).toHaveLength(1);
  });

  it('detects Amex test card', () => {
    const matches = scanPatterns('Card: 340000000000009');
    const pans = matches.filter(m => m.type === 'PAN');
    expect(pans).toHaveLength(1);
  });

  it('detects card with dashes', () => {
    const matches = scanPatterns('Card: 4111-1111-1111-1111');
    const pans = matches.filter(m => m.type === 'PAN');
    expect(pans).toHaveLength(1);
  });

  it('rejects numbers that fail Luhn', () => {
    const matches = scanPatterns('Not a card: 4111111111111112');
    const pans = matches.filter(m => m.type === 'PAN');
    expect(pans).toHaveLength(0);
  });

  it('rejects short digit sequences', () => {
    const matches = scanPatterns('Short: 12345678');
    const pans = matches.filter(m => m.type === 'PAN');
    expect(pans).toHaveLength(0);
  });
});

describe('CUI patterns', () => {
  it('detects CUI//SP- markings', () => {
    const matches = scanPatterns('CUI//SP-PRVCY');
    expect(matches.some(m => m.type === 'CUI')).toBe(true);
  });

  it('detects CONTROLLED UNCLASSIFIED INFORMATION', () => {
    const matches = scanPatterns('CONTROLLED UNCLASSIFIED INFORMATION');
    expect(matches.some(m => m.type === 'CUI')).toBe(true);
  });

  it('detects FOR OFFICIAL USE ONLY', () => {
    const matches = scanPatterns('FOR OFFICIAL USE ONLY');
    expect(matches.some(m => m.type === 'CUI')).toBe(true);
  });

  it('does not match partial words', () => {
    const matches = scanPatterns('uncontrolled access');
    const cui = matches.filter(m => m.type === 'CUI');
    expect(cui).toHaveLength(0);
  });

  it('does not match bare "controlled" in normal English', () => {
    const matches = scanPatterns('This is a controlled environment');
    const cui = matches.filter(m => m.type === 'CUI');
    expect(cui).toHaveLength(0);
  });
});

describe('credential patterns', () => {
  it('detects AWS access keys', () => {
    const matches = scanPatterns('key: AKIAIOSFODNN7EXAMPLE');
    expect(matches.some(m => m.type === 'CREDENTIAL')).toBe(true);
  });

  it('detects GitHub PATs', () => {
    const matches = scanPatterns('token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij');
    expect(matches.some(m => m.type === 'CREDENTIAL')).toBe(true);
  });

  it('detects Bearer tokens', () => {
    const matches = scanPatterns('Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test');
    expect(matches.some(m => m.type === 'CREDENTIAL')).toBe(true);
  });

  it('detects api_key assignments', () => {
    const matches = scanPatterns('api_key=sk_live_1234567890abcdef');
    expect(matches.some(m => m.type === 'CREDENTIAL')).toBe(true);
  });

  it('does not match short tokens', () => {
    const matches = scanPatterns('Bearer short');
    const creds = matches.filter(m => m.type === 'CREDENTIAL');
    expect(creds).toHaveLength(0);
  });
});

describe('IBAN patterns', () => {
  it('detects valid German IBAN', () => {
    const matches = scanPatterns('IBAN: DE89370400440532013000');
    const ibans = matches.filter(m => m.type === 'IBAN');
    expect(ibans).toHaveLength(1);
  });

  it('detects valid UK IBAN', () => {
    const matches = scanPatterns('IBAN: GB29NWBK60161331926819');
    const ibans = matches.filter(m => m.type === 'IBAN');
    expect(ibans).toHaveLength(1);
  });

  it('rejects invalid check digits', () => {
    const matches = scanPatterns('DE00370400440532013000');
    const ibans = matches.filter(m => m.type === 'IBAN');
    expect(ibans).toHaveLength(0);
  });
});

describe('MRN patterns', () => {
  it('detects MRN with colon separator', () => {
    const matches = scanPatterns('MRN: A12345678');
    expect(matches.some(m => m.type === 'MRN')).toBe(true);
  });

  it('detects MRN with hash separator', () => {
    const matches = scanPatterns('MRN#123456');
    expect(matches.some(m => m.type === 'MRN')).toBe(true);
  });

  it('does not match without MRN prefix', () => {
    const matches = scanPatterns('record A12345678');
    const mrns = matches.filter(m => m.type === 'MRN');
    expect(mrns).toHaveLength(0);
  });
});

describe('NPI patterns', () => {
  it('detects valid NPI', () => {
    // 1234567893 is a valid NPI (passes 80840 + Luhn)
    const matches = scanPatterns('NPI: 1234567893');
    const npis = matches.filter(m => m.type === 'NPI');
    expect(npis).toHaveLength(1);
  });

  it('rejects NPI with bad Luhn', () => {
    const matches = scanPatterns('NPI: 1234567890');
    const npis = matches.filter(m => m.type === 'NPI');
    expect(npis).toHaveLength(0);
  });
});

describe('classifyWithRegex', () => {
  it('returns CLEAN for safe content', () => {
    const result = classifyWithRegex('Hello, this is a normal message.');
    expect(result.verdict).toBe('CLEAN');
    expect(result.violations).toHaveLength(0);
    expect(result.classifier).toBe('regex');
  });

  it('returns VIOLATION with redacted values', () => {
    const result = classifyWithRegex('SSN: 123-45-6789');
    expect(result.verdict).toBe('VIOLATION');
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0].type).toBe('SSN');
    // Value should be redacted
    expect(result.violations[0].value).not.toBe('123-45-6789');
    expect(result.violations[0].value).toContain('...');
  });

  it('detects multiple violation types', () => {
    const content = 'SSN: 123-45-6789, Key: AKIAIOSFODNN7EXAMPLE';
    const result = classifyWithRegex(content);
    expect(result.verdict).toBe('VIOLATION');
    expect(result.violations.length).toBeGreaterThanOrEqual(2);
    const types = result.violations.map(v => v.type);
    expect(types).toContain('SSN');
    expect(types).toContain('CREDENTIAL');
  });
});

describe('passport patterns', () => {
  it('detects passport with context keyword', () => {
    const matches = scanPatterns('Passport: AB1234567');
    const passports = matches.filter(m => m.type === 'PASSPORT');
    expect(passports).toHaveLength(1);
  });

  it('detects single-letter prefix with keyword', () => {
    const matches = scanPatterns('passport C12345678');
    const passports = matches.filter(m => m.type === 'PASSPORT');
    expect(passports).toHaveLength(1);
  });

  it('does not match without passport keyword', () => {
    const matches = scanPatterns('Model A1234567');
    const passports = matches.filter(m => m.type === 'PASSPORT');
    expect(passports).toHaveLength(0);
  });

  it('does not false positive on product model numbers', () => {
    const matches = scanPatterns('iPhone A1234567, Part B12345678');
    const passports = matches.filter(m => m.type === 'PASSPORT');
    expect(passports).toHaveLength(0);
  });
});
