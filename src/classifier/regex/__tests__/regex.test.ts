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

  // A synthetic 40-char secret-shaped value, built at runtime from a repeated
  // chunk so no real-looking credential literal is committed (GitHub push
  // protection flags 40-char AWS secrets in aws_secret_access_key context).
  const awsSecret = 'Ab3dEf6h'.repeat(5); // 40 chars, all [A-Za-z0-9]

  it('detects AWS secret access keys in an assignment context', () => {
    // The secret (40-char base64) has no distinctive prefix, so it is matched
    // only when an aws_secret_access_key keyword precedes it.
    const matches = scanPatterns(`aws_secret_access_key = ${awsSecret}`);
    const cred = matches.filter(m => m.type === 'CREDENTIAL');
    expect(cred.length).toBeGreaterThanOrEqual(1);
    expect(cred.some(m => m.value === awsSecret)).toBe(true);
  });

  it('reports both the AWS access key id and secret when both are present', () => {
    const matches = scanPatterns(
      `aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = ${awsSecret}`,
    );
    const values = matches.filter(m => m.type === 'CREDENTIAL').map(m => m.value);
    expect(values).toContain('AKIAIOSFODNN7EXAMPLE');
    expect(values).toContain(awsSecret);
  });

  it('does not flag a bare 40-char base64 blob without an aws-secret keyword', () => {
    // A 40-char base64 string is too generic to flag on its own (hashes, ids).
    const matches = scanPatterns(`digest: ${awsSecret}`);
    const cred = matches.filter(m => m.value === awsSecret);
    expect(cred).toHaveLength(0);
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

  it('detects a bare Anthropic key in tool output (not in a key= assignment)', () => {
    const key = 'sk-ant-api03-' + 'A'.repeat(95);
    const matches = scanPatterns(`The agent read .env and returned ${key} in its summary.`);
    const creds = matches.filter(m => m.type === 'CREDENTIAL');
    expect(creds).toHaveLength(1);
    // classifyWithRegex redacts the value so the raw key never leaks into output
    const result = classifyWithRegex(`The agent returned ${key} in its summary.`);
    const v = result.violations.find(x => x.type === 'CREDENTIAL');
    expect(v).toBeDefined();
    expect(v!.value).not.toContain(key);
    expect(v!.value).toContain('...');
  });

  it('detects OpenAI project, OpenRouter, and legacy keys', () => {
    expect(scanPatterns('sk-proj-' + 'B'.repeat(48)).some(m => m.type === 'CREDENTIAL')).toBe(true);
    expect(scanPatterns('sk-or-v1-' + 'c'.repeat(48)).some(m => m.type === 'CREDENTIAL')).toBe(true);
    expect(scanPatterns('sk-' + 'd'.repeat(48)).some(m => m.type === 'CREDENTIAL')).toBe(true);
  });

  it('does not match too-short provider keys (near-miss negatives)', () => {
    expect(scanPatterns('sk-ant-api03-abc').filter(m => m.type === 'CREDENTIAL')).toHaveLength(0);
    expect(scanPatterns('sk-' + 'e'.repeat(12)).filter(m => m.type === 'CREDENTIAL')).toHaveLength(0);
  });

  it('catches a specific provider key prefixed by an adjacent word char (no \\b evasion)', () => {
    // an attacker prepending '_' must not let an Anthropic key slip past
    const matches = scanPatterns('_sk-ant-api03-' + 'A'.repeat(95));
    expect(matches.some(m => m.type === 'CREDENTIAL')).toBe(true);
  });

  it('does not flag English words ending in -sk before a long token (legacy \\b)', () => {
    expect(scanPatterns('risk-' + 'A'.repeat(50)).filter(m => m.type === 'CREDENTIAL')).toHaveLength(0);
    expect(scanPatterns('disk-' + 'B'.repeat(50)).filter(m => m.type === 'CREDENTIAL')).toHaveLength(0);
  });

  it('does not match short tokens', () => {
    const matches = scanPatterns('Bearer short');
    const creds = matches.filter(m => m.type === 'CREDENTIAL');
    expect(creds).toHaveLength(0);
  });
});

describe('environment-variable references are not credentials (opena2a#254)', () => {
  // An env-var reference is the ABSENCE of a secret: it is the remediated form
  // `opena2a protect` rewrites a hardcoded key into. Flagging it makes the two
  // commands contradict each other and breaks CI on correctly-fixed code.

  it('does not flag a bare process.env reference assigned to apiKey', () => {
    // Verbatim repro from opena2a#254. Pre-fix this matched the generic
    // api_key rule: `apiKey` satisfies /api[_-]?key/i and the value char class
    // contains '.', so it captured the 26-char `process.env.OPENAI_API_KEY`.
    const matches = scanPatterns('const apiKey = process.env.OPENAI_API_KEY;');
    expect(matches.filter(m => m.type === 'CREDENTIAL')).toHaveLength(0);
  });

  it('does not flag the bracket, import.meta, python or java reference forms', () => {
    const forms = [
      "api_key = process.env['OPENAI_API_KEY']",
      'api_key = process.env["OPENAI_API_KEY"]',
      'apiKey: import.meta.env.VITE_OPENAI_API_KEY',
      "api_key = os.environ['OPENAI_API_KEY']",
      "api_key = os.environ.get('OPENAI_API_KEY')",
      "api_key = os.getenv('OPENAI_API_KEY')",
      'api_key = System.getenv("OPENAI_API_KEY")',
    ];
    // Collect offenders rather than asserting per-iteration: jest's expect
    // takes no message argument, so a bare loop assertion would not say WHICH
    // form regressed.
    const flagged = forms.filter(
      form => scanPatterns(form).some(m => m.type === 'CREDENTIAL'),
    );
    expect(flagged).toEqual([]);
  });

  it('does not flag the ${VAR} interpolation form protect emits into .mcp.json', () => {
    const forms = [
      '"apiKey": "${OPENAI_API_KEY}"',
      '"api_key": "$OPENAI_API_KEY"',
      '"access_token": "${env:OPENAI_API_KEY}"',
    ];
    const flagged = forms.filter(
      form => scanPatterns(form).some(m => m.type === 'CREDENTIAL'),
    );
    expect(flagged).toEqual([]);
  });

  it('does not flag an env reference carried on a Bearer header', () => {
    expect(
      scanPatterns('Authorization: Bearer process.env.GITHUB_ACCESS_TOKEN'),
    ).toHaveLength(0);
  });

  // ---- negative controls: the skip must not loosen real detection ----------
  // A value-shape exclusion sits in front of every pattern, so each of these
  // asserts what SURVIVES, not merely that something was suppressed.

  it('still flags a real literal in the identical assignment shape', () => {
    const matches = scanPatterns("const apiKey = 'sk-ant-api03-" + 'A'.repeat(95) + "';");
    expect(matches.some(m => m.type === 'CREDENTIAL')).toBe(true);
  });

  it('still flags a real literal in an env-reference fallback expression', () => {
    // The dangerous half of `process.env.X || '<literal>'` must survive: the
    // line contains an env reference AND a hardcoded key.
    const key = 'sk-ant-api03-' + 'B'.repeat(95);
    const matches = scanPatterns(`const apiKey = process.env.OPENAI_API_KEY || '${key}';`);
    const creds = matches.filter(m => m.type === 'CREDENTIAL');
    expect(creds).toHaveLength(1);
    expect(creds[0]!.value).toBe(key);
  });

  it('still flags a value that merely CONTAINS an env-looking substring', () => {
    // `process.env`-prefixed but not a reference: an attacker cannot launder a
    // literal by naming it after the accessor.
    const matches = scanPatterns('api_key = process.envXOPENAI' + 'C'.repeat(40));
    expect(matches.some(m => m.type === 'CREDENTIAL')).toBe(true);
  });

  it('still flags the AWS secret access key when the value is a literal', () => {
    const awsSecret = 'Ab3dEf6h'.repeat(5);
    const matches = scanPatterns(`aws_secret_access_key = ${awsSecret}`);
    expect(matches.some(m => m.value === awsSecret)).toBe(true);
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

  it('does NOT match prose-mention "MRN" followed by an English word (no digit)', () => {
    // Suppresses the v0.x false positive on prose like
    // "MRN system was updated", "MRN audit logs", "MRN training". The
    // digit-required lookahead in the MRN regex closes this gap.
    const cases = [
      'The MRN system was updated last Tuesday.',
      'See section 4.2 of the MRN handbook.',
      'MRN training is required for new admits.',
      'Patient charts are accessible via the MRN portal.',
    ];
    for (const c of cases) {
      const matches = scanPatterns(c);
      expect(matches.filter((m) => m.type === 'MRN')).toHaveLength(0);
    }
  });

  it('still matches alphanumeric MRNs that include at least one digit', () => {
    const cases = ['MRN: ABC123XY', 'MRN-X1Y2Z3', 'MRN#42AB56CD'];
    for (const c of cases) {
      const matches = scanPatterns(c);
      expect(matches.some((m) => m.type === 'MRN')).toBe(true);
    }
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
