#!/usr/bin/env node
// Deterministic synthetic corpus generator for the aicomply accuracy harness.
//
// Produces 200 positives + 200 hard-negatives per detection class into
// bench/corpus/<class>.jsonl. Re-running with no args reproduces the same
// corpus byte-for-byte (Mulberry32 PRNG with fixed seeds).
//
// NO REAL PII. SSNs are constructed from synthetic area/group/serial triples
// that satisfy the regex + validator without corresponding to real records.
// PANs are Luhn-valid numbers in synthetic IIN ranges. IBANs use synthetic
// BBANs with correctly-computed mod-97 check digits.
//
// Each line is a JSONL record:
//   { class, label, text, variant }
//
// where:
//   class   = SSN | PAN | IBAN | CUI | CREDENTIAL | PASSPORT | MRN | NPI
//   label   = "positive" | "negative"
//   text    = the content to scan
//   variant = canonical | nfkc | zero-width | whitespace | base64 |
//             url-encoded | near-miss | prose-mention | wrong-format

import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CORPUS_DIR = resolve(__dirname, 'corpus');
mkdirSync(CORPUS_DIR, { recursive: true });

// ---------------------------------------------------------------------------
// Deterministic PRNG (Mulberry32)
// ---------------------------------------------------------------------------
function mulberry32(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function randInt(rng, lo, hi) {
  return Math.floor(rng() * (hi - lo + 1)) + lo;
}

function pick(rng, arr) {
  return arr[Math.floor(rng() * arr.length)];
}

function pad(n, width) {
  const s = String(n);
  return s.length >= width ? s : '0'.repeat(width - s.length) + s;
}

// ---------------------------------------------------------------------------
// Validator math (mirrors src/classifier/regex/patterns.ts)
// ---------------------------------------------------------------------------
function luhnCheckDigit(digits) {
  // Compute the Luhn check digit for the given partial number (without check digit).
  let sum = 0;
  let alt = true; // we're computing from rightmost added position
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let n = parseInt(digits[i], 10);
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return (10 - (sum % 10)) % 10;
}

function ibanMod97(s) {
  // String-based mod 97 to handle 30-digit numbers without BigInt.
  let rem = 0;
  for (const d of s) rem = (rem * 10 + parseInt(d, 10)) % 97;
  return rem;
}

function buildIban(countryCode, bban) {
  // ISO 13616: rearrange BBAN + countryCode + "00", convert letters to digits,
  // mod 97, check digit = 98 - rem. Then concat country + checkDigits + bban.
  const rearr = bban + countryCode + '00';
  let numeric = '';
  for (const ch of rearr) {
    const code = ch.charCodeAt(0);
    if (code >= 65 && code <= 90) numeric += String(code - 55);
    else numeric += ch;
  }
  const check = 98 - ibanMod97(numeric);
  return countryCode + pad(check, 2) + bban;
}

// ---------------------------------------------------------------------------
// Adversarial mutations
// ---------------------------------------------------------------------------
function toFullwidthDigits(s) {
  return s.replace(/[0-9]/g, (d) => String.fromCodePoint(0xff10 + parseInt(d, 10)));
}

function injectZeroWidth(s) {
  return s.split('').join('​');
}

function spaceOutDigits(s) {
  // Insert spaces between digit characters only (preserves separators).
  let out = '';
  for (let i = 0; i < s.length; i += 1) {
    out += s[i];
    if (i + 1 < s.length && /\d/.test(s[i]) && /\d/.test(s[i + 1])) out += ' ';
  }
  return out;
}

function toBase64(s) {
  return Buffer.from(s, 'utf8').toString('base64');
}

function toUrlEncoded(s) {
  return encodeURIComponent(s);
}

// ---------------------------------------------------------------------------
// SSN generators
// ---------------------------------------------------------------------------
function generateValidSsn(rng) {
  // area: 1-665 or 667-899
  const area = rng() < 0.5 ? randInt(rng, 1, 665) : randInt(rng, 667, 899);
  const group = randInt(rng, 1, 99);
  const serial = randInt(rng, 1, 9999);
  return `${pad(area, 3)}-${pad(group, 2)}-${pad(serial, 4)}`;
}

function ssnNegatives(rng, n) {
  const out = [];
  // All negatives must FAIL the SSN validator (area 666 / 9xx, group 00,
  // serial 0000) OR fail the regex shape entirely. Otherwise we're
  // labeling true positives as negatives and inflating the FP count.
  const generators = [
    // Invalid area: 666
    () => `666-${pad(randInt(rng, 1, 99), 2)}-${pad(randInt(rng, 1, 9999), 4)}`,
    // Invalid area: 9xx
    () => `${randInt(rng, 900, 999)}-${pad(randInt(rng, 1, 99), 2)}-${pad(randInt(rng, 1, 9999), 4)}`,
    // Group is 00
    () => `${pad(randInt(rng, 1, 665), 3)}-00-${pad(randInt(rng, 1, 9999), 4)}`,
    // Serial is 0000
    () => `${pad(randInt(rng, 1, 665), 3)}-${pad(randInt(rng, 1, 99), 2)}-0000`,
    // Phone number look-alike (10 digits, not SSN format)
    () => `(${randInt(rng, 200, 999)}) ${randInt(rng, 200, 999)}-${randInt(rng, 1000, 9999)}`,
    // Missing a digit - does not match \d{3}-\d{2}-\d{4}
    () => `${pad(randInt(rng, 1, 665), 3)}-${pad(randInt(rng, 1, 99), 2)}-${pad(randInt(rng, 1, 999), 3)}`,
    // Date sequence YYYY-MM-DD (4-2-2 doesn't match 3-2-4 SSN shape)
    () => `${randInt(rng, 1900, 2030)}-${pad(randInt(rng, 1, 12), 2)}-${pad(randInt(rng, 1, 28), 2)}`,
    // 4-2-4 (book/part code shape) - first group is 4 digits, not 3, so SSN regex won't match.
    () => `${randInt(rng, 1000, 9999)}-${randInt(rng, 10, 99)}-${randInt(rng, 1000, 9999)} CODE`,
  ];
  for (let i = 0; i < n; i += 1) {
    const text = pick(rng, generators)();
    out.push({ class: 'SSN', label: 'negative', text: `Reference: ${text}.`, variant: 'near-miss' });
  }
  return out;
}

// ---------------------------------------------------------------------------
// PAN generators
// ---------------------------------------------------------------------------
function generateValidPan(rng) {
  // Choose issuer: Visa (16), MC (16), Amex (15), Discover (16).
  const issuer = pick(rng, ['visa', 'mc', 'amex', 'disc']);
  let head;
  let totalLen;
  if (issuer === 'visa') { head = '4'; totalLen = 16; }
  else if (issuer === 'mc') { head = String(randInt(rng, 51, 55)); totalLen = 16; }
  else if (issuer === 'amex') { head = pick(rng, ['34', '37']); totalLen = 15; }
  else { head = '6011'; totalLen = 16; }
  let body = head;
  while (body.length < totalLen - 1) body += String(randInt(rng, 0, 9));
  const check = luhnCheckDigit(body);
  return body + String(check);
}

function panNegatives(rng, n) {
  const out = [];
  for (let i = 0; i < n; i += 1) {
    const variant = pick(rng, ['non-luhn', 'invalid-iin', 'too-short', 'too-long', 'prose-number']);
    let text;
    if (variant === 'non-luhn') {
      // Random 16 digits, almost certainly fails Luhn.
      let s = '';
      for (let j = 0; j < 16; j += 1) s += String(randInt(rng, 0, 9));
      text = s;
    } else if (variant === 'invalid-iin') {
      // Starts with 1 or 7 (unallocated), Luhn-valid.
      const head = pick(rng, ['1', '7', '8']);
      let body = head;
      while (body.length < 15) body += String(randInt(rng, 0, 9));
      text = body + String(luhnCheckDigit(body));
    } else if (variant === 'too-short') {
      let s = '';
      for (let j = 0; j < 12; j += 1) s += String(randInt(rng, 0, 9));
      text = s;
    } else if (variant === 'too-long') {
      let s = '';
      for (let j = 0; j < 20; j += 1) s += String(randInt(rng, 0, 9));
      text = s;
    } else {
      text = `Order ${randInt(rng, 100000, 999999)} qty ${randInt(rng, 1, 999)}`;
    }
    out.push({ class: 'PAN', label: 'negative', text: `Transaction ${text} cleared.`, variant });
  }
  return out;
}

// ---------------------------------------------------------------------------
// IBAN generators
// ---------------------------------------------------------------------------
function generateValidIban(rng) {
  // Generate a German-style IBAN (DE, 22 chars total, 18-digit BBAN).
  // BBAN structure varies by country; we use the German format which is all digits.
  let bban = '';
  for (let i = 0; i < 18; i += 1) bban += String(randInt(rng, 0, 9));
  return buildIban('DE', bban);
}

function ibanNegatives(rng, n) {
  const out = [];
  for (let i = 0; i < n; i += 1) {
    const variant = pick(rng, ['bad-checksum', 'wrong-length', 'invalid-country']);
    let text;
    if (variant === 'bad-checksum') {
      // Generate a valid IBAN then corrupt the check digit.
      const good = generateValidIban(rng);
      const wrongCheck = (parseInt(good.slice(2, 4), 10) + 1) % 100;
      text = good.slice(0, 2) + pad(wrongCheck, 2) + good.slice(4);
    } else if (variant === 'wrong-length') {
      let bban = '';
      for (let j = 0; j < 10; j += 1) bban += String(randInt(rng, 0, 9));
      text = 'DE' + pad(randInt(rng, 10, 99), 2) + bban;
    } else {
      // Invalid country code (ZZ doesn't exist) but otherwise valid shape.
      let bban = '';
      for (let j = 0; j < 18; j += 1) bban += String(randInt(rng, 0, 9));
      text = 'ZZ' + pad(randInt(rng, 10, 99), 2) + bban;
    }
    out.push({ class: 'IBAN', label: 'negative', text: `Account ${text}.`, variant });
  }
  return out;
}

// ---------------------------------------------------------------------------
// NPI generators (10-digit, Luhn-check with 80840 prefix)
// ---------------------------------------------------------------------------
function generateValidNpi(rng) {
  // Generate first 9 digits, then compute the 10th so the full Luhn check
  // of "80840" + 10-digit NPI passes.
  let head = '';
  for (let i = 0; i < 9; i += 1) head += String(randInt(rng, 0, 9));
  const check = luhnCheckDigit('80840' + head);
  return head + String(check);
}

function npiNegatives(rng, n) {
  const out = [];
  for (let i = 0; i < n; i += 1) {
    // Build a Luhn-VALID 10-digit (with 80840 prefix), then force a fail
    // by bumping the check digit. Guarantees Luhn(80840 + bad) != 0.
    let head = '';
    for (let j = 0; j < 9; j += 1) head += String(randInt(rng, 0, 9));
    const realCheck = luhnCheckDigit('80840' + head);
    const wrongCheck = (realCheck + randInt(rng, 1, 9)) % 10;
    const bad = head + String(wrongCheck);
    out.push({ class: 'NPI', label: 'negative', text: `NPI: ${bad}.`, variant: 'bad-luhn' });
  }
  return out;
}

// ---------------------------------------------------------------------------
// CUI generators (no validator; just the regex)
// ---------------------------------------------------------------------------
const CUI_SP_TYPES = ['PROPIN', 'ITAR', 'NUCLEAR', 'PRVCY', 'EXPT-CTRL', 'NOFORN'];
const CUI_TYPES = ['BASIC', 'SP-DCRIT', 'LE-INV', 'TAX', 'HLTH', 'ADMIN', 'GENINFO'];

function generateValidCui(rng) {
  const variant = randInt(rng, 0, 3);
  if (variant === 0) return `CUI//SP-${pick(rng, CUI_SP_TYPES)}`;
  if (variant === 1) return `CUI//${pick(rng, CUI_TYPES)}`;
  if (variant === 2) return 'CONTROLLED UNCLASSIFIED INFORMATION';
  return 'FOR OFFICIAL USE ONLY';
}

function cuiNegatives(rng, n) {
  const out = [];
  const lines = [
    'The legal department maintains a controlled access list.',
    'Use of the CUI Registry by federal agencies is voluntary.',
    'For official channels only - see the procurement memo.',
    'Information classification is governed by E.O. 13526.',
    'This document is unclassified and may be shared freely.',
  ];
  for (let i = 0; i < n; i += 1) {
    out.push({ class: 'CUI', label: 'negative', text: pick(rng, lines), variant: 'prose-mention' });
  }
  return out;
}

// ---------------------------------------------------------------------------
// CREDENTIAL generators
// ---------------------------------------------------------------------------
function randAlnum(rng, n, upper = false) {
  const chars = upper
    ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    : 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let out = '';
  for (let i = 0; i < n; i += 1) out += chars[Math.floor(rng() * chars.length)];
  return out;
}

function generateValidCredential(rng) {
  const variant = randInt(rng, 0, 4);
  if (variant === 0) return `AKIA${randAlnum(rng, 16, true)}`;
  if (variant === 1) return `ghp_${randAlnum(rng, 36)}`;
  if (variant === 2) return `github_pat_${randAlnum(rng, 82)}`;
  if (variant === 3) return `Bearer ${randAlnum(rng, 32)}`;
  return `api_key=${randAlnum(rng, 24)}`;
}

function credentialNegatives(rng, n) {
  const out = [];
  for (let i = 0; i < n; i += 1) {
    const variant = pick(rng, ['short-bearer', 'akia-short', 'ghp-short', 'docs-mention', 'placeholder']);
    let text;
    if (variant === 'short-bearer') text = `Bearer X`;
    else if (variant === 'akia-short') text = `AKIA${randAlnum(rng, 8, true)}`;
    else if (variant === 'ghp-short') text = `ghp_${randAlnum(rng, 12)}`;
    else if (variant === 'docs-mention') text = 'Set api_key to your actual key in production.';
    else text = 'Use placeholder ${API_KEY} during local development.';
    out.push({ class: 'CREDENTIAL', label: 'negative', text, variant });
  }
  return out;
}

// ---------------------------------------------------------------------------
// PASSPORT generators
// ---------------------------------------------------------------------------
function generateValidPassport(rng) {
  const letters = String.fromCharCode(0x41 + randInt(rng, 0, 25)) + String.fromCharCode(0x41 + randInt(rng, 0, 25));
  const len = randInt(rng, 6, 9);
  let digits = '';
  for (let i = 0; i < len; i += 1) digits += String(randInt(rng, 0, 9));
  const prefix = pick(rng, ['Passport: ', 'passport ', 'Travel document #', 'Passport-']);
  return `${prefix}${letters}${digits}`;
}

function passportNegatives(rng, n) {
  const out = [];
  for (let i = 0; i < n; i += 1) {
    const variant = pick(rng, ['no-context', 'wrong-format', 'prose']);
    let text;
    if (variant === 'no-context') text = `${String.fromCharCode(0x41 + randInt(rng, 0, 25))}${String.fromCharCode(0x41 + randInt(rng, 0, 25))}${randInt(rng, 100000, 999999999)}`;
    else if (variant === 'wrong-format') text = `Passport renewal date: ${randInt(rng, 2025, 2035)}-${pad(randInt(rng, 1, 12), 2)}`;
    else text = 'The passport application form requires two photographs.';
    out.push({ class: 'PASSPORT', label: 'negative', text, variant });
  }
  return out;
}

// ---------------------------------------------------------------------------
// MRN generators
// ---------------------------------------------------------------------------
function generateValidMrn(rng) {
  const prefix = pick(rng, ['MRN: ', 'MRN ', 'MRN#', 'MRN-', 'mrn: ']);
  const len = randInt(rng, 6, 12);
  // Real-world MRNs always contain at least one digit. Force one in a
  // random position so synthetic positives match the regex's tightened
  // shape (digit-required, see patterns.ts MRN entry).
  let body = '';
  for (let i = 0; i < len; i += 1) body += pick(rng, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.split(''));
  const digitPos = randInt(rng, 0, len - 1);
  const digit = String(randInt(rng, 0, 9));
  body = body.slice(0, digitPos) + digit + body.slice(digitPos + 1);
  return `${prefix}${body}`;
}

function mrnNegatives(rng, n) {
  const out = [];
  const lines = [
    'The MRN system was updated last Tuesday.',
    'See section 4.2 of the MRN handbook.',
    'MRN training is required for new admits.',
    'Patient charts are accessible via the MRN portal.',
    'MRN audit logs retain entries for 7 years.',
  ];
  for (let i = 0; i < n; i += 1) {
    out.push({ class: 'MRN', label: 'negative', text: pick(rng, lines), variant: 'prose-mention' });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Build a class's full positive set including adversarial variants
// ---------------------------------------------------------------------------
function buildPositives(klass, rng, count, generateFn, supportsBase64 = false) {
  const out = [];
  const canonicalCount = Math.floor(count * 0.5);
  const advCount = count - canonicalCount;
  // 50% canonical
  for (let i = 0; i < canonicalCount; i += 1) {
    const core = generateFn(rng);
    const sentence = `Record: ${core}.`;
    out.push({ class: klass, label: 'positive', text: sentence, variant: 'canonical' });
  }
  // 50% adversarial - interleaved variants
  const variants = ['nfkc', 'zero-width', 'whitespace'];
  if (supportsBase64) variants.push('base64', 'url-encoded');
  for (let i = 0; i < advCount; i += 1) {
    const v = variants[i % variants.length];
    const core = generateFn(rng);
    let text;
    if (v === 'nfkc') text = `Record: ${toFullwidthDigits(core)}.`;
    else if (v === 'zero-width') text = `Record: ${injectZeroWidth(core)}.`;
    else if (v === 'whitespace') text = `Record: ${spaceOutDigits(core)}.`;
    else if (v === 'base64') {
      // Wrap with context so the Base64-encoded blob clears the 24-char
      // length gate even when the underlying payload is short (e.g. an SSN
      // is only 11 chars; Base64 alone would be ~16 chars).
      text = `payload: ${toBase64(`Record holds value=${core} verified`)}`;
    } else {
      // Same rationale for URL-encoded: ensure ≥ 2 percent-escapes.
      text = `payload: ${toUrlEncoded(`record = ${core}; type = sensitive`)}`;
    }
    out.push({ class: klass, label: 'positive', text, variant: v });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Main: build, write each class to bench/corpus/<class>.jsonl
// ---------------------------------------------------------------------------
const COUNT_PER_LABEL = 200;

const CLASSES = [
  { name: 'SSN',        pos: (rng) => buildPositives('SSN', rng, COUNT_PER_LABEL, generateValidSsn, true), neg: ssnNegatives },
  { name: 'PAN',        pos: (rng) => buildPositives('PAN', rng, COUNT_PER_LABEL, generateValidPan, true), neg: panNegatives },
  { name: 'IBAN',       pos: (rng) => buildPositives('IBAN', rng, COUNT_PER_LABEL, generateValidIban, true), neg: ibanNegatives },
  { name: 'NPI',        pos: (rng) => buildPositives('NPI', rng, COUNT_PER_LABEL, () => `NPI: ${generateValidNpi(rng)}`, false), neg: npiNegatives },
  { name: 'CUI',        pos: (rng) => buildPositives('CUI', rng, COUNT_PER_LABEL, generateValidCui, false), neg: cuiNegatives },
  { name: 'CREDENTIAL', pos: (rng) => buildPositives('CREDENTIAL', rng, COUNT_PER_LABEL, generateValidCredential, true), neg: credentialNegatives },
  { name: 'PASSPORT',   pos: (rng) => buildPositives('PASSPORT', rng, COUNT_PER_LABEL, generateValidPassport, false), neg: passportNegatives },
  { name: 'MRN',        pos: (rng) => buildPositives('MRN', rng, COUNT_PER_LABEL, generateValidMrn, false), neg: mrnNegatives },
];

let totalPos = 0;
let totalNeg = 0;

for (const klass of CLASSES) {
  // Separate seed per class so changes to one class's count don't shift others.
  const posRng = mulberry32(klass.name.charCodeAt(0) * 1009 + 1);
  const negRng = mulberry32(klass.name.charCodeAt(0) * 2003 + 2);
  const positives = klass.pos(posRng);
  const negatives = klass.neg(negRng, COUNT_PER_LABEL);
  const lines = [...positives, ...negatives].map((r) => JSON.stringify(r)).join('\n') + '\n';
  const filename = resolve(CORPUS_DIR, `${klass.name.toLowerCase()}.jsonl`);
  writeFileSync(filename, lines, 'utf8');
  console.log(`  wrote ${klass.name}: ${positives.length} positives + ${negatives.length} negatives → ${filename}`);
  totalPos += positives.length;
  totalNeg += negatives.length;
}

console.log(`\n  total: ${totalPos} positives + ${totalNeg} negatives across ${CLASSES.length} classes`);
