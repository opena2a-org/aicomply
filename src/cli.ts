#!/usr/bin/env node
/**
 * aicomply CLI -- a zero-integration try-path for the dual-layer classifier.
 *
 * The library API (`comply()`) is the production surface. This CLI exists so a
 * developer can evaluate aicomply against real content in one command, before
 * writing any integration code:
 *
 *   npx @opena2a/aicomply scan ./support-ticket.txt
 *   echo "My SSN is 123-45-6789" | aicomply scan
 *   aicomply scan src/*.log --json
 *
 * Exit codes make it usable as a CI gate:
 *   0  CLEAN          - no findings
 *   1  VIOLATION/DENY - findings present
 *   2  usage error, or no input (stdin is a terminal or every input is 0 bytes)
 *
 * Dependency-free by design (no commander / yargs) to honor the org's
 * small-library pattern. argv is parsed by hand.
 */

import { fstatSync, readFileSync, statSync, type Stats } from 'fs';
import { comply } from './index';
import { DEFAULT_NANOMIND_DAEMON_URL } from './classifier/guard-client/nanomind-adapter';
import { PATTERN_TYPES } from './classifier/regex/pack';
import type { ComplyResult, Violation } from './types';
import { packageVersion } from './version';

/**
 * A recoverable usage error (exit code 2). Thrown rather than calling
 * process.exit() inline so run() stays pure and testable -- only the bin
 * wrapper at the bottom of this file actually exits the process.
 */
class UsageError extends Error {}

interface ParsedArgs {
  command: string | undefined;
  files: string[];
  json: boolean;
  quiet: boolean;
  help: boolean;
  version: boolean;
}

function parseArgs(argv: string[]): ParsedArgs {
  const parsed: ParsedArgs = {
    command: undefined,
    files: [],
    json: false,
    quiet: false,
    help: false,
    version: false,
  };
  // `--` ends the options (POSIX utility syntax guideline 10): each later
  // argument is an operand, so a file whose name starts with - can be named.
  let optionsEnded = false;
  for (const arg of argv) {
    if (optionsEnded || !arg.startsWith('-') || arg === '-') {
      if (parsed.command === undefined) parsed.command = arg;
      else parsed.files.push(arg);
    } else if (arg === '--') optionsEnded = true;
    else if (arg === '--json') parsed.json = true;
    else if (arg === '--quiet' || arg === '-q') parsed.quiet = true;
    else if (arg === '--help' || arg === '-h') parsed.help = true;
    else if (arg === '--version' || arg === '-V') parsed.version = true;
    else {
      // Unknown flag -- surface it rather than silently ignoring.
      throw new UsageError(`unknown option '${arg}'`);
    }
  }
  return parsed;
}

/**
 * The option spellings parseArgs reads. Before `--` each of them is an
 * option, so an input with one of these names was named after `--`.
 */
const OPTION_NAMES = new Set(['--json', '--quiet', '-q', '--help', '-h', '--version', '-V']);

/**
 * The report lists at most this many findings of an input, then one line that
 * counts the rest by type; --json lists every finding.
 */
const MAX_FINDING_LINES = 50;

const HELP = `aicomply -- inline content classifier for AI agent I/O

Detects SSNs, card and bank account numbers, passport and medical record
numbers, provider identifiers (NPI), credentials and CUI markings before your
agent ships content to a hosted LLM. Runs a deterministic regex layer always,
plus an optional semantic Guard layer when a local nanomind-daemon is reachable.
Email addresses, phone numbers, postal addresses, dates of birth and names are
not detected (see PATTERN CLASSES).

USAGE
  aicomply scan [file...]      Scan files for sensitive content
  aicomply scan -              Read content from stdin
  echo "text" | aicomply scan  Pipe content from stdin

OPTIONS
  --json        Machine-readable JSON output (verdict + findings)
  --quiet, -q   Print only the verdict line
  --version, -V Print version
  --help, -h    This help
  --            Ends the options; each later argument is an input, so a file
                name can start with - (aicomply scan -- -notes.txt)
                A lone - is still stdin after --; name a file called - as ./-

PATTERN CLASSES (regex layer)
  SSN         US Social Security numbers
  PAN         payment card numbers
  IBAN        bank account numbers
  PASSPORT    passport numbers
  MRN         medical record numbers
  NPI         US National Provider Identifiers
  CREDENTIAL  API keys and access tokens
  CUI         Controlled Unclassified Information markings
  Content holding only other data, such as email addresses, phone numbers,
  postal addresses, dates of birth or names, is CLEAN. What is not detected:
  https://github.com/opena2a-org/aicomply/blob/main/docs/detection.md

EXIT CODES
  0  CLEAN          no findings from the layers that ran
  1  VIOLATION/DENY findings present (usable as a CI gate)
  2  usage error, or no input: stdin is a terminal or every input is 0 bytes

EXAMPLES
  aicomply scan ./support-ticket.txt
  cat transcript.log | aicomply scan --json
  aicomply scan src/*.txt -q

The library API is the production surface: https://github.com/opena2a-org/aicomply
`;

const SCAN_HELP = `aicomply scan -- scan files or piped stdin for sensitive content

Runs the deterministic regex layer over each input, plus the optional semantic
Guard layer when a local nanomind-daemon is reachable. Prints a verdict per
input and an overall verdict. An input of 0 bytes is not classified: it is
listed as "0 bytes, nothing to classify" (--json: "bytes": 0, "verdict": null,
"layers": []), and the inputs that were scanned decide the exit code.
The report lists the first ${MAX_FINDING_LINES} findings of each input and counts the rest by
type; --json lists every finding.

The regex layer checks SSNs, card and bank account numbers, passport and
medical record numbers, provider identifiers (NPI), credentials and CUI
markings (aicomply --help lists the classes). It does not detect email
addresses, phone numbers, postal addresses, dates of birth or names:
  https://github.com/opena2a-org/aicomply/blob/main/docs/detection.md

USAGE
  aicomply scan [file...]      Scan one or more files
  aicomply scan -              Read content from stdin
  echo "text" | aicomply scan  Pipe content from stdin

OPTIONS
  --json        Machine-readable JSON output (verdict + findings, values masked;
                each finding carries its line and column in the input, and each
                input its size in bytes and the layers that ran)
  --quiet, -q   Print only the verdict line (CLEAN / VIOLATION / DENY);
                --json takes precedence when both are given
  --help, -h    This help
  --            Ends the options; each later argument is an input, so a file
                name can start with - (aicomply scan -- -notes.txt)
                A lone - is still stdin after --; name a file called - as ./-

EXIT CODES
  0  CLEAN          no findings from the layers that ran
  1  VIOLATION/DENY findings present (usable as a CI gate)
  2  usage error, or no input: stdin is a terminal or every input is 0 bytes

EXAMPLES
  aicomply scan ./support-ticket.txt
  cat transcript.log | aicomply scan --json
  aicomply scan src/*.txt -q
`;

/**
 * What the CLI prints in place of a detected value. The library's redacted
 * `value` still shows the last 2 or 4 characters of a value longer than 8
 * characters, and a finding has no field for the matched value's length
 * (`start`/`end` can span a keyword such as "Passport:"), so no share of the
 * value is printed.
 */
const MASKED_VALUE = '•••';

function readStdin(): Promise<Buffer> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    process.stdin.on('data', (chunk: Buffer) => chunks.push(chunk));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks)));
    process.stdin.on('error', () => resolve(Buffer.concat(chunks)));
  });
}

/** stdin is scanned when no file is named or `-` is among the files. */
function stdinRequested(files: string[]): boolean {
  return files.length === 0 || files.includes('-');
}

const STDIN_NOT_READ = 'stdin not read because files were named; add - to scan it too';

const QUIET_WITH_JSON = '--json takes precedence over --quiet; drop --json to print only the verdict line';

/**
 * What stdin holds when files are named without `-`, so it is not scanned.
 * Decided from fstat alone, never by reading: reading a pipe to its end waits
 * until its writer closes it, so a writer that holds it open and never writes
 * would hold up the scan.
 *
 *   'content'  a regular file with bytes (`aicomply scan a.txt < b.txt`)
 *   'stream'   a pipe or socket: what it carries is known only by reading it
 *   undefined  anything else: a terminal or /dev/null (character devices),
 *              an empty file, or no descriptor 0
 */
function unreadStdin(): 'content' | 'stream' | undefined {
  let stats: Stats;
  try {
    stats = fstatSync(0);
  } catch {
    return undefined;
  }
  if (stats.isFile()) return stats.size > 0 ? 'content' : undefined;
  if (stats.isFIFO() || stats.isSocket()) return 'stream';
  return undefined;
}

interface Source {
  label: string;
  content: string;
  /** How many bytes the input delivered. An input of 0 bytes is not classified. */
  bytes: number;
}

function isDirectory(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

/**
 * The glob the help uses (`src/*.txt`) for the files in `dir`, written as one
 * POSIX shell word: trailing slashes dropped, `./` put before a name that
 * starts with -, and the name single-quoted unless it holds only letters,
 * digits and `_@%+=:,./-`.
 */
export function filesGlob(dir: string): string {
  const trimmed = dir.replace(/\/+$/, '');
  if (trimmed === '') return '/*.txt';
  const name = trimmed.startsWith('-') ? `./${trimmed}` : trimmed;
  const word = /^[A-Za-z0-9_@%+=:,./-]+$/.test(name) ? name : `'${name.replace(/'/g, `'"'"'`)}'`;
  return `${word}/*.txt`;
}

/**
 * The text of an input. Bytes that start with a UTF-32, UTF-16 or UTF-8 byte
 * order mark are decoded in that encoding, without the mark; other bytes are
 * decoded as UTF-8. A byte sequence the encoding cannot decode becomes U+FFFD
 * and the rest is scanned, as in the Python CLI.
 */
export function decodeInput(data: Buffer): string {
  const [b0, b1, b2, b3] = data;
  // FF FE 00 00 is checked before FF FE: it is the UTF-32LE mark.
  if (data.length >= 4 && b0 === 0xff && b1 === 0xfe && b2 === 0 && b3 === 0) {
    return decodeUtf32(data.subarray(4), true);
  }
  if (data.length >= 4 && b0 === 0 && b1 === 0 && b2 === 0xfe && b3 === 0xff) {
    return decodeUtf32(data.subarray(4), false);
  }
  if (data.length >= 2 && b0 === 0xff && b1 === 0xfe) {
    return new TextDecoder('utf-16le', { ignoreBOM: true }).decode(data.subarray(2));
  }
  if (data.length >= 2 && b0 === 0xfe && b1 === 0xff) {
    // Swapped to little-endian; an odd last byte stays and decodes to U+FFFD.
    const le = Buffer.from(data.subarray(2));
    for (let i = 0; i + 1 < le.length; i += 2) {
      const hi = le[i];
      le[i] = le[i + 1];
      le[i + 1] = hi;
    }
    return new TextDecoder('utf-16le', { ignoreBOM: true }).decode(le);
  }
  // Kept, the UTF-8 mark was column 1 of the first line, so each finding on
  // that line was one column right of where an editor shows it.
  if (data.length >= 3 && b0 === 0xef && b1 === 0xbb && b2 === 0xbf) {
    return data.toString('utf8', 3);
  }
  return data.toString('utf8');
}

/**
 * UTF-32 without its mark. A unit above U+10FFFF or in the surrogate range, and
 * 1 to 3 bytes left over at the end, each become one U+FFFD.
 */
function decodeUtf32(data: Buffer, littleEndian: boolean): string {
  const parts: string[] = [];
  let i = 0;
  for (; i + 4 <= data.length; i += 4) {
    const cp = littleEndian ? data.readUInt32LE(i) : data.readUInt32BE(i);
    const valid = cp <= 0x10ffff && (cp < 0xd800 || cp > 0xdfff);
    parts.push(valid ? String.fromCodePoint(cp) : '�');
  }
  if (i < data.length) parts.push('�');
  return parts.join('');
}

/**
 * Reads each named file, then stdin when it is requested. `pipeUnread` is true
 * when stdin is a pipe or socket that is not read because files were named.
 */
async function collectSources(files: string[], pipeUnread: boolean): Promise<Source[]> {
  const realFiles = files.filter((f) => f !== '-');
  const sources: Source[] = [];

  for (const file of realFiles) {
    try {
      const data = readFileSync(file);
      sources.push({ label: file, content: decodeInput(data), bytes: data.length });
    } catch (err) {
      // The path exists, so "check the path" would send the user the wrong way.
      if (isDirectory(file)) {
        throw new UsageError(
          `'${file}' is a directory, and directories are not scanned. Name the files in it:\n` +
            `  aicomply scan ${filesGlob(file)}`,
        );
      }
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'EACCES' || code === 'EPERM') {
        throw new UsageError(`cannot read '${file}': permission denied`);
      }
      // The help's example `aicomply scan src/*.txt -q` puts the option after
      // the files, so it gets written after -- as well (`aicomply scan --
      // -notes.txt -q`), where it is an input.
      if (OPTION_NAMES.has(file)) {
        throw new UsageError(
          `cannot read '${file}': after -- every argument is an input; put ${file} before --`,
        );
      }
      throw new UsageError(`cannot read '${file}' (check the path). Try 'aicomply --help'.`);
    }
  }

  if (stdinRequested(files)) {
    if (process.stdin.isTTY) {
      // No piped input and no files -- guide the user rather than hang.
      throw new UsageError(
        'no input. Pass a file or pipe content:\n' +
          '  aicomply scan ./file.txt\n' +
          '  echo "My SSN is 123-45-6789" | aicomply scan',
      );
    }
    const data = await readStdin();
    sources.push({ label: '(stdin)', content: decodeInput(data), bytes: data.length });
  }

  // comply() runs no layer on empty content and returns CLEAN, so a run in
  // which no input carried a byte would print a verdict nothing reached.
  // Files come first in `sources`, then stdin. A pipe or socket left unread
  // can hold the content meant for the scan, so the line that says stdin was
  // not read follows the error, as it follows a report.
  if (sources.every((s) => s.bytes === 0)) {
    const empty = sources.map((s, i) =>
      i < realFiles.length ? `${s.label} is 0 bytes` : `${s.label} delivered 0 bytes`,
    );
    const note = pipeUnread ? `\naicomply: ${STDIN_NOT_READ}` : '';
    throw new UsageError(`no input: ${empty.join(', ')}${note}`);
  }

  return sources;
}

function guardActive(result: ComplyResult): boolean {
  return result.classifierResults.guard !== undefined;
}

/** A finding's 1-based line and column in the original content of its input. */
export interface FindingLocation {
  line: number;
  column: number;
}

interface ContentOffsets {
  content: string;
  newlines: number[];
  /** Index of the high surrogate of each surrogate pair. */
  surrogatePairs: number[];
}

// The renderers locate every finding of one input in turn, so the newline and
// surrogate-pair offsets of the last content are kept instead of recounted per
// finding: a large log can carry thousands of findings.
let offsetCache: ContentOffsets | undefined;

function contentOffsets(content: string): ContentOffsets {
  if (offsetCache === undefined || offsetCache.content !== content) {
    const newlines: number[] = [];
    for (let i = content.indexOf('\n'); i !== -1; i = content.indexOf('\n', i + 1)) {
      newlines.push(i);
    }
    // A character outside the Basic Multilingual Plane, such as an emoji, is
    // one code point held in two UTF-16 code units: a high surrogate followed
    // by a low one.
    const surrogatePairs: number[] = [];
    const pair = /[\uD800-\uDBFF][\uDC00-\uDFFF]/g;
    for (let m = pair.exec(content); m !== null; m = pair.exec(content)) {
      surrogatePairs.push(m.index);
    }
    offsetCache = { content, newlines, surrogatePairs };
  }
  return offsetCache;
}

/** How many of the ascending `offsets` are below `limit`. */
function countBelow(offsets: number[], limit: number): number {
  let lo = 0;
  let hi = offsets.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (offsets[mid] < limit) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/**
 * Where a position in the original content is: `line` is one plus the number
 * of `\n` before `originalStart`, and `column` is one plus the number of code
 * points between the last of them and `originalStart`, the count the Python
 * CLI prints. Only `\n` ends a line, so a `\r` stays the last character of its
 * line. Returns undefined when there is no position to locate.
 */
export function locate(
  content: string,
  originalStart: number | undefined,
): FindingLocation | undefined {
  if (
    originalStart === undefined ||
    !Number.isInteger(originalStart) ||
    originalStart < 0 ||
    originalStart > content.length
  ) {
    return undefined;
  }
  const { newlines, surrogatePairs } = contentOffsets(content);
  const before = countBelow(newlines, originalStart);
  const lineStart = before === 0 ? 0 : newlines[before - 1] + 1;
  // originalStart counts UTF-16 code units. A pair is two of them and one
  // code point, so each pair on the line that ends before originalStart takes
  // one off the column. A `\n` is never inside a pair, so no pair spans
  // lineStart.
  const pairs =
    countBelow(surrogatePairs, originalStart - 1) - countBelow(surrogatePairs, lineStart);
  return { line: before + 1, column: originalStart - lineStart + 1 - pairs };
}

/**
 * Only a pattern match comes from a content view and carries original
 * positions. For a decoded-base64 / decoded-url match those positions are the
 * enclosing encoded token, so that is what the location names.
 */
function locateFinding(content: string, v: Violation): FindingLocation | undefined {
  return v.view === undefined ? undefined : locate(content, v.originalStart);
}

interface LocatedFinding {
  v: Violation;
  loc: FindingLocation | undefined;
}

/**
 * The findings of one input in the order they appear in it: by line, then by
 * column. A finding without a location, such as a Guard finding, follows the
 * located ones. Findings at the same place keep the order comply() gave them.
 */
function inInputOrder(content: string, violations: Violation[]): LocatedFinding[] {
  return violations
    .map((v) => ({ v, loc: locateFinding(content, v) }))
    .sort((a, b) => {
      if (a.loc === undefined || b.loc === undefined) {
        return (a.loc === undefined ? 1 : 0) - (b.loc === undefined ? 1 : 0);
      }
      return a.loc.line - b.loc.line || a.loc.column - b.loc.column;
    });
}

/**
 * The line after the first MAX_FINDING_LINES findings of an input: how many
 * `rest` holds and how many of them are of each type, the most frequent type
 * first and, at equal counts, in the order the types first appear in `rest`.
 */
function notListedLine(rest: LocatedFinding[]): string {
  const byType = new Map<string, number>();
  for (const { v } of rest) byType.set(v.type, (byType.get(v.type) ?? 0) + 1);
  // Array.prototype.sort is stable, so equal counts keep the Map's order.
  const counts = [...byType]
    .sort((a, b) => b[1] - a[1])
    .map(([type, n]) => `${type} ${n}`)
    .join(', ');
  return `... ${rest.length} more (${counts}); use --json for all`;
}

export function renderHuman(sources: Source[], results: ComplyResult[]): void {
  const out = process.stdout;
  let anyGuard = false;
  let totalFindings = 0;
  let worst: 'CLEAN' | 'VIOLATION' | 'DENY' = 'CLEAN';

  // The findings of each flagged input in input order; an empty or CLEAN
  // input lists none. Each input lists its first MAX_FINDING_LINES.
  const ordered = sources.map((src, i) =>
    src.bytes === 0 || results[i].verdict === 'CLEAN'
      ? []
      : inInputOrder(src.content, results[i].violations),
  );

  // The type column is as wide as the longest type printed, and at least 12
  // characters: a Guard class such as exfiltration_pattern (20 characters) is
  // longer than any pattern class.
  let typeWidth = 12;
  for (const findings of ordered) {
    for (const { v } of findings.slice(0, MAX_FINDING_LINES)) {
      typeWidth = Math.max(typeWidth, v.type.length);
    }
  }

  out.write('\n');
  for (let i = 0; i < sources.length; i++) {
    const src = sources[i];
    const res = results[i];
    if (src.bytes === 0) {
      // No layer ran on it, so it gets no verdict and adds none to the total.
      out.write(`  EMPTY      ${src.label}   0 bytes, nothing to classify\n\n`);
      continue;
    }
    if (guardActive(res)) anyGuard = true;
    totalFindings += res.violations.length;
    if (res.verdict === 'DENY') worst = 'DENY';
    else if (res.verdict === 'VIOLATION' && worst !== 'DENY') worst = 'VIOLATION';

    const tag =
      res.verdict === 'CLEAN'
        ? 'CLEAN     '
        : res.verdict === 'DENY'
          ? 'DENY      '
          : 'VIOLATION ';
    out.write(`  ${tag} ${src.label}`);
    if (res.verdict === 'CLEAN') {
      out.write(`   no finding in the ${PATTERN_TYPES.length} pattern classes (aicomply --help lists them)\n\n`);
      continue;
    }
    out.write(`   ${res.violations.length} finding${res.violations.length === 1 ? '' : 's'}\n`);
    const findings = ordered[i];
    for (const { v, loc } of findings.slice(0, MAX_FINDING_LINES)) {
      const layer = v.classifier;
      const view = v.view && v.view !== 'normalized' ? `  view ${v.view}` : '';
      const where = loc ? `  line ${loc.line} col ${loc.column}` : '';
      out.write(
        `    ${v.type.padEnd(typeWidth)} ${MASKED_VALUE.padEnd(18)} confidence ${v.confidence.toFixed(2)}  layer ${layer}${view}${where}\n`,
      );
    }
    if (findings.length > MAX_FINDING_LINES) {
      out.write(`    ${notListedLine(findings.slice(MAX_FINDING_LINES))}\n`);
    }
    out.write('\n');
  }

  // Honest disclosure of which layers actually ran -- with a recovery path,
  // never a dead end (UX: empower, never shame).
  if (!anyGuard) {
    out.write(
      `  Semantic Guard layer: inactive (preview; no nanomind-daemon on ${DEFAULT_NANOMIND_DAEMON_URL}).\n` +
        '  It targets prompt-injection / exfiltration the regex layer cannot see, but the\n' +
        '  current model over-flags benign text - preview only, not for production gating.\n' +
        '  Try it: npm i @nanomind/daemon && npx nanomind-daemon start\n\n',
    );
  } else if (results.some(r => r.violations.some(v => v.classifier === 'guard'))) {
    // The same caveat, on the surface where it actually matters. It used to
    // appear ONLY when the Guard was inactive -- so the warning was shown when
    // it was harmless and hidden the moment the Guard started deciding
    // verdicts. A measured ~70% benign false-positive rate reaching a user as
    // an unqualified `confidence 1.00` is the opposite of empowering.
    out.write(
      '  Semantic Guard layer: active (preview). It targets prompt-injection /\n' +
        '  exfiltration the regex layer cannot see, but the current model over-flags\n' +
        '  benign text - treat guard-layer findings as advisory, not production gating.\n' +
        '  Regex-layer findings above are unaffected.\n\n',
    );
  }

  if (worst === 'CLEAN') {
    // CLEAN is also the verdict for an input no layer detects, so the line
    // states what was checked and makes no claim about the content.
    out.write('Verdict: CLEAN  ·  no findings from the layers that ran.\n');
  } else {
    out.write(
      `Verdict: ${worst}  ·  ${totalFindings} finding${totalFindings === 1 ? '' : 's'} across ${sources.length} input${sources.length === 1 ? '' : 's'}. ` +
        'Block, redact, or log before this content reaches an LLM.\n',
    );
  }
}

export function renderJson(sources: Source[], results: ComplyResult[]): void {
  const payload = sources.map((src, i) => ({
    source: src.label,
    // An input of 0 bytes was not classified: its `verdict` is null and its
    // `layers` is [].
    bytes: src.bytes,
    verdict: src.bytes === 0 ? null : results[i].verdict,
    guardActive: guardActive(results[i]),
    layers: results[i].layers,
    findings: results[i].violations.map((v) => {
      const loc = locateFinding(src.content, v);
      return {
        type: v.type,
        maskedValue: MASKED_VALUE,
        confidence: v.confidence,
        classifier: v.classifier,
        // Only pattern matches come from a content view. A Guard finding has
        // none, so it prints null rather than claiming the normalized stream.
        view: v.view ?? null,
        // The value is masked, so its place in the input is what a user
        // searches for; null for a finding with no position there.
        line: loc?.line ?? null,
        column: loc?.column ?? null,
      };
    }),
  }));
  process.stdout.write(JSON.stringify(payload, null, 2) + '\n');
}

export async function run(argv: string[]): Promise<number> {
  try {
    return await runInner(argv);
  } catch (err) {
    if (err instanceof UsageError) {
      process.stderr.write(`aicomply: ${err.message}\n`);
      return 2;
    }
    throw err;
  }
}

async function runInner(argv: string[]): Promise<number> {
  const args = parseArgs(argv);

  if (args.version) {
    process.stdout.write(`${packageVersion()}\n`);
    return 0;
  }
  // Scan-scoped help: `aicomply scan --help` documents the scan command and its
  // flags, rather than falling through to the generic top-level banner.
  if (args.command === 'scan' && args.help) {
    process.stdout.write(SCAN_HELP);
    return 0;
  }
  if (args.help || args.command === undefined) {
    process.stdout.write(HELP);
    return args.command === undefined && !args.help ? 2 : 0;
  }
  if (args.command !== 'scan') {
    process.stderr.write(`aicomply: unknown command '${args.command}'. Try 'aicomply --help'.\n`);
    return 2;
  }

  // A file with content on stdin is a usage error before any scan; a pipe or
  // socket gets one stderr line after the report, or after the no-input error
  // when every named file is 0 bytes.
  const unread = stdinRequested(args.files) ? undefined : unreadStdin();
  if (unread === 'content') {
    throw new UsageError(
      'stdin is a file with content and is not read because files were named; add - to scan it too:\n' +
        '  aicomply scan - <files>',
    );
  }

  const sources = await collectSources(args.files, unread === 'stream');
  const results: ComplyResult[] = [];
  for (const src of sources) {
    results.push(await comply({ content: src.content }));
  }
  // An input of 0 bytes was not classified, so the inputs that were decide
  // the verdict and the exit code.
  const scanned = results.filter((_, i) => sources[i].bytes > 0);

  if (args.json) renderJson(sources, results);
  else if (args.quiet) {
    const worst = scanned.some((r) => r.verdict === 'DENY')
      ? 'DENY'
      : scanned.some((r) => r.verdict === 'VIOLATION')
        ? 'VIOLATION'
        : 'CLEAN';
    process.stdout.write(`${worst}\n`);
  } else renderHuman(sources, results);

  const notes = args.json && args.quiet ? [QUIET_WITH_JSON] : [];
  if (unread === 'stream') notes.push(STDIN_NOT_READ);
  if (notes.length > 0) {
    // Most of a large report can still be queued for a piped stdout. Writing
    // the notes once it is flushed keeps them after the report where both
    // streams go to one pipe.
    await flushed(process.stdout);
    process.stderr.write(notes.map((note) => `aicomply: ${note}\n`).join(''));
  }

  // Exit 1 if anything is not CLEAN, so the CLI works as a CI gate.
  return scanned.some((r) => r.verdict !== 'CLEAN') ? 1 : 0;
}

/**
 * Resolves once `stream` has handed everything written to it so far to the
 * operating system. When the stream is a pipe, write() can return while most
 * of the output is still queued. A write's callback runs after every earlier
 * write to the same stream has finished, so an empty write marks the end of
 * the queue. The callback also runs when the write fails, as it does with
 * EPIPE once the reader has closed the pipe (`| head`).
 */
function flushed(stream: NodeJS.WriteStream): Promise<void> {
  return new Promise((resolve) => {
    stream.write('', () => resolve());
  });
}

/**
 * Exits with `code` once stdout and stderr are flushed. process.exit()
 * discards what is still queued: a --json report piped to another command
 * arrived cut off.
 */
function exitWhenFlushed(code: number): void {
  Promise.all([flushed(process.stdout), flushed(process.stderr)]).then(() => process.exit(code));
}

// Only run when invoked as a binary, not when imported by tests.
if (require.main === module) {
  // A write that fails, as one does with EPIPE once the reader has closed the
  // pipe, would be thrown as an unhandled 'error' event. The listeners go on
  // before run(), as run() waits for stdout to be flushed before it writes
  // its stderr notes.
  for (const stream of [process.stdout, process.stderr]) stream.on('error', () => {});
  run(process.argv.slice(2))
    .then((code) => exitWhenFlushed(code))
    .catch((err) => {
      process.stderr.write(`aicomply: ${err instanceof Error ? err.message : String(err)}\n`);
      exitWhenFlushed(2);
    });
}
