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
 *   2  usage error
 *
 * Dependency-free by design (no commander / yargs) to honor the org's
 * small-library pattern. argv is parsed by hand.
 */

import { fstatSync, readFileSync, statSync, type Stats } from 'fs';
import { comply } from './index';
import { DEFAULT_NANOMIND_DAEMON_URL } from './classifier/guard-client/nanomind-adapter';
import { PATTERN_TYPES } from './classifier/regex/pack';
import type { ComplyResult, Violation } from './types';

// Keep in sync with package.json version on every release bump.
const VERSION = '2.2.3';

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
  --version,-V  Print version
  --help, -h    This help
  --            Ends the options; each later argument is an input, so a file
                name can start with - (aicomply scan -- -notes.txt)

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
  2  usage error

EXAMPLES
  aicomply scan ./support-ticket.txt
  cat transcript.log | aicomply scan --json
  aicomply scan src/*.txt -q

The library API is the production surface: https://github.com/opena2a-org/aicomply
`;

const SCAN_HELP = `aicomply scan -- scan files or piped stdin for sensitive content

Runs the deterministic regex layer over each input, plus the optional semantic
Guard layer when a local nanomind-daemon is reachable. Prints a verdict per
input and an overall verdict.

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
                each finding carries its line and column in the input)
  --quiet, -q   Print only the verdict line (CLEAN / VIOLATION / DENY)
  --help, -h    This help
  --            Ends the options; each later argument is an input, so a file
                name can start with - (aicomply scan -- -notes.txt)

EXIT CODES
  0  CLEAN          no findings from the layers that ran
  1  VIOLATION/DENY findings present (usable as a CI gate)
  2  usage error

EXAMPLES
  aicomply scan ./support-ticket.txt
  cat transcript.log | aicomply scan --json
  aicomply scan src/*.txt -q
`;

/**
 * What the CLI prints in place of a detected value. The library's redacted
 * `value` can still carry most of a short match (a 7-character passport
 * number keeps 6 of its characters), and a finding does not record the
 * matched value's length (`start`/`end` can span a keyword such as
 * "Passport:"), so no share of the value is printed.
 */
const MASKED_VALUE = '•••';

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => (data += chunk));
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', () => resolve(data));
  });
}

/** stdin is scanned when no file is named or `-` is among the files. */
function stdinRequested(files: string[]): boolean {
  return files.length === 0 || files.includes('-');
}

const STDIN_NOT_READ = 'stdin not read because files were named; add - to scan it too';

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

async function collectSources(files: string[]): Promise<Source[]> {
  const realFiles = files.filter((f) => f !== '-');
  const sources: Source[] = [];

  for (const file of realFiles) {
    try {
      sources.push({ label: file, content: readFileSync(file, 'utf8') });
    } catch {
      // The path exists, so "check the path" would send the user the wrong way.
      if (isDirectory(file)) {
        throw new UsageError(
          `'${file}' is a directory, and directories are not scanned. Name the files in it:\n` +
            `  aicomply scan ${filesGlob(file)}`,
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
    sources.push({ label: '(stdin)', content: await readStdin() });
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

// The renderers locate every finding of one input in turn, so the newline
// offsets of the last content are kept instead of recounted per finding: a
// large log can carry thousands of findings.
let newlineCache: { content: string; offsets: number[] } | undefined;

function newlineOffsets(content: string): number[] {
  if (newlineCache === undefined || newlineCache.content !== content) {
    const offsets: number[] = [];
    for (let i = content.indexOf('\n'); i !== -1; i = content.indexOf('\n', i + 1)) {
      offsets.push(i);
    }
    newlineCache = { content, offsets };
  }
  return newlineCache.offsets;
}

/**
 * Where a position in the original content is: `line` is one plus the number
 * of `\n` before `originalStart`, and `column` counts from 1 after the last of
 * them, in the string's own indexing (UTF-16 code units). Only `\n` ends a
 * line, so a `\r` stays the last character of its line. Returns undefined when
 * there is no position to locate.
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
  const offsets = newlineOffsets(content);
  // Count the newlines before originalStart; the offsets ascend.
  let lo = 0;
  let hi = offsets.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (offsets[mid] < originalStart) lo = mid + 1;
    else hi = mid;
  }
  const lastNewline = lo === 0 ? -1 : offsets[lo - 1];
  return { line: lo + 1, column: originalStart - lastNewline };
}

/**
 * Only a pattern match comes from a content view and carries original
 * positions. For a decoded-base64 / decoded-url match those positions are the
 * enclosing encoded token, so that is what the location names.
 */
function locateFinding(content: string, v: Violation): FindingLocation | undefined {
  return v.view === undefined ? undefined : locate(content, v.originalStart);
}

export function renderHuman(sources: Source[], results: ComplyResult[]): void {
  const out = process.stdout;
  let anyGuard = false;
  let totalFindings = 0;
  let worst: 'CLEAN' | 'VIOLATION' | 'DENY' = 'CLEAN';

  out.write('\n');
  for (let i = 0; i < sources.length; i++) {
    const src = sources[i];
    const res = results[i];
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
    for (const v of res.violations as Violation[]) {
      const layer = v.classifier;
      const view = v.view && v.view !== 'normalized' ? `  view ${v.view}` : '';
      const loc = locateFinding(src.content, v);
      const where = loc ? `  line ${loc.line} col ${loc.column}` : '';
      out.write(
        `    ${v.type.padEnd(12)} ${MASKED_VALUE.padEnd(18)} confidence ${v.confidence.toFixed(2)}  layer ${layer}${view}${where}\n`,
      );
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
    verdict: results[i].verdict,
    guardActive: guardActive(results[i]),
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
    process.stdout.write(`${VERSION}\n`);
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
  // socket gets one stderr line after the report.
  const unread = stdinRequested(args.files) ? undefined : unreadStdin();
  if (unread === 'content') {
    throw new UsageError(
      'stdin is a file with content and is not read because files were named; add - to scan it too:\n' +
        '  aicomply scan - <files>',
    );
  }

  const sources = await collectSources(args.files);
  const results: ComplyResult[] = [];
  for (const src of sources) {
    results.push(await comply({ content: src.content }));
  }

  if (args.json) renderJson(sources, results);
  else if (args.quiet) {
    const worst = results.some((r) => r.verdict === 'DENY')
      ? 'DENY'
      : results.some((r) => r.verdict === 'VIOLATION')
        ? 'VIOLATION'
        : 'CLEAN';
    process.stdout.write(`${worst}\n`);
  } else renderHuman(sources, results);

  if (unread === 'stream') process.stderr.write(`aicomply: ${STDIN_NOT_READ}\n`);

  // Exit 1 if anything is not CLEAN, so the CLI works as a CI gate.
  return results.some((r) => r.verdict !== 'CLEAN') ? 1 : 0;
}

// Only run when invoked as a binary, not when imported by tests.
if (require.main === module) {
  run(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((err) => {
      process.stderr.write(`aicomply: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exit(2);
    });
}
