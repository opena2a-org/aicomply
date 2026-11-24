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
 *   2  usage error, no input, or no verdict (an input that cannot be read or is INCOMPLETE)
 *      no input: stdin is a terminal or every input is 0 bytes
 *
 * Dependency-free by design (no commander / yargs) to honor the org's
 * small-library pattern. argv is parsed by hand.
 */

import { constants as bufferConstants } from 'buffer';
import { fstatSync, readFileSync, statSync, type Stats } from 'fs';
import { comply } from './index';
import { DEFAULT_NANOMIND_DAEMON_URL } from './classifier/guard-client/nanomind-adapter';
import { PATTERN_NOT_EVALUATED } from './classifier/regex';
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

/** The start of the first line that names the patterns not evaluated on an input. */
const NOT_EVALUATED_LABEL = '    not evaluated: ';

/**
 * The lines that name the patterns not evaluated on an input are at most this
 * many columns wide, unless one id alone is wider: they break only between ids.
 */
const NAMES_LINE_WIDTH = 80;

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
  2  usage error, no input, or no verdict (an input that cannot be read or is INCOMPLETE)
     no input: stdin is a terminal or every input is 0 bytes

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
listed as EMPTY, "0 bytes, nothing to classify" (--json: "bytes": 0,
"verdict": "EMPTY", "layers": []), and the inputs that were scanned decide the
exit code.
A named file that cannot be read is listed as UNREADABLE with the reason
(--json: "verdict": "UNREADABLE", "error"); the other inputs are scanned, and
the run exits 2 unless one of them is flagged.
A binary input (one whose text holds a NUL byte) is decoded as text,
as any input is, and scanned; its line in the report says "binary, scanned
as text". A value stored compressed or encoded in it is not seen.
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
  --quiet, -q   Print only the verdict line (CLEAN / INCOMPLETE / VIOLATION / DENY);
                --json takes precedence when both are given
  --help, -h    This help
  --            Ends the options; each later argument is an input, so a file
                name can start with - (aicomply scan -- -notes.txt)
                A lone - is still stdin after --; name a file called - as ./-

EXIT CODES
  0  CLEAN          no findings from the layers that ran
  1  VIOLATION/DENY findings present (usable as a CI gate)
  2  usage error, no input, or no verdict (an input that cannot be read or is INCOMPLETE)
     no input: stdin is a terminal or every input is 0 bytes

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

/**
 * The verdict of an input of 0 bytes, in the report and in --json. No layer
 * runs on such an input, so it gets this word in place of a layer's verdict.
 */
const EMPTY_VERDICT = 'EMPTY';

/**
 * The verdict of a named file that could not be read or decoded, in the
 * report and in --json. It is not scanned, so no layer gives it a verdict.
 */
const UNREADABLE_VERDICT = 'UNREADABLE';

/**
 * The verdicts of an input that was scanned, from the worst: --quiet prints
 * the worst one any input has, and the report gives it as the overall verdict.
 */
const VERDICTS = ['DENY', 'VIOLATION', 'INCOMPLETE', 'CLEAN'] as const;
type InputVerdict = (typeof VERDICTS)[number];

/**
 * The verdict of a scanned input. comply() gives VIOLATION for content on
 * which the regex engine could not run a pattern, with a
 * PATTERN_NOT_EVALUATED finding for each such pattern. When those are the
 * only findings, the input was not evaluated in full and nothing was found
 * in what was: it is INCOMPLETE, no verdict and never CLEAN.
 */
function inputVerdict(res: ComplyResult): InputVerdict {
  if (res.verdict === 'DENY') return 'DENY';
  const notEvaluated = new Set((res.unevaluatedPatterns ?? []).map((id) => `${PATTERN_NOT_EVALUATED}:${id}`));
  if (notEvaluated.size === 0) return res.verdict;
  return res.violations.every((v) => notEvaluated.has(v.type)) ? 'INCOMPLETE' : 'VIOLATION';
}

/** The worst of `verdicts`, the verdicts of the inputs that were scanned. */
function worstVerdict(verdicts: InputVerdict[]): InputVerdict {
  return VERDICTS.find((v) => verdicts.includes(v)) ?? 'CLEAN';
}

/**
 * The verdict of the run, for the verdicts of the inputs that were scanned
 * and the number of inputs that could not be read: the worst of the verdicts,
 * but INCOMPLETE in place of CLEAN when an input could not be read, as the
 * scan reached no verdict on it.
 */
function overallVerdict(verdicts: InputVerdict[], unreadable: number): InputVerdict {
  const worst = worstVerdict(verdicts);
  return worst === 'CLEAN' && unreadable > 0 ? 'INCOMPLETE' : worst;
}

/**
 * The exit code for the verdict of the run: 1 when any input is flagged
 * (VIOLATION or DENY), whatever the others are; otherwise 2 when any is
 * INCOMPLETE or could not be read, as the scan reached no verdict on it;
 * otherwise 0.
 */
function exitCode(overall: InputVerdict): 0 | 1 | 2 {
  return overall === 'CLEAN' ? 0 : overall === 'INCOMPLETE' ? 2 : 1;
}

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
  /**
   * True when the decoded text holds a NUL character, as a binary file does.
   * Its bytes are still decoded as text and scanned; the report says so on
   * its input line.
   */
  binary?: boolean;
  /**
   * Set for a named file that could not be read or decoded, which is not
   * scanned: `reason` is what the report and --json give for it, and
   * `message` the usage error when no input could be scanned.
   */
  unreadable?: { reason: string; message: string };
}

/** A named file that could not be read or decoded, as a source that is not scanned. */
function unreadableSource(label: string, reason: string, message: string): Source {
  return { label, content: '', bytes: 0, unreadable: { reason, message } };
}

/**
 * Why a named file could not be read, for the error `err` that reading it
 * threw. Throws a UsageError for an option name written after --.
 */
function unreadableFile(file: string, err: unknown): Source {
  const code = (err as NodeJS.ErrnoException).code;
  // The path exists, so "check the path" would send the user the wrong way.
  // EISDIR is what reading a directory fails with, ENOENT a missing path;
  // the stat covers a directory whose read fails with another code.
  if (code === 'EISDIR' || isDirectory(file)) {
    const glob = filesGlob(file);
    return unreadableSource(
      file,
      `a directory, and directories are not scanned; name the files in it: aicomply scan ${glob}`,
      `'${file}' is a directory, and directories are not scanned. Name the files in it:\n` +
        `  aicomply scan ${glob}`,
    );
  }
  let why: string;
  if (code === 'EACCES' || code === 'EPERM') {
    why = 'permission denied';
  } else if (code === 'ERR_FS_FILE_TOO_LARGE') {
    // On Node 26.12, readFileSync reads a file of 2147483647 bytes and
    // refuses one of 2147483648 (2 GiB) or more.
    why = 'it is 2 GiB or larger, and this CLI reads files under 2 GiB';
  } else if (OPTION_NAMES.has(file)) {
    // The help's example `aicomply scan src/*.txt -q` puts the option after
    // the files, so it gets written after -- as well (`aicomply scan --
    // -notes.txt -q`), where it is an input. That is a usage error, not an
    // input to list as unreadable: the scan would run without the option.
    throw new UsageError(`cannot read '${file}': after -- every argument is an input; put ${file} before --`);
  } else {
    return unreadableSource(
      file,
      'cannot read (check the path)',
      `cannot read '${file}' (check the path). Try 'aicomply --help'.`,
    );
  }
  return unreadableSource(file, `cannot read: ${why}`, `cannot read '${file}': ${why}`);
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
 * 1 to 3 bytes left over at the end, each become one U+FFFD. The length of the
 * text is counted first, and text longer than the longest string throws a
 * RangeError before any of it is decoded.
 */
function decodeUtf32(data: Buffer, littleEndian: boolean): string {
  const end = data.length - (data.length % 4);
  const codePoint = (i: number): number => {
    const cp = littleEndian ? data.readUInt32LE(i) : data.readUInt32BE(i);
    return cp <= 0x10ffff && (cp < 0xd800 || cp > 0xdfff) ? cp : 0xfffd;
  };
  // The length in UTF-16 code units, where a code point above U+FFFF takes two
  // (a surrogate pair), and whether every code point is at most U+00FF. The
  // U+FFFD for bytes left over is one code unit, above U+00FF.
  let length = end < data.length ? 1 : 0;
  let latin1 = end === data.length;
  for (let i = 0; i < end; i += 4) {
    const cp = codePoint(i);
    length += cp > 0xffff ? 2 : 1;
    if (cp > 0xff) latin1 = false;
  }
  if (length > bufferConstants.MAX_STRING_LENGTH) {
    throw new RangeError(`the text is ${length} UTF-16 code units, longer than the longest string`);
  }
  // The text is written into one buffer and read back as one string. On Node
  // 26.12, one string for each code point, joined at the end, ran out of heap
  // on 629145600 bytes of U+1F600 and threw "Invalid array length" on
  // 629145600 bytes of U+0061. Text whose code points are all at most U+00FF
  // is read back as latin1, one byte for each: read back as UTF-16LE, a text
  // of 157286373 such characters, in lines, ran out of memory in the
  // JSON.stringify of the Guard request, where the same text decoded from
  // UTF-8 was scanned.
  let o = 0;
  if (latin1) {
    const out = Buffer.allocUnsafe(length);
    for (let i = 0; i < end; i += 4) out[o++] = codePoint(i);
    return out.toString('latin1');
  }
  const out = Buffer.allocUnsafe(length * 2);
  for (let i = 0; i < end; i += 4) {
    const cp = codePoint(i);
    if (cp > 0xffff) {
      o = out.writeUInt16LE(0xd800 + ((cp - 0x10000) >> 10), o);
      o = out.writeUInt16LE(0xdc00 + ((cp - 0x10000) & 0x3ff), o);
    } else {
      o = out.writeUInt16LE(cp, o);
    }
  }
  if (end < data.length) out.writeUInt16LE(0xfffd, o);
  return out.toString('utf16le');
}

/**
 * decodeInput for an input that `name` names in a message: a quoted file
 * name, or (stdin). A decode that throws is a usage error that gives the
 * input's size in bytes.
 */
function decodeNamed(data: Buffer, name: string): string {
  const content = tryDecode(data);
  if (content === undefined) throw new UsageError(`cannot scan ${name}: ${tooLargeToDecode(data)}`);
  return content;
}

/** decodeInput, or undefined when the decode throws. */
function tryDecode(data: Buffer): string | undefined {
  try {
    return decodeInput(data);
  } catch {
    // Each decoder writes U+FFFD for bytes it cannot decode and goes on, so
    // what fails here is the length. On Node 26.12, toString throws
    // ERR_STRING_TOO_LONG past the longest string, and the UTF-16 TextDecoder
    // throws ERR_ENCODING_INVALID_ENCODED_DATA from 268435456 bytes on.
    // decodeUtf32 throws a RangeError past the longest string.
    return undefined;
  }
}

/**
 * Whether decoded text is binary: it holds a NUL character, which text files
 * do not and nearly every binary format does. The mark of a UTF-16 or UTF-32
 * input is decoded first, so the zero bytes of its text do not count.
 */
export function isBinary(content: string): boolean {
  return content.includes('\u0000');
}

/**
 * The note on the input line of a binary input. Its bytes were decoded as
 * text, each sequence that does not decode as U+FFFD, and the patterns ran on
 * that text, so a value stored in a compressed or encoded form is not seen.
 */
export const BINARY_NOTE = 'binary, scanned as text;';

function tooLargeToDecode(data: Buffer): string {
  return `at ${data.length} bytes it is too large to decode as one input`;
}

/**
 * Reads each named file, then stdin when it is requested. `pipeUnread` is true
 * when stdin is a pipe or socket that is not read because files were named.
 * A named file that cannot be read or decoded does not end the run: it is
 * kept in its place as an unreadable source, and the other inputs are
 * scanned. When no input carries a byte to scan, the run ends on a usage
 * error that says why for each input.
 */
async function collectSources(files: string[], pipeUnread: boolean): Promise<Source[]> {
  const realFiles = files.filter((f) => f !== '-');
  const sources: Source[] = [];

  for (const file of realFiles) {
    let data: Buffer;
    try {
      data = readFileSync(file);
    } catch (err) {
      sources.push(unreadableFile(file, err));
      continue;
    }
    const content = tryDecode(data);
    if (content === undefined) {
      const why = tooLargeToDecode(data);
      sources.push(unreadableSource(file, `cannot scan: ${why}`, `cannot scan '${file}': ${why}`));
      continue;
    }
    sources.push({ label: file, content, bytes: data.length, binary: isBinary(content) });
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
    const content = decodeNamed(data, '(stdin)');
    sources.push({ label: '(stdin)', content, bytes: data.length, binary: isBinary(content) });
  }

  // comply() runs no layer on empty content and returns CLEAN, so a run in
  // which no input carried a byte would print a verdict nothing reached. An
  // input that could not be read carries none either. Each such input gets
  // its own line, then the inputs that were read get the no-input line.
  // Files come first in `sources`, then stdin. A pipe or socket left unread
  // can hold the content meant for the scan, so the line that says stdin was
  // not read follows the error, as it follows a report.
  if (sources.every((s) => s.bytes === 0)) {
    const lines = sources.flatMap((s) => (s.unreadable ? [s.unreadable.message] : []));
    const empty = sources.flatMap((s, i) =>
      s.unreadable ? [] : [i < realFiles.length ? `${s.label} is 0 bytes` : `${s.label} delivered 0 bytes`],
    );
    if (empty.length > 0) lines.push(`no input: ${empty.join(', ')}`);
    if (pipeUnread) lines.push(STDIN_NOT_READ);
    throw new UsageError(lines.join('\naicomply: '));
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
  newlines: Uint32Array;
  /**
   * Entry `b` is the number of surrogate pairs whose high surrogate is below
   * `b * PAIR_SAMPLE_SPAN`.
   */
  pairSamples: Uint32Array;
}

/**
 * The span, in code units, between two samples of the surrogate-pair count.
 * Locating a finding counts the pairs between the sample below it and its
 * offset, at most this many code units.
 */
const PAIR_SAMPLE_SPAN = 4096;

/**
 * Offsets into a content, in the order they are added, held in a Uint32Array
 * that doubles in length when it is full. On Node 26.12 an array holds at most
 * 134217728 entries (see normalize/text-builder.ts), and a content can hold
 * more newlines than that.
 */
class OffsetList {
  private offsets = new Uint32Array(1024);
  private length = 0;

  add(offset: number): void {
    if (this.length === this.offsets.length) {
      const grown = new Uint32Array(2 * this.length);
      grown.set(this.offsets);
      this.offsets = grown;
    }
    this.offsets[this.length] = offset;
    this.length += 1;
  }

  /** The offsets added, in the order they were added. */
  finish(): Uint32Array {
    return this.offsets.subarray(0, this.length);
  }
}

// The renderers locate every finding of one input in turn, so the newline
// offsets and surrogate-pair samples of the last content are kept instead of
// recounted per finding: a large log can carry thousands of findings.
let offsetCache: ContentOffsets | undefined;

function contentOffsets(content: string): ContentOffsets {
  if (offsetCache === undefined || offsetCache.content !== content) {
    const newlines = new OffsetList();
    for (let i = content.indexOf('\n'); i !== -1; i = content.indexOf('\n', i + 1)) {
      newlines.add(i);
    }
    // A content can hold more surrogate pairs than an array holds entries,
    // so their count is sampled every PAIR_SAMPLE_SPAN code units rather than
    // each pair's index kept.
    const pairSamples = new Uint32Array(Math.floor(content.length / PAIR_SAMPLE_SPAN) + 1);
    let pairs = 0;
    for (let b = 0; b < pairSamples.length; b++) {
      pairSamples[b] = pairs;
      pairs += countPairs(content, b * PAIR_SAMPLE_SPAN, (b + 1) * PAIR_SAMPLE_SPAN);
    }
    offsetCache = { content, newlines: newlines.finish(), pairSamples };
  }
  return offsetCache;
}

/**
 * How many surrogate pairs of `content` have their high surrogate at an index
 * from `start` up to, not including, `end`. A character outside the Basic
 * Multilingual Plane, such as an emoji, is one code point held in two UTF-16
 * code units: a high surrogate followed by a low one. A high surrogate is
 * never a low one, so whether a pair starts at an index depends only on the
 * two code units there.
 */
function countPairs(content: string, start: number, end: number): number {
  const last = Math.min(end, content.length - 1);
  let count = 0;
  for (let i = start; i < last; i++) {
    const unit = content.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = content.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        count += 1;
        i += 1;
      }
    }
  }
  return count;
}

/** How many surrogate pairs of `content` have their high surrogate below `limit`. */
function pairsBelow(content: string, pairSamples: Uint32Array, limit: number): number {
  if (limit <= 0) return 0;
  const b = Math.floor(limit / PAIR_SAMPLE_SPAN);
  return pairSamples[b] + countPairs(content, b * PAIR_SAMPLE_SPAN, limit);
}

/** How many of the ascending `offsets` are below `limit`. */
function countBelow(offsets: Uint32Array, limit: number): number {
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
  const { newlines, pairSamples } = contentOffsets(content);
  const before = countBelow(newlines, originalStart);
  const lineStart = before === 0 ? 0 : newlines[before - 1] + 1;
  // originalStart counts UTF-16 code units. A pair is two of them and one
  // code point, so each pair on the line that ends before originalStart takes
  // one off the column. A `\n` is never inside a pair, so no pair spans
  // lineStart.
  const pairs =
    pairsBelow(content, pairSamples, originalStart - 1) - pairsBelow(content, pairSamples, lineStart);
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

/**
 * The findings of a result that the report lists and counts: its violations
 * but the PATTERN_NOT_EVALUATED entries, as the lines under the input's row
 * name those patterns instead.
 */
function reportedFindings(res: ComplyResult): Violation[] {
  return res.violations.filter((v) => !v.type.startsWith(`${PATTERN_NOT_EVALUATED}:`));
}

/**
 * The lines under an input's row that name the patterns the regex engine
 * could not run on it, in the order given, joined by ", ". A line breaks only
 * between ids, before an id that would take it past NAMES_LINE_WIDTH columns,
 * and the next line starts at the column of the first id; every line but the
 * last ends with the comma. Every id is named. None when `ids` is empty.
 */
function notEvaluatedLines(ids: readonly string[]): string[] {
  const indent = ' '.repeat(NOT_EVALUATED_LABEL.length);
  const lines: string[] = [];
  let line = '';
  ids.forEach((id, i) => {
    const name = i === ids.length - 1 ? id : `${id},`;
    if (line === '') {
      line = NOT_EVALUATED_LABEL + name;
    } else if (line.length + 1 + name.length > NAMES_LINE_WIDTH) {
      lines.push(line);
      line = indent + name;
    } else {
      line += ` ${name}`;
    }
  });
  if (line !== '') lines.push(line);
  return lines;
}

export function renderHuman(sources: Source[], results: ComplyResult[]): void {
  const out = process.stdout;
  let anyGuard = false;
  let totalFindings = 0;
  // The verdict of each input that was scanned; an input of 0 bytes has none.
  const verdicts = sources.map((src, i) => (src.bytes === 0 ? undefined : inputVerdict(results[i])));
  const scanned = verdicts.filter((v): v is InputVerdict => v !== undefined);
  const unreadable = sources.filter((s) => s.unreadable).length;
  const worst = overallVerdict(scanned, unreadable);
  // The inputs that were scanned with a pattern the regex engine could not run.
  const notEvaluatedInputs = verdicts.filter(
    (v, i) => v !== undefined && (results[i].unevaluatedPatterns ?? []).length > 0,
  ).length;

  // The findings of each flagged input in input order; an empty, CLEAN or
  // INCOMPLETE input lists none. A pattern that was not evaluated is not a
  // finding: it is named under the input's row, never listed or counted here.
  // Each input lists its first MAX_FINDING_LINES.
  const ordered = sources.map((src, i) =>
    verdicts[i] === 'VIOLATION' || verdicts[i] === 'DENY'
      ? inInputOrder(src.content, reportedFindings(results[i]))
      : [],
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
    if (src.unreadable) {
      // It was not scanned, so it gets no layer's verdict and adds none to the
      // total; the verdict line counts it.
      out.write(`  ${UNREADABLE_VERDICT.padEnd(10)} ${src.label}   ${src.unreadable.reason}\n\n`);
      continue;
    }
    if (src.bytes === 0) {
      // No layer ran on it, so it gets no layer's verdict and adds none to the
      // total.
      out.write(`  ${EMPTY_VERDICT.padEnd(10)} ${src.label}   0 bytes, nothing to classify\n\n`);
      continue;
    }
    if (guardActive(res)) anyGuard = true;
    const verdict = verdicts[i] as InputVerdict;

    // Each verdict is at most 10 characters, the width of the column.
    out.write(`  ${verdict.padEnd(10)} ${src.label}${src.binary ? `   ${BINARY_NOTE}` : ''}`);
    const gap = src.binary ? ' ' : '   ';
    if (verdict === 'CLEAN') {
      out.write(`${gap}no finding in the ${PATTERN_TYPES.length} pattern classes (aicomply --help lists them)\n\n`);
      continue;
    }
    const findings = ordered[i];
    const unevaluated = res.unevaluatedPatterns ?? [];
    // The patterns that did not run are counted apart and named below the
    // findings; they are not findings.
    const k = unevaluated.length;
    const notRun = `${k} pattern${k === 1 ? '' : 's'} not evaluated`;
    if (verdict === 'INCOMPLETE') {
      out.write(`${gap}${notRun}\n`);
    } else {
      const n = findings.length;
      totalFindings += n;
      out.write(`${gap}${n} finding${n === 1 ? '' : 's'}${k === 0 ? '' : `, ${notRun}`}\n`);
    }
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
    for (const line of notEvaluatedLines(unevaluated)) out.write(`${line}\n`);
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

  out.write(verdictLine(worst, totalFindings, sources.length - unreadable, notEvaluatedInputs, unreadable));
}

/**
 * The report's last line. `worst` is the verdict of the run, `inputs` the
 * number of inputs that were read, `notEvaluated` the number of them with a
 * pattern the regex engine could not run, and `unreadable` the number of
 * named files that could not be read; each of the last two is given whenever
 * it is not 0.
 */
export function verdictLine(
  worst: InputVerdict,
  totalFindings: number,
  inputs: number,
  notEvaluated: number,
  unreadable = 0,
): string {
  const m = notEvaluated;
  const u = unreadable;
  const notRead = `${u} input${u === 1 ? '' : 's'} could not be read`;
  if (worst === 'CLEAN') {
    // CLEAN is also the verdict for an input no layer detects, so the line
    // states what was checked and makes no claim about the content.
    return 'Verdict: CLEAN  ·  no findings from the layers that ran.\n';
  }
  if (worst === 'INCOMPLETE') {
    const parts = [
      ...(m === 0 ? [] : [`${m} input${m === 1 ? ' was' : 's were'} not evaluated in full`]),
      ...(u === 0 ? [] : [notRead]),
    ];
    const review =
      m === 0
        ? ''
        : m === 1
          ? ' Review it for the patterns named above, or block it, before it reaches an LLM.'
          : ' Review them for the patterns named above, or block them, before they reach an LLM.';
    const rescan = u === 0 ? '' : ` Scan the ${UNREADABLE_VERDICT} input${u === 1 ? '' : 's'} once ${u === 1 ? 'it' : 'they'} can be read.`;
    return `Verdict: INCOMPLETE  ·  no findings, but ${parts.join(' and ')}.${review}${rescan}\n`;
  }
  const notEvaluatedPart = m === 0 ? '' : `; ${m} input${m === 1 ? '' : 's'} not evaluated in full`;
  const notReadPart = u === 0 ? '' : `; ${notRead}`;
  return (
    `Verdict: ${worst}  ·  ${totalFindings} finding${totalFindings === 1 ? '' : 's'} across ${inputs} input${inputs === 1 ? '' : 's'}${notEvaluatedPart}${notReadPart}. ` +
    'Block, redact, or log before this content reaches an LLM.\n'
  );
}

export function renderJson(sources: Source[], results: ComplyResult[]): void {
  const payload = sources.map((src, i) => src.unreadable ? {
    source: src.label,
    // A named file that could not be read or decoded was not scanned: its
    // `verdict` is UNREADABLE, the word the report prints for it, `bytes` is
    // null as no input was read, and `error` says why.
    bytes: null,
    verdict: UNREADABLE_VERDICT,
    error: src.unreadable.reason,
    guardActive: false,
    layers: [],
    findings: [],
  } : ({
    source: src.label,
    // An input of 0 bytes was not classified: its `verdict` is EMPTY, the
    // word the report prints for it, and its `layers` is [].
    bytes: src.bytes,
    verdict: src.bytes === 0 ? EMPTY_VERDICT : inputVerdict(results[i]),
    guardActive: guardActive(results[i]),
    layers: results[i].layers,
    // The patterns the regex engine could not run on this input, when any.
    ...(results[i].unevaluatedPatterns !== undefined
      ? { notEvaluated: results[i].unevaluatedPatterns }
      : {}),
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
  const verdicts = results.filter((_, i) => sources[i].bytes > 0).map(inputVerdict);
  const unreadable = sources.filter((s) => s.unreadable);
  const overall = overallVerdict(verdicts, unreadable.length);

  if (args.json) renderJson(sources, results);
  else if (args.quiet) process.stdout.write(`${overall}\n`);
  else renderHuman(sources, results);

  const notes = args.json && args.quiet ? [QUIET_WITH_JSON] : [];
  // The report and --json name each input that could not be read; --quiet
  // prints only the verdict, so stderr says which ones and why.
  if (args.quiet && !args.json) {
    for (const s of unreadable) if (s.unreadable) notes.push(s.unreadable.message);
  }
  if (unread === 'stream') notes.push(STDIN_NOT_READ);
  if (notes.length > 0) {
    // Most of a large report can still be queued for a piped stdout. Writing
    // the notes once it is flushed keeps them after the report where both
    // streams go to one pipe.
    await flushed(process.stdout);
    process.stderr.write(notes.map((note) => `aicomply: ${note}\n`).join(''));
  }

  // 0 only when every input was read and every one that was scanned is
  // CLEAN, so a CI gate passes on 0 alone: 1 when one is flagged, 2 when the
  // scan reached no verdict.
  return exitCode(overall);
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
