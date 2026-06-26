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

import { readFileSync } from 'fs';
import { comply } from './index';
import { DEFAULT_NANOMIND_DAEMON_URL } from './classifier/guard-client/nanomind-adapter';
import type { ComplyResult, Violation } from './types';

// Keep in sync with package.json version on every release bump.
const VERSION = '2.2.2';

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
  for (const arg of argv) {
    if (arg === '--json') parsed.json = true;
    else if (arg === '--quiet' || arg === '-q') parsed.quiet = true;
    else if (arg === '--help' || arg === '-h') parsed.help = true;
    else if (arg === '--version' || arg === '-V') parsed.version = true;
    else if (arg.startsWith('-') && arg !== '-') {
      // Unknown flag -- surface it rather than silently ignoring.
      throw new UsageError(`unknown option '${arg}'`);
    } else if (parsed.command === undefined) parsed.command = arg;
    else parsed.files.push(arg);
  }
  return parsed;
}

const HELP = `aicomply -- inline content classifier for AI agent I/O

Detects PII, credentials, and regulated data before your agent ships content to
a hosted LLM. Runs a deterministic regex layer always, plus an optional semantic
Guard layer when a local nanomind-daemon is reachable.

USAGE
  aicomply scan [file...]      Scan files for sensitive content
  aicomply scan -              Read content from stdin
  echo "text" | aicomply scan  Pipe content from stdin

OPTIONS
  --json        Machine-readable JSON output (verdict + findings)
  --quiet, -q   Print only the verdict line
  --version,-V  Print version
  --help, -h    This help

EXIT CODES
  0  CLEAN          no findings, safe to forward
  1  VIOLATION/DENY findings present (usable as a CI gate)
  2  usage error

EXAMPLES
  aicomply scan ./support-ticket.txt
  cat transcript.log | aicomply scan --json
  aicomply scan src/*.txt -q

The library API is the production surface: https://github.com/opena2a-org/aicomply
`;

const SCAN_HELP = `aicomply scan -- scan files or piped stdin for sensitive content

Runs the deterministic regex layer (PII, credentials, regulated data) over each
input, plus the optional semantic Guard layer when a local nanomind-daemon is
reachable. Prints a verdict per input and an overall verdict.

USAGE
  aicomply scan [file...]      Scan one or more files
  aicomply scan -              Read content from stdin
  echo "text" | aicomply scan  Pipe content from stdin

OPTIONS
  --json        Machine-readable JSON output (verdict + findings, values masked)
  --quiet, -q   Print only the verdict line (CLEAN / VIOLATION / DENY)
  --help, -h    This help

EXIT CODES
  0  CLEAN          no findings, safe to forward
  1  VIOLATION/DENY findings present (usable as a CI gate)
  2  usage error

EXAMPLES
  aicomply scan ./support-ticket.txt
  cat transcript.log | aicomply scan --json
  aicomply scan src/*.txt -q
`;

/** Mask a detected value so the CLI never prints a full secret to a terminal or log. */
function maskValue(value: string): string {
  const v = value ?? '';
  if (v.length <= 4) return '•'.repeat(v.length || 1);
  const head = v.slice(0, 4);
  const tail = v.length > 8 ? v.slice(-2) : '';
  return `${head}${'•'.repeat(Math.max(3, v.length - head.length - tail.length))}${tail}`;
}

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => (data += chunk));
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', () => resolve(data));
  });
}

interface Source {
  label: string;
  content: string;
}

async function collectSources(files: string[]): Promise<Source[]> {
  const stdinRequested = files.length === 0 || files.includes('-');
  const realFiles = files.filter((f) => f !== '-');
  const sources: Source[] = [];

  for (const file of realFiles) {
    try {
      sources.push({ label: file, content: readFileSync(file, 'utf8') });
    } catch {
      throw new UsageError(`cannot read '${file}' (check the path). Try 'aicomply --help'.`);
    }
  }

  if (stdinRequested) {
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

function renderHuman(sources: Source[], results: ComplyResult[]): void {
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
      out.write('   no PII, credentials, or regulated data detected\n\n');
      continue;
    }
    out.write(`   ${res.violations.length} finding${res.violations.length === 1 ? '' : 's'}\n`);
    for (const v of res.violations as Violation[]) {
      const masked = maskValue(v.value);
      const layer = v.classifier;
      const view = v.view && v.view !== 'normalized' ? `  view ${v.view}` : '';
      out.write(
        `    ${v.type.padEnd(12)} ${masked.padEnd(18)} confidence ${v.confidence.toFixed(2)}  layer ${layer}${view}\n`,
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
  }

  if (worst === 'CLEAN') {
    out.write('Verdict: CLEAN  ·  safe to forward.\n');
  } else {
    out.write(
      `Verdict: ${worst}  ·  ${totalFindings} finding${totalFindings === 1 ? '' : 's'} across ${sources.length} input${sources.length === 1 ? '' : 's'}. ` +
        'Block, redact, or log before this content reaches an LLM.\n',
    );
  }
}

function renderJson(sources: Source[], results: ComplyResult[]): void {
  const payload = sources.map((src, i) => ({
    source: src.label,
    verdict: results[i].verdict,
    guardActive: guardActive(results[i]),
    findings: results[i].violations.map((v) => ({
      type: v.type,
      maskedValue: maskValue(v.value),
      confidence: v.confidence,
      classifier: v.classifier,
      view: v.view ?? 'normalized',
    })),
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
