// The three expressions of the pack gate (scripts/pack-gate.mjs), the guidance
// each refusal prints, and the exact-line exemptions. Importing this module
// defines them and does nothing else, so a test reads the same definitions the
// gate applies.
//
// This file is byte-identical in every repository that publishes with the
// pack gate.

// The first expression's inline case-modifier group compiles on Node 23 or
// newer only. An older runtime throws here, with that reason, instead of
// failing on the expression below with a bare syntax error. The pack gate
// imports this module inside its error handling, so there the reason becomes
// its could-not-run refusal (exit 2).
if (Number(process.versions.node.split('.')[0]) < 23) {
  throw new Error(`Node ${process.versions.node} cannot compile the first expression, which needs Node 23 or newer`);
}

// The first two expressions are the ones the scanner repository's tree gate
// walks its tracked files with. That gate imports them from here, so the tree
// gate and the pack gate read one definition. They are pasted verbatim with
// String.raw, so no slash needs escaping.
export const PATTERN = new RegExp(String.raw`\[CHIEF-|\bCHIEF\b|\b(CPO|CCO|CISO|CSR|CDS|CDE|DPO)\b|\bCA \(\d\)|\b(CPO|CCO|CISO|CSR|CDS|CDE|DPO|CA)-\d{3}\b|COUNCIL_LEDGER|\bbriefs/|hackmyagent/CLAUDE\.md|\btodo/|\bqgf/|\.claude-sessions|(?i:chief (data scientist|security researcher|architect|product officer|information security officer|communications officer)|chief council)`);
export const VENDOR = new RegExp(String.raw`(claude|anthropic)[-\s](review|generat|label|train|curat|assist|audit)\w*|(review|generat|label|train|curat|built|powered|assisted)\w*\s+by\s+(claude|anthropic)|Claude Code Review`, 'i');

// The third expression. A Markdown table row carrying a percentage under a
// header naming an accuracy measure, that is, in a column whose header cell
// names one, is refused unless the same file carries the literal word
// `withdrawn` within its first 25 lines.
export const FIGURES = Object.freeze({
  header: /\bF1\b|\bprecision\b|\bFPR\b|\bflag[- ]rate\b/i,
  percentage: /\d(?:[.,]\d+)?\s?%/,
  notice: 'withdrawn',
  noticeWithin: 25,
});

export const PATTERN_GUIDANCE =
  "name the control, not the role; for the reader persona write 'security manager'; for TLS write 'certificate signing request' in full";
export const VENDOR_GUIDANCE =
  'the vendor is named as the actor; state what was done without naming who did it';
export const FIGURES_GUIDANCE =
  'an accuracy figure ships only beside its withdrawal notice; state the withdrawal within the first 25 lines of the file, or remove the figure';

// Exact file-and-line exemptions. An entry exempts a line only when the
// package name, the packed path and the line content after trimming are all
// equal: never a pattern, never a path on its own. An entry whose file is
// packed and carries no such line refuses the pack, so a stale entry fails
// instead of lingering.
//
// hackmyagent: the ten capability-abuse attack payloads are named by the
// scanner's own check ids, numbered 001 to 010, whose middle part the first
// expression reads as a decision identifier.
const CAPABILITY_ABUSE_IDS = Array.from({ length: 10 }, (_, i) => `ATK-CA-${String(i + 1).padStart(3, '0')}`);
export const EXEMPT = Object.freeze(
  CAPABILITY_ABUSE_IDS.map((id) =>
    Object.freeze({ pkg: 'hackmyagent', file: 'dist/attack/payloads/capability-abuse.js', line: `id: '${id}',` }),
  ),
);

// A line that can belong to a Markdown table: it carries a pipe and some text.
const isTableLine = (line) => line.includes('|') && line.trim() !== '';

// A table's delimiter row: pipes, colons, hyphens and spaces only, with at
// least one pipe and one hyphen.
const isDelimiterRow = (line) => isTableLine(line) && line.includes('-') && /^[\s|:-]+$/.test(line);

// The cells of a table line, trimmed, without the optional outer pipes. A pipe
// escaped with a backslash stays inside its cell.
function cells(line) {
  let text = line.trim();
  if (text.startsWith('|')) text = text.slice(1);
  if (text.endsWith('|') && !text.endsWith('\\|')) text = text.slice(0, -1);
  return text.split(/(?<!\\)\|/).map((cell) => cell.trim());
}

// The 1-based numbers of the lines of one file that the third expression
// refuses: each body row with a percentage in a column whose header cell names
// an accuracy measure, unless the notice is within the file's first 25 lines.
export function figureLines(lines) {
  if (lines.slice(0, FIGURES.noticeWithin).some((line) => line.includes(FIGURES.notice))) return [];
  const refused = [];
  for (let i = 0; i + 1 < lines.length; i += 1) {
    if (!isTableLine(lines[i]) || !isDelimiterRow(lines[i + 1])) continue;
    const named = cells(lines[i]).map((cell) => FIGURES.header.test(cell));
    let row = i + 2;
    for (; row < lines.length && isTableLine(lines[row]); row += 1) {
      if (cells(lines[row]).some((cell, column) => named[column] === true && FIGURES.percentage.test(cell))) {
        refused.push(row + 1);
      }
    }
    i = row - 1;
  }
  return refused;
}
