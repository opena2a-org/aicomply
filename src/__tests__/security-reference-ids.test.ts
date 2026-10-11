/**
 * SECURITY.md lists contract IDs under "Reference IDs" and says they are
 * referenced in source and tests, so an advisory that names one leads a
 * reader to the code that implements it and the test that pins it. Each ID
 * in that table must appear in a source file under src/ or scripts/ and in
 * the title of a describe/it/test block that runs, in a test under src/. A
 * comment in a test file does not count: it names the ID without saying which
 * test pins it. Nor does a skipped or todo block, which pins nothing. This
 * file reads the IDs from the table and is left out of the test
 * search, so naming an ID here cannot satisfy the check.
 */

import { readdirSync, readFileSync } from 'fs';
import { join, relative, sep } from 'path';
import ts from 'typescript';

const ROOT = join(__dirname, '..', '..');
const SECURITY = join(ROOT, 'SECURITY.md');

/** The IDs in the first column of the table under `## Reference IDs`. */
function referenceIds(markdown: string): string[] {
  const start = markdown.search(/^## Reference IDs\s*$/m);
  if (start < 0) return [];
  const rest = markdown.slice(start).split('\n').slice(1);
  const end = rest.findIndex((line) => /^## /.test(line));
  const section = end < 0 ? rest : rest.slice(0, end);
  return section
    .filter((line) => line.trim().startsWith('|'))
    .map((line) => line.split('|')[1].trim())
    .filter((cell) => cell !== '' && cell !== 'ID' && !/^:?-+:?$/.test(cell));
}

/** Every file under `dir`, skipping node_modules. */
function walk(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    if (entry.name === 'node_modules') return [];
    const path = join(dir, entry.name);
    return entry.isDirectory() ? walk(path) : [path];
  });
}

const isTest = (path: string) => path.split(sep).includes('__tests__');

/** True when `text` names `id` as a whole token, as `grep -w` would. */
function names(text: string, id: string): boolean {
  const escaped = id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(?<![A-Za-z0-9_-])${escaped}(?![A-Za-z0-9_-])`).test(text);
}

/** Blocks that run, `fit` and `fdescribe` (focused) included. */
const BLOCKS = new Set(['describe', 'it', 'test', 'fdescribe', 'fit']);
/** Blocks that are skipped. */
const SKIPPED_BLOCKS = new Set(['xdescribe', 'xit', 'xtest']);
/** Modifiers that keep a block from running: `it.skip`, `it.todo`. */
const SKIP_MODIFIERS = new Set(['skip', 'todo']);

type BlockKind = 'runs' | 'skipped' | '';

/**
 * 'runs' for `it`, `fit`, `it.only`, `it.each(table)`, `` it.each`table` ``
 * and the like; 'skipped' for `xit`, `it.skip`, `it.todo`, `describe.skip`
 * and the like; '' for other callees, such as a method named `test` on
 * another object (`re.test('...')`).
 */
function blockKind(callee: ts.Expression): BlockKind {
  if (ts.isIdentifier(callee)) {
    if (BLOCKS.has(callee.text)) return 'runs';
    return SKIPPED_BLOCKS.has(callee.text) ? 'skipped' : '';
  }
  if (ts.isPropertyAccessExpression(callee)) {
    const kind = blockKind(callee.expression);
    return kind === 'runs' && SKIP_MODIFIERS.has(callee.name.text) ? 'skipped' : kind;
  }
  if (ts.isCallExpression(callee)) return blockKind(callee.expression);
  if (ts.isTaggedTemplateExpression(callee)) return blockKind(callee.tag);
  return '';
}

/**
 * The titles of the describe/it/test blocks that run in a test file, read
 * from the parsed file, so a comment or a string elsewhere in the file is not
 * one. A skipped or todo block, and every block inside a skipped describe,
 * pins nothing, so its title is left out.
 */
function blockTitles(text: string): string[] {
  const titles: string[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const kind = blockKind(node.expression);
      if (kind === 'skipped') return;
      const title = node.arguments[0];
      if (kind === 'runs' && title !== undefined && (ts.isStringLiteralLike(title) || ts.isTemplateExpression(title))) {
        // A template with substitutions has no fixed text; its source is searched.
        titles.push(ts.isStringLiteralLike(title) ? title.text : title.getText());
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(ts.createSourceFile('titles.ts', text, ts.ScriptTarget.Latest, true));
  return titles;
}

describe('SECURITY.md reference IDs', () => {
  const ids = referenceIds(readFileSync(SECURITY, 'utf8'));
  const files = [...walk(join(ROOT, 'src')), ...walk(join(ROOT, 'scripts'))].map((path) => ({
    path,
    text: readFileSync(path, 'utf8'),
  }));
  const sources = files.filter((f) => !isTest(f.path));
  const tests = files
    .filter((f) => isTest(f.path) && f.path !== __filename)
    .map((f) => ({ path: f.path, titles: blockTitles(f.text) }));

  it('lists at least one ID', () => {
    expect(ids.length).toBeGreaterThan(0);
  });

  it('names each ID in a source file and in a test title', () => {
    const missing = ids.flatMap((id) => {
      const gaps: string[] = [];
      if (!sources.some((f) => names(f.text, id))) gaps.push('no source file under src/ or scripts/');
      if (!tests.some((f) => f.titles.some((title) => names(title, id)))) {
        gaps.push('no describe/it/test title in a test under src/');
      }
      return gaps.length ? [`${id}: ${gaps.join(', ')} names it`] : [];
    });
    expect(missing).toEqual([]);
  });

  it('reads an ID from a block title, not from a comment or another string', () => {
    const file = [
      '/**',
      ' *   - D7: named in the header comment only',
      ' */',
      "describe('verifyClassification (CR-001)', () => {",
      "  // it('D9 in a test that is commented out', () => {});",
      "  it('accepts a valid classification', () => {",
      "    expect(label('AC-005')).toBe('AC-005');",
      '  });',
      "  it.each([1, 2])('rejects size %d (D17)', () => {});",
      '  test(`reports AC-002 as ${status}`, () => {});',
      '});',
    ].join('\n');
    const titles = blockTitles(file);
    const named = (id: string) => titles.some((title) => names(title, id));

    expect(titles).toEqual([
      'verifyClassification (CR-001)',
      'accepts a valid classification',
      'rejects size %d (D17)',
      '`reports AC-002 as ${status}`',
    ]);
    expect(['CR-001', 'D17', 'AC-002'].filter(named)).toEqual(['CR-001', 'D17', 'AC-002']);
    expect(['D7', 'D9', 'AC-005'].filter(named)).toEqual([]);
  });

  it('leaves out the title of a skipped or todo block and of every block in a skipped describe', () => {
    const file = [
      "it.skip('parse-to-deny on a bad signature (CR-001)', () => {});",
      "it.todo('pins the signing library (D7)');",
      "test.skip.each([1])('verify budget %d (D17)', () => {});",
      "xit('encrypts the vault (D9)', () => {});",
      "xtest('reports a miss (AC-002)', () => {});",
      "describe.skip('Registry hot path', () => {",
      "  it('makes no request (AC-005)', () => {});",
      '});',
      "xdescribe('another suite', () => {",
      "  describe('nested', () => { it('XY-1 under a skipped suite', () => {}); });",
      '});',
      "it('runs (AB-001)', () => {});",
    ].join('\n');

    expect(blockTitles(file)).toEqual(['runs (AB-001)']);
  });

  it('reads the title under a tagged-template it.each and under fit and fdescribe', () => {
    const file = [
      'it.each`',
      '  status',
      "  ${'miss'}",
      "`('reports $status (AC-002)', () => {});",
      "fit('focused (CR-001)', () => {});",
      "fdescribe('focused suite (D7)', () => {",
      "  it.only('only this one (D9)', () => {});",
      '});',
    ].join('\n');

    expect(blockTitles(file)).toEqual([
      'reports $status (AC-002)',
      'focused (CR-001)',
      'focused suite (D7)',
      'only this one (D9)',
    ]);
  });

  it('does not read a method named test, it or describe on another object as a block', () => {
    const file = [
      "it('matches the ID pattern', () => {",
      "  expect(/AC-\\d+/.test('AC-001 in a regex call')).toBe(true);",
      "  re.test('CR-001 passed to a method');",
      "  suite.it('D7 on another object', () => {});",
      "  page.describe('D9 on another object', () => {});",
      '});',
    ].join('\n');

    expect(blockTitles(file)).toEqual(['matches the ID pattern']);
  });

  it('reads the IDs from the table', () => {
    const md = [
      '## Reference IDs',
      '',
      '| ID | Contract |',
      '|----|----------|',
      '| AB-001 | first |',
      '| Z9 | second |',
      '',
      '## Next',
      '| XY-1 | outside |',
    ].join('\n');
    expect(referenceIds(md)).toEqual(['AB-001', 'Z9']);
  });

  it('matches an ID only as a whole token', () => {
    expect(names('see D7 here', 'D7')).toBe(true);
    expect(names('(D7: noble)', 'D7')).toBe(true);
    expect(names('D17 budget', 'D7')).toBe(false);
    expect(names('AC-0021', 'AC-002')).toBe(false);
    expect(names('XAC-002', 'AC-002')).toBe(false);
  });

  it('leaves this file out of the test search', () => {
    expect(tests.map((f) => relative(ROOT, f.path))).not.toContain(relative(ROOT, __filename));
    expect(tests.length).toBeGreaterThan(0);
  });
});
