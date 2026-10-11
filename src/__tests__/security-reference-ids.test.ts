/**
 * SECURITY.md lists contract IDs under "Reference IDs" and says they are
 * referenced in source and tests, so an advisory that names one leads a
 * reader to the code that implements it and the test that pins it. Each ID
 * in that table must appear in a source file under src/ or scripts/ and in
 * the title of a describe/it/test block in a test under src/. A comment in a
 * test file does not count: it names the ID without saying which test pins
 * it. This file reads the IDs from the table and is left out of the test
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

const BLOCKS = new Set(['describe', 'it', 'test']);

/** `it` for `it`, `it.only`, `it.each(table)` and the like; '' for other callees. */
function blockName(callee: ts.Expression): string {
  if (ts.isIdentifier(callee)) return BLOCKS.has(callee.text) ? callee.text : '';
  if (ts.isPropertyAccessExpression(callee) || ts.isCallExpression(callee)) {
    return blockName(callee.expression);
  }
  return '';
}

/**
 * The titles of the describe/it/test blocks in a test file, read from the
 * parsed file, so a comment or a string elsewhere in the file is not one.
 */
function blockTitles(text: string): string[] {
  const titles: string[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && blockName(node.expression) !== '') {
      const title = node.arguments[0];
      if (title !== undefined && (ts.isStringLiteralLike(title) || ts.isTemplateExpression(title))) {
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
      '  test.skip(`reports AC-002 as ${status}`, () => {});',
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
