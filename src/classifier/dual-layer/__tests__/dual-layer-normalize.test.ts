/**
 * End-to-end: prove the normalization layer actually closes the v1.0
 * README gaps when wired through `comply()`. Each test mutates a known
 * detection pattern (SSN, AWS key, GitHub token) with one of the
 * in-scope adversarial transforms and asserts the violation surfaces
 * with correct view tagging and original-content anchoring.
 *
 * Maps to CHIEF-CSR decision 2026-05-28 (threat-model scope) and the
 * README §"What V1 does NOT do" bullets being closed for v1.0.
 */

import { comply } from '../../../index';

describe('comply() under adversarial mutations (v1.0 normalization)', () => {
  it('detects an SSN built from fullwidth digits (NFKC defeat)', async () => {
    const r = await comply({ content: 'SSN:１２３-４５-６７８９' });
    expect(r.verdict).toBe('VIOLATION');
    const ssn = r.violations.find((v) => v.type === 'SSN');
    expect(ssn).toBeDefined();
    expect(ssn?.view).toBe('normalized');
  });

  it('detects an SSN with zero-width spaces injected between digits', async () => {
    const r = await comply({ content: 'SSN:1​2​3-4​5-6​7​8​9' });
    expect(r.verdict).toBe('VIOLATION');
    expect(r.violations.some((v) => v.type === 'SSN')).toBe(true);
  });

  it('detects an SSN with ASCII spaces between digits via compact-form view', async () => {
    const r = await comply({ content: 'My SSN is 1 2 3 - 4 5 - 6 7 8 9 please' });
    expect(r.verdict).toBe('VIOLATION');
    const ssn = r.violations.find((v) => v.type === 'SSN');
    expect(ssn).toBeDefined();
    expect(ssn?.view).toBe('compact');
  });

  it('detects a Base64-encoded GitHub token via decoded-base64 view', async () => {
    const inner = 'token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const b64 = Buffer.from(inner).toString('base64');
    const r = await comply({ content: `payload: ${b64}` });
    expect(r.verdict).toBe('VIOLATION');
    const finding = r.violations.find((v) => v.view === 'decoded-base64');
    expect(finding).toBeDefined();
    // Original anchor must point at the encoded blob, not at the decoded position.
    expect(finding?.originalStart).toBe('payload: '.length);
    expect(finding?.originalEnd).toBe('payload: '.length + b64.length);
  });

  it('preserves originalContent + sets normalizedContent + records normalization steps', async () => {
    const r = await comply({ content: '１２３-４５-６７８９' });
    expect(r.originalContent).toBe('１２３-４５-６７８９');
    expect(r.normalizedContent).toBe('123-45-6789');
    expect(r.normalizations?.find((s) => s.transform === 'nfkc')).toBeDefined();
  });

  it('no-op on clean ASCII: normalizedContent equals input, no transforms recorded', async () => {
    const r = await comply({ content: 'SSN:123-45-6789' });
    expect(r.verdict).toBe('VIOLATION');
    expect(r.normalizedContent).toBe('SSN:123-45-6789');
    expect(r.normalizations).toEqual([]);
    // The clean-stream match should be tagged 'normalized', not 'compact'.
    expect(r.violations.find((v) => v.type === 'SSN')?.view).toBe('normalized');
  });

  it('does not double-report the same SSN found in both normalized and compact views', async () => {
    // "123-45-6789" with no whitespace inside matches in the normalized
    // stream; the compact-form scan would find the same span. Dedupe
    // must suppress the second hit.
    const r = await comply({ content: 'SSN is 123-45-6789 today' });
    const ssnHits = r.violations.filter((v) => v.type === 'SSN');
    expect(ssnHits).toHaveLength(1);
  });

  it('handles empty content without normalization metadata (early return)', async () => {
    const r = await comply({ content: '' });
    expect(r.verdict).toBe('CLEAN');
    // Early-return path in comply() does not run normalize(); these
    // fields are undefined, which is acceptable for the empty-input case.
    expect(r.originalContent).toBeUndefined();
  });
});
