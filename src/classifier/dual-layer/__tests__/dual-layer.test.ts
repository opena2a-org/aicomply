import { classifyDualLayer } from '..';

describe('classifyDualLayer', () => {
  it('returns CLEAN for safe content', async () => {
    const result = await classifyDualLayer('This is perfectly safe content.');
    expect(result.verdict).toBe('CLEAN');
    expect(result.violations).toHaveLength(0);
    expect(result.classifierResults.regex.verdict).toBe('CLEAN');
    // Guard is unavailable in V1
    expect(result.classifierResults.guard).toBeUndefined();
  });

  it('returns VIOLATION when regex detects PII', async () => {
    const result = await classifyDualLayer('My SSN is 123-45-6789');
    expect(result.verdict).toBe('VIOLATION');
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0].type).toBe('SSN');
    expect(result.violations[0].classifier).toBe('regex');
  });

  it('returns VIOLATION when regex detects credentials', async () => {
    const result = await classifyDualLayer('AKIAIOSFODNN7EXAMPLE');
    expect(result.verdict).toBe('VIOLATION');
    expect(result.violations.some(v => v.type === 'CREDENTIAL')).toBe(true);
  });

  it('returns VIOLATION when regex detects CUI', async () => {
    const result = await classifyDualLayer('CUI//SP-PRVCY marked document');
    expect(result.verdict).toBe('VIOLATION');
    expect(result.violations.some(v => v.type === 'CUI')).toBe(true);
  });

  it('aggregates violations from multiple patterns', async () => {
    const content = 'SSN: 123-45-6789 and key AKIAIOSFODNN7EXAMPLE';
    const result = await classifyDualLayer(content);
    expect(result.verdict).toBe('VIOLATION');
    expect(result.violations.length).toBeGreaterThanOrEqual(2);
  });

  it('includes regex result in classifierResults', async () => {
    const result = await classifyDualLayer('safe content');
    expect(result.classifierResults.regex).toBeDefined();
    expect(result.classifierResults.regex.classifier).toBe('regex');
  });
});
