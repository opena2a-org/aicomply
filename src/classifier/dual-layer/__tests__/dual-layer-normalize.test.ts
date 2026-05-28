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

  it('detects a URL-encoded credential and tags it `decoded-url` (not `compact`)', async () => {
    // Regression: code-review surfaced an inverted heuristic that
    // mistagged URL-decoded findings as `compact` because decoded
    // payloads typically don't contain a literal `%`. Fixed by carrying
    // the view tag on DecodedExtraction.source directly.
    const inner = 'secret = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const enc = encodeURIComponent(inner);
    const r = await comply({ content: `query: ${enc}` });
    expect(r.verdict).toBe('VIOLATION');
    const finding = r.violations.find((v) => v.view === 'decoded-url');
    expect(finding).toBeDefined();
    expect(r.violations.find((v) => v.view === 'compact' && v.type === 'CREDENTIAL')).toBeUndefined();
  });

  it('does NOT double-report mixed-injection: one SSN whitespace-injected + one canonical', async () => {
    // Regression: code-review found the compact-view dedup was broken
    // because compact findings inherited a whole-extraction anchor that
    // never matched the per-finding offsets from the normalized scan.
    // Fixed by carrying a per-character offsetMap on the compact view.
    const r = await comply({
      content: 'first 1 2 3-45-6789 then 555-12-3456 confidential',
    });
    expect(r.verdict).toBe('VIOLATION');
    const ssnHits = r.violations.filter((v) => v.type === 'SSN');
    // Two distinct SSNs, two violations — neither double-reported.
    expect(ssnHits).toHaveLength(2);
    // The whitespace-injected one surfaces via the compact view; the
    // un-injected one via the normalized view.
    const views = new Set(ssnHits.map((v) => v.view));
    expect(views).toContain('normalized');
    expect(views).toContain('compact');
  });

  it('detects credentials wrapped in TWO layers of Base64 (depth-2 recursion)', async () => {
    // Regression: adversarial review found the depth-2 recursion path was
    // unit-tested but not exercised end-to-end through comply(). Stack
    // two base64 wrappers around a credential payload and assert it
    // surfaces with view='decoded-base64'.
    const inner = 'token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const layer1 = Buffer.from(inner).toString('base64');
    const layer2 = Buffer.from(layer1).toString('base64');
    const r = await comply({ content: `wrapped: ${layer2}` });
    expect(r.verdict).toBe('VIOLATION');
    expect(r.violations.some((v) => v.view === 'decoded-base64')).toBe(true);
  });

  it('detects PII with COMBINED zero-width + whitespace injection (mixed adversarial)', async () => {
    // Regression: tests covered each mutation in isolation but not the
    // realistic blend of "attacker injects whatever Unicode chars they
    // can while also breaking up digits with ASCII whitespace".
    // U+200B between every char + spaces sprinkled in the digit run.
    const r = await comply({
      content: 'SSN:1​ 2​ 3​-​4 5​-​6 7 8 9',
    });
    expect(r.verdict).toBe('VIOLATION');
    expect(r.violations.some((v) => v.type === 'SSN')).toBe(true);
  });

  it('surfaces multiple distinct credentials inside ONE Base64 blob (no dedup collapse)', async () => {
    // Regression: adversarial review found that decoded-view findings
    // were dedup'd on a whole-blob anchor, so two credentials inside
    // one Base64 payload collapsed to a single violation. Fix carries
    // the in-view start/end in the dedup key for non-offsetMap views.
    const t1 = 'ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const t2 = 'ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
    const payload = `token1=${t1};token2=${t2}`;
    const b64 = Buffer.from(payload).toString('base64');
    const r = await comply({ content: `data: ${b64}` });
    const creds = r.violations.filter((v) => v.view === 'decoded-base64' && v.type === 'CREDENTIAL');
    expect(creds.length).toBeGreaterThanOrEqual(2);
  });

  it('redacts originalContent on supply-chain DENY too (not just parse-to-deny)', async () => {
    // Regression: the original parse-to-deny fix gated redaction on
    // signatureValid===false, missing the supply-chain DENY and
    // policy-pack DENY paths. Fix gates on verdict==='DENY'.
    const { warmRegistryCache } = await import('../../../index');
    const fakeCache = await import('../../../registry/index').then((m) => {
      const c = new m.RegistryIntelligenceCache({ baseUrl: 'http://localhost' });
      // Inject a supply-chain alert without hitting the network.
      (c as unknown as { supplyChainIndex: Map<string, unknown[]> }).supplyChainIndex = new Map([
        ['my-agent', [{ id: 'fake-alert-1', name: 'my-agent' }]],
      ]);
      (c as unknown as { lastSupplyChainFetch: number }).lastSupplyChainFetch = Date.now();
      (c as unknown as { fleetIndex: Map<string, unknown> }).fleetIndex = new Map();
      (c as unknown as { lastFleetFetch: number }).lastFleetFetch = Date.now();
      return c;
    });
    expect(warmRegistryCache).toBeDefined();
    const r = await comply({
      content: 'attacker [2J wipescreen content',
      sourcePackage: 'my-agent',
      registryCache: fakeCache,
    });
    expect(r.verdict).toBe('DENY');
    expect(r.registrySignals?.supplyChainBlock).toBe(true);
    expect(r.originalContent).toBeUndefined();
    expect(r.normalizedContent).toBeUndefined();
  });

  it('omits originalContent and normalizedContent on parse-to-deny (untrusted bytes)', async () => {
    // Regression: code-review flagged that the invalid-Guard-signature
    // path echoed attacker-controlled input back via originalContent,
    // allowing log-injection / ANSI-escape attacks in downstream
    // operator dashboards. Fix omits raw byte fields on parse-to-deny
    // but keeps the structured `normalizations` array for auditors.
    const { classifyDualLayer } = await import('../index');
    const helpers = await import('../../../arp/__tests__/test-helpers');
    const signer = helpers.generateTestKeyPair();
    const verifier = helpers.generateTestKeyPair();
    const content = 'attacker content with X escape';
    const guardResult = helpers.signGuardResult(signer, 'documentation', content);
    const r = await classifyDualLayer(content, {
      guardResult,
      guardVerifyOptions: helpers.makeVerifyOptions(verifier),
    });
    expect(r.signatureValid).toBe(false);
    expect(r.verdict).toBe('DENY');
    expect(r.originalContent).toBeUndefined();
    expect(r.normalizedContent).toBeUndefined();
    expect(Array.isArray(r.normalizations)).toBe(true);
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
    // Empty input still populates the audit fields per the types.ts
    // contract — originalContent / normalizedContent / normalizations
    // are always defined on v1.0+ results so consumers can rely on
    // them without `??`-guarding every access.
    expect(r.originalContent).toBe('');
    expect(r.normalizedContent).toBe('');
    expect(r.normalizations).toEqual([]);
  });
});
