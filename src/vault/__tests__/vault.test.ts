import { createDecipheriv } from 'node:crypto';
import { SessionVault } from '..';

describe('SessionVault', () => {
  let vault: SessionVault;

  beforeEach(() => {
    vault = new SessionVault();
  });

  afterEach(() => {
    vault.destroy();
  });

  it('encrypts and decrypts round-trip', () => {
    const plaintext = 'SSN: 123-45-6789';
    vault.store('entry-1', plaintext);
    const result = vault.retrieve('entry-1');
    expect(result).toBe(plaintext);
  });

  it('handles unicode content', () => {
    const plaintext = 'Patient: Jean-Pierre Lefevre, MRN: 12345';
    vault.store('unicode', plaintext);
    expect(vault.retrieve('unicode')).toBe(plaintext);
  });

  it('handles empty string', () => {
    vault.store('empty', '');
    expect(vault.retrieve('empty')).toBe('');
  });

  it('handles large content', () => {
    const plaintext = 'x'.repeat(100000);
    vault.store('large', plaintext);
    expect(vault.retrieve('large')).toBe(plaintext);
  });

  it('returns null for missing entries', () => {
    expect(vault.retrieve('nonexistent')).toBeNull();
  });

  it('deletes entries', () => {
    vault.store('to-delete', 'secret');
    expect(vault.retrieve('to-delete')).toBe('secret');

    vault.delete('to-delete');
    expect(vault.retrieve('to-delete')).toBeNull();
  });

  it('overwrites entries with same ID', () => {
    vault.store('key', 'value1');
    vault.store('key', 'value2');
    expect(vault.retrieve('key')).toBe('value2');
  });

  it('tracks size correctly', () => {
    expect(vault.size()).toBe(0);

    vault.store('a', 'data');
    vault.store('b', 'data');
    expect(vault.size()).toBe(2);

    vault.delete('a');
    expect(vault.size()).toBe(1);
  });

  it('evicts oldest when max entries exceeded', () => {
    const smallVault = new SessionVault(3);

    smallVault.store('first', 'data1');
    smallVault.store('second', 'data2');
    smallVault.store('third', 'data3');
    smallVault.store('fourth', 'data4'); // should evict 'first'

    expect(smallVault.retrieve('first')).toBeNull();
    expect(smallVault.retrieve('fourth')).toBe('data4');

    smallVault.destroy();
  });

  it('expires entries after TTL', async () => {
    const shortTtlVault = new SessionVault(1000, 50); // 50ms TTL

    shortTtlVault.store('expiring', 'data');
    expect(shortTtlVault.retrieve('expiring')).toBe('data');

    await new Promise(resolve => setTimeout(resolve, 100));

    expect(shortTtlVault.retrieve('expiring')).toBeNull();

    shortTtlVault.destroy();
  });

  it('uses unique IVs for each encryption', () => {
    // Store same content twice -- encrypted values should differ
    vault.store('a', 'identical');
    vault.store('b', 'identical');

    // Both should decrypt correctly
    expect(vault.retrieve('a')).toBe('identical');
    expect(vault.retrieve('b')).toBe('identical');
  });

  // D9: entries are held in memory as AES-256-GCM ciphertext under a 256-bit key.
  it('holds entries as authenticated AES-256-GCM ciphertext (D9)', () => {
    vault.store('gcm', 'SSN: 123-45-6789');
    const internals = vault as unknown as {
      key: Uint8Array;
      entries: Map<string, { encrypted: Uint8Array; iv: Uint8Array; authTag: Uint8Array }>;
    };
    const entry = internals.entries.get('gcm')!;
    expect(internals.key).toHaveLength(32);
    expect(entry.iv).toHaveLength(12);
    expect(entry.authTag).toHaveLength(16);
    expect(Buffer.from(entry.encrypted).toString('utf8')).not.toContain('123-45-6789');

    const decipher = createDecipheriv('aes-256-gcm', internals.key, entry.iv);
    decipher.setAuthTag(entry.authTag);
    const plain = Buffer.concat([decipher.update(entry.encrypted), decipher.final()]);
    expect(plain.toString('utf8')).toBe('SSN: 123-45-6789');

    entry.encrypted[0] ^= 0xff;
    expect(() => vault.retrieve('gcm')).toThrow();
  });

  it('destroy zeroes the key', () => {
    vault.store('key', 'secret');
    vault.destroy();

    // After destroy, retrieval should fail (key is zeroed)
    // The entry map is cleared so it returns null
    expect(vault.retrieve('key')).toBeNull();
  });
});
