import { describe, expect, it } from 'vitest';
import { aegis256Decrypt, aegis256Encrypt } from '../src/aegis';
import { hexToBytes, bytesToHex } from '../src/bytes';
import { runCommitment } from '../src/commitment';
import vector from '../src/commitment-vector.json';

describe('Appendix A.2 AEGIS-256 full-robustness fixture', () => {
  it('reproduces the published ciphertext and tag with both contexts', () => {
    const expected = hexToBytes(vector.ciphertextAndTag128);
    expect(vector.keyA).not.toBe(vector.keyB);
    expect(vector.adA).not.toBe(vector.adB);
    expect(vector.nonceA).toBe(vector.nonceB);
    for (const [key, ad] of [[vector.keyA, vector.adA], [vector.keyB, vector.adB]]) {
      const enc = aegis256Encrypt(hexToBytes(key), hexToBytes(vector.nonceA), hexToBytes(ad), hexToBytes(vector.plaintext), 16);
      expect(bytesToHex(enc.ciphertext) + bytesToHex(enc.tag)).toBe(bytesToHex(expected));
      expect(aegis256Decrypt(hexToBytes(key), hexToBytes(vector.nonceA), hexToBytes(ad), expected.slice(0, 16), expected.slice(16))).toEqual(hexToBytes(vector.plaintext));
    }
  });
  for (const tagLength of [16, 32] as const) {
    it(`executes both acceptances and state convergence with ${tagLength}-byte tags`, () => {
      const r = runCommitment('collision', tagLength);
      expect(r.acceptedA).toBe(true);
      expect(r.acceptedB).toBe(true);
      expect(r.ambiguous).toBe(true);
      expect(r.plaintextA).toBe(vector.plaintext);
      expect(r.plaintextB).toBe(vector.plaintext);
      expect(r.tagB).toBe(r.tag);
      expect(r.ciphertextB).toBe(r.ciphertext);
      expect(r.trace).toHaveLength(7);
      expect(r.trace[0].bits.some(n => n > 0)).toBe(true);
      expect(r.trace.at(-1)?.bits).toEqual([0, 0, 0, 0, 0, 0]);
      expect(r.stateEqual).toBe(true);
    });
    for (const scenario of ['same-ad', 'tampered-ad'] as const) {
      it(`rejects the ${scenario} control with ${tagLength}-byte tags`, () => {
        const r = runCommitment(scenario, tagLength);
        expect(r.acceptedA).toBe(true);
        expect(r.acceptedB).toBe(false);
        expect(r.plaintextB).toBeNull();
        expect(r.ambiguous).toBe(false);
        expect(r.stateEqual).toBe(false);
        expect(r.trace.at(-1)?.bits.some(n => n > 0)).toBe(true);
      });
    }
  }
});
