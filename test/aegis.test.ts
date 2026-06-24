import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import {
  type TagLength,
  aegis256Decrypt,
  aegis256Encrypt,
  constantTimeEqual,
  initialize,
  update,
} from '../src/aegis';
import { bytesToHex, hexToBytes } from '../src/bytes';

interface AegisVector {
  name: string;
  error?: string;
  key?: string;
  nonce?: string;
  ad?: string;
  msg?: string;
  ct?: string;
  tag128?: string;
  tag256?: string;
  // Fields for the standalone Update test vector:
  S0?: string;
  S1?: string;
  S2?: string;
  S3?: string;
  S4?: string;
  S5?: string;
  M?: string;
  S0_2?: string;
  S1_2?: string;
  S2_2?: string;
  S3_2?: string;
  S4_2?: string;
  S5_2?: string;
}

const thisDir = dirname(fileURLToPath(import.meta.url));
const vectorsPath = resolve(thisDir, 'vectors/aegis-256-test-vectors.json');
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8')) as AegisVector[];

function requireHex(value: string | undefined, field: string, vectorName: string): Uint8Array {
  if (typeof value !== 'string') {
    throw new Error(`Missing ${field} for vector ${vectorName}`);
  }
  return hexToBytes(value);
}

const updateVector = vectors.find((v) => v.name === 'Update Test Vector');
// Encryption vectors carry a `msg`; failure vectors carry an `error` instead.
const encryptVectors = vectors.filter((v) => typeof v.msg === 'string' && !v.error);
const failureVectors = vectors.filter((v) => v.error === 'verification failed');

describe('AEGIS-256 update function', () => {
  it('matches the official update test vector', () => {
    expect(updateVector).toBeTruthy();

    const S = [
      requireHex(updateVector?.S0, 'S0', 'Update Test Vector'),
      requireHex(updateVector?.S1, 'S1', 'Update Test Vector'),
      requireHex(updateVector?.S2, 'S2', 'Update Test Vector'),
      requireHex(updateVector?.S3, 'S3', 'Update Test Vector'),
      requireHex(updateVector?.S4, 'S4', 'Update Test Vector'),
      requireHex(updateVector?.S5, 'S5', 'Update Test Vector'),
    ] as [Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array];

    const out = update(S, requireHex(updateVector?.M, 'M', 'Update Test Vector'));

    expect(bytesToHex(out[0])).toBe(updateVector?.S0_2);
    expect(bytesToHex(out[1])).toBe(updateVector?.S1_2);
    expect(bytesToHex(out[2])).toBe(updateVector?.S2_2);
    expect(bytesToHex(out[3])).toBe(updateVector?.S3_2);
    expect(bytesToHex(out[4])).toBe(updateVector?.S4_2);
    expect(bytesToHex(out[5])).toBe(updateVector?.S5_2);
  });
});

describe('AEGIS-256 encryption vectors (draft-irtf-cfrg-aegis-aead-18)', () => {
  it('exercises the full official vector set', () => {
    // Guard against silently testing fewer vectors than the draft publishes.
    expect(encryptVectors.length).toBeGreaterThanOrEqual(5);
    expect(failureVectors.length).toBeGreaterThanOrEqual(4);
  });

  for (const v of encryptVectors) {
    const key = requireHex(v.key, 'key', v.name);
    const nonce = requireHex(v.nonce, 'nonce', v.name);
    const ad = requireHex(v.ad, 'ad', v.name);
    const msg = requireHex(v.msg, 'msg', v.name);

    it(`${v.name}: encrypts to the exact ciphertext, tag128, and tag256`, () => {
      const t128 = aegis256Encrypt(key, nonce, ad, msg, 16);
      expect(bytesToHex(t128.ciphertext)).toBe(v.ct);
      expect(bytesToHex(t128.tag)).toBe(v.tag128);

      const t256 = aegis256Encrypt(key, nonce, ad, msg, 32);
      // Ciphertext is independent of tag length.
      expect(bytesToHex(t256.ciphertext)).toBe(v.ct);
      expect(bytesToHex(t256.tag)).toBe(v.tag256);
    });

    it(`${v.name}: round-trips through decrypt for both tag lengths`, () => {
      for (const tagLength of [16, 32] as TagLength[]) {
        const { ciphertext, tag } = aegis256Encrypt(key, nonce, ad, msg, tagLength);
        const decrypted = aegis256Decrypt(key, nonce, ad, ciphertext, tag, tagLength);
        expect(decrypted).not.toBeNull();
        expect(decrypted && constantTimeEqual(decrypted, msg)).toBe(true);
      }
    });
  }
});

describe('AEGIS-256 authentication failures (draft vectors 6-9)', () => {
  for (const v of failureVectors) {
    const key = requireHex(v.key, 'key', v.name);
    const nonce = requireHex(v.nonce, 'nonce', v.name);
    const ad = requireHex(v.ad, 'ad', v.name);
    const ct = requireHex(v.ct, 'ct', v.name);

    it(`${v.name}: rejects with a 128-bit tag`, () => {
      const tag = requireHex(v.tag128, 'tag128', v.name);
      expect(aegis256Decrypt(key, nonce, ad, ct, tag, 16)).toBeNull();
    });

    it(`${v.name}: rejects with a 256-bit tag`, () => {
      const tag = requireHex(v.tag256, 'tag256', v.name);
      expect(aegis256Decrypt(key, nonce, ad, ct, tag, 32)).toBeNull();
    });
  }
});

describe('AEGIS-256 API behaviour', () => {
  const vector1 = encryptVectors[0];
  const key = requireHex(vector1.key, 'key', vector1.name);
  const nonce = requireHex(vector1.nonce, 'nonce', vector1.name);
  const ad = requireHex(vector1.ad, 'ad', vector1.name);

  it('rejects a tag whose length does not match the requested tagLength', () => {
    const { ciphertext, tag } = aegis256Encrypt(key, nonce, ad, hexToBytes(vector1.msg ?? ''), 16);
    // A valid 16-byte tag must be refused when 32 bytes are expected.
    expect(aegis256Decrypt(key, nonce, ad, ciphertext, tag, 32)).toBeNull();
  });

  it('round-trips a non-block-aligned plaintext (partial final block)', () => {
    const msg = new TextEncoder().encode('AEGIS handles partial blocks too.'); // 33 bytes
    const { ciphertext, tag } = aegis256Encrypt(key, nonce, ad, msg);
    expect(ciphertext.length).toBe(msg.length);
    const decrypted = aegis256Decrypt(key, nonce, ad, ciphertext, tag);
    expect(decrypted && constantTimeEqual(decrypted, msg)).toBe(true);
  });

  it('initialization is deterministic', () => {
    const a = initialize(key, nonce);
    const b = initialize(key, nonce);
    for (let i = 0; i < 6; i += 1) {
      expect(constantTimeEqual(a[i], b[i])).toBe(true);
    }
  });

  it('constantTimeEqual reports equality and inequality correctly', () => {
    const a = hexToBytes('00112233445566778899aabbccddeeff');
    const b = hexToBytes('00112233445566778899aabbccddeeff');
    const c = hexToBytes('00112233445566778899aabbccddee00');

    expect(constantTimeEqual(a, b)).toBe(true);
    expect(constantTimeEqual(a, c)).toBe(false);
    expect(constantTimeEqual(a, c.slice(0, 8))).toBe(false);
  });
});
