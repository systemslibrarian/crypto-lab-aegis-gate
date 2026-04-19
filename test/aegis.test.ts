import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { aegis256Decrypt, aegis256Encrypt, constantTimeEqual, initialize, update } from '../src/aegis';
import { bytesToHex, hexToBytes } from '../src/bytes';

interface AegisVector {
  name: string;
  key?: string;
  nonce?: string;
  ad?: string;
  msg?: string;
  ct?: string;
  tag128?: string;
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

describe('AEGIS-256 update function', () => {
  it('matches the official update test vector', () => {
    const updateVector = vectors.find((v) => v.name === 'Update Test Vector');
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

describe('AEGIS-256 draft vectors', () => {
  const v1 = vectors.find((v) => v.name === 'Test Vector 1');
  const v2 = vectors.find((v) => v.name === 'Test Vector 2');

  it('matches Test Vector 1 ciphertext and tag128 exactly', () => {
    expect(v1).toBeTruthy();

    const result = aegis256Encrypt(
      requireHex(v1?.key, 'key', 'Test Vector 1'),
      requireHex(v1?.nonce, 'nonce', 'Test Vector 1'),
      requireHex(v1?.ad, 'ad', 'Test Vector 1'),
      requireHex(v1?.msg, 'msg', 'Test Vector 1'),
    );

    expect(bytesToHex(result.ciphertext)).toBe(v1?.ct);
    expect(bytesToHex(result.tag)).toBe(v1?.tag128);
  });

  it('matches Test Vector 2 (empty message) tag128 exactly', () => {
    expect(v2).toBeTruthy();

    const result = aegis256Encrypt(
      requireHex(v2?.key, 'key', 'Test Vector 2'),
      requireHex(v2?.nonce, 'nonce', 'Test Vector 2'),
      requireHex(v2?.ad, 'ad', 'Test Vector 2'),
      requireHex(v2?.msg, 'msg', 'Test Vector 2'),
    );

    expect(bytesToHex(result.ciphertext)).toBe(v2?.ct);
    expect(bytesToHex(result.tag)).toBe(v2?.tag128);
  });

  it('returns null on wrong tag', () => {
    expect(v1).toBeTruthy();

    const key = requireHex(v1?.key, 'key', 'Test Vector 1');
    const nonce = requireHex(v1?.nonce, 'nonce', 'Test Vector 1');
    const ad = requireHex(v1?.ad, 'ad', 'Test Vector 1');
    const ct = requireHex(v1?.ct, 'ct', 'Test Vector 1');
    const badTag = requireHex(v1?.tag128, 'tag128', 'Test Vector 1').slice();
    badTag[0] ^= 0x01;

    const dec = aegis256Decrypt(key, nonce, ad, ct, badTag);
    expect(dec).toBeNull();
  });

  it('returns null on tampered ciphertext', () => {
    expect(v1).toBeTruthy();

    const key = requireHex(v1?.key, 'key', 'Test Vector 1');
    const nonce = requireHex(v1?.nonce, 'nonce', 'Test Vector 1');
    const ad = requireHex(v1?.ad, 'ad', 'Test Vector 1');
    const ct = requireHex(v1?.ct, 'ct', 'Test Vector 1').slice();
    const tag = requireHex(v1?.tag128, 'tag128', 'Test Vector 1');
    ct[0] ^= 0x01;

    const dec = aegis256Decrypt(key, nonce, ad, ct, tag);
    expect(dec).toBeNull();
  });

  it('round-trips valid ciphertext for vector 1', () => {
    expect(v1).toBeTruthy();

    const key = requireHex(v1?.key, 'key', 'Test Vector 1');
    const nonce = requireHex(v1?.nonce, 'nonce', 'Test Vector 1');
    const ad = requireHex(v1?.ad, 'ad', 'Test Vector 1');
    const ct = requireHex(v1?.ct, 'ct', 'Test Vector 1');
    const tag = requireHex(v1?.tag128, 'tag128', 'Test Vector 1');
    const msg = requireHex(v1?.msg, 'msg', 'Test Vector 1');

    const dec = aegis256Decrypt(key, nonce, ad, ct, tag);
    expect(dec).not.toBeNull();
    expect(dec && constantTimeEqual(dec, msg)).toBe(true);
  });

  it('initialization is deterministic', () => {
    expect(v1).toBeTruthy();

    const key = requireHex(v1?.key, 'key', 'Test Vector 1');
    const nonce = requireHex(v1?.nonce, 'nonce', 'Test Vector 1');

    const a = initialize(key, nonce);
    const b = initialize(key, nonce);

    expect(constantTimeEqual(a[0], b[0])).toBe(true);
    expect(constantTimeEqual(a[1], b[1])).toBe(true);
    expect(constantTimeEqual(a[2], b[2])).toBe(true);
    expect(constantTimeEqual(a[3], b[3])).toBe(true);
    expect(constantTimeEqual(a[4], b[4])).toBe(true);
    expect(constantTimeEqual(a[5], b[5])).toBe(true);
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
