import { describe, expect, it } from 'vitest';

import { aesRound, gmul } from '../src/aes';

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('hex string must have even length');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

describe('AES helpers', () => {
  it('matches the classic FIPS 197 GF(2^8) example', () => {
    expect(gmul(0x57, 0x13)).toBe(0xfe);
  });
});

describe('aesRound', () => {
  it('produces known reference output for all-zero input', () => {
    const A = new Uint8Array(16);
    const B = new Uint8Array(16);
    const out = aesRound(A, B);

    expect(bytesToHex(out)).toBe('63636363636363636363636363636363');
  });

  it('matches a documented FIPS 197 single-round reference state', () => {
    // FIPS 197 round flow example from AES-128 encryption:
    // state before round transform: 00102030405060708090a0b0c0d0e0f0
    // round key:                    d6aa74fdd2af72fadaa678f1d6ab76fe
    // state after SubBytes+ShiftRows+MixColumns+AddRoundKey:
    //                               89d810e8855ace682d1843d8cb128fe4
    const A = hexToBytes('00102030405060708090a0b0c0d0e0f0');
    const B = hexToBytes('d6aa74fdd2af72fadaa678f1d6ab76fe');
    const out = aesRound(A, B);

    expect(bytesToHex(out)).toBe('89d810e8855ace682d1843d8cb128fe4');
  });
});
