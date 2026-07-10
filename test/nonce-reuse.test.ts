import { describe, expect, it } from 'vitest';

import { aegis256Encrypt } from '../src/aegis';
import { bytesToHex, randomBytes, utf8ToBytes, xorBytes } from '../src/bytes';
import {
  GUARANTEED_LEAK_BLOCKS,
  formatPrintable,
  leakedRunLength,
  recoverSibling,
} from '../src/nonce-reuse';

describe('nonce-reuse keystream cancellation', () => {
  // Two messages that differ from the very first byte (no shared prefix).
  const ptA = utf8ToBytes('Retreat at dusk! Regroup at the river bridge tonight.');
  const ptB = utf8ToBytes('Attack at dawn now: 06:00hrs, north gate, all units.');
  const empty = new Uint8Array(0);

  it('the first two blocks (32 bytes) always leak, even with no shared prefix', () => {
    const key = randomBytes(32);
    const nonce = randomBytes(32);
    const a = aegis256Encrypt(key, nonce, empty, ptA);
    const b = aegis256Encrypt(key, nonce, empty, ptB);

    const leaked = leakedRunLength(a.ciphertext, b.ciphertext, ptA, ptB);
    expect(leaked).toBeGreaterThanOrEqual(GUARANTEED_LEAK_BLOCKS * 16);

    // Over the leaked run, C_A xor C_B equals P_A xor P_B exactly.
    const ctXor = xorBytes(a.ciphertext, b.ciphertext).slice(0, leaked);
    const ptXor = xorBytes(ptA, ptB).slice(0, leaked);
    expect(bytesToHex(ctXor)).toBe(bytesToHex(ptXor));
  });

  it('a shared plaintext prefix extends the leak through it', () => {
    const key = randomBytes(32);
    const nonce = randomBytes(32);
    const shared = 'FLASH//TOP SECRET//NOFORN//urgent: ';
    const a = aegis256Encrypt(key, nonce, empty, utf8ToBytes(`${shared}hold position`));
    const b = aegis256Encrypt(key, nonce, empty, utf8ToBytes(`${shared}fall back now!`));

    const leaked = leakedRunLength(
      a.ciphertext,
      b.ciphertext,
      utf8ToBytes(`${shared}hold position`),
      utf8ToBytes(`${shared}fall back now!`),
    );
    // Shared prefix (35 bytes) plus the two-block guarantee past divergence.
    expect(leaked).toBeGreaterThan(shared.length);
  });

  it('recovers the leaked prefix of the unknown plaintext from the two ciphertexts', () => {
    const key = randomBytes(32);
    const nonce = randomBytes(32);
    const a = aegis256Encrypt(key, nonce, empty, ptA);
    const b = aegis256Encrypt(key, nonce, empty, ptB);

    const leaked = leakedRunLength(a.ciphertext, b.ciphertext, ptA, ptB);
    const recovered = recoverSibling(a.ciphertext, b.ciphertext, ptA);
    // The leaked run of the recovery equals the true secret B there.
    expect(bytesToHex(recovered.slice(0, leaked))).toBe(bytesToHex(ptB.slice(0, leaked)));
    expect(formatPrintable(recovered.slice(0, leaked))).toContain('Attack at dawn');
  });

  it('a fresh nonce leaks nothing', () => {
    const key = randomBytes(32);
    const a = aegis256Encrypt(key, randomBytes(32), empty, ptA);
    const b = aegis256Encrypt(key, randomBytes(32), empty, ptB);

    // With overwhelming probability the very first byte already differs.
    expect(leakedRunLength(a.ciphertext, b.ciphertext, ptA, ptB)).toBe(0);
  });

  it('formatPrintable keeps printable ASCII and dots the rest', () => {
    expect(formatPrintable(new Uint8Array([0x41, 0x42, 0x00, 0x7f, 0x20]))).toBe('AB·· ');
  });
});
