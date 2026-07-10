import { xorBytes } from './bytes';

/**
 * Helpers behind the nonce-reuse exhibit.
 *
 * AEGIS-256 encrypts block i as C_i = P_i ^ Z_i, where the keystream Z_i is
 * read from the state (Z = S1 ^ S4 ^ S5 ^ (S2 & S3)) BEFORE that block's
 * Update folds the plaintext in. Reusing a key+nonce reuses the initial
 * state, so for two messages under the same pair:
 *
 *   C_A_i ^ C_B_i = (P_A_i ^ Z_A_i) ^ (P_B_i ^ Z_B_i)
 *                 = (P_A_i ^ P_B_i) ^ (Z_A_i ^ Z_B_i)
 *
 * and wherever Z_A_i == Z_B_i the keystream cancels, leaking P_A_i ^ P_B_i
 * directly — a classic two-time pad, no key recovery required.
 *
 * Crucially, AEGIS is NOT a pure stream cipher: the keystream never reads
 * S0, and a plaintext block only enters S0. So the first TWO blocks
 * (32 bytes) always cancel regardless of message content, and the leak
 * continues through any shared plaintext prefix — but once the messages
 * diverge, the plaintext they absorbed pushes the two states apart and the
 * keystreams stop matching. A leaked 32-byte prefix is already a
 * catastrophic break; nonce reuse also voids AEGIS's authentication
 * guarantees (see the draft's security considerations).
 */

/** Number of leading blocks whose keystream is guaranteed to cancel. */
export const GUARANTEED_LEAK_BLOCKS = 2;

/**
 * Length, in bytes, of the leading run where the keystream cancelled: the
 * prefix of C_A ^ C_B that equals P_A ^ P_B. This is exactly the region a
 * two-time-pad attacker recovers.
 */
export function leakedRunLength(
  ctA: Uint8Array,
  ctB: Uint8Array,
  ptA: Uint8Array,
  ptB: Uint8Array,
): number {
  const ctXor = xorBytes(ctA, ctB);
  const ptXor = xorBytes(ptA, ptB);
  const limit = Math.min(ctXor.length, ptXor.length);
  let n = 0;
  while (n < limit && ctXor[n] === ptXor[n]) {
    n += 1;
  }
  return n;
}

/**
 * Known-plaintext recovery under nonce reuse: given both ciphertexts and one
 * plaintext, recover the other over the overlapping prefix.
 *
 *   P_B = C_B ^ C_A ^ P_A   (the shared keystream cancels)
 *
 * This is correct only over the leaked run; past it the bytes are garbage,
 * which is exactly what the exhibit highlights.
 */
export function recoverSibling(
  ctKnown: Uint8Array,
  ctUnknown: Uint8Array,
  knownPlaintext: Uint8Array,
): Uint8Array {
  return xorBytes(xorBytes(ctKnown, ctUnknown), knownPlaintext);
}

/**
 * Render bytes for display: printable ASCII stays, everything else becomes a
 * middle dot. Used to show recovered plaintext emerging from raw bytes.
 */
export function formatPrintable(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) {
    out += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '·';
  }
  return out;
}
