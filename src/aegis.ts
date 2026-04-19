import type { AESBlock } from './aes';
import { aesRound, xorBlocks } from './aes';
import { concatBytes, hexToBytes, padBlock } from './bytes';

/**
 * AEGIS-256 state: 6 x 128-bit AES blocks.
 */
export type AegisState = [AESBlock, AESBlock, AESBlock, AESBlock, AESBlock, AESBlock];

/**
 * Constants from draft-irtf-cfrg-aegis-aead-18 Section 3.1.
 */
export const C0: AESBlock = hexToBytes('000101020305080d1522375990e97962');
export const C1: AESBlock = hexToBytes('db3d18556dc22ff12011314273b528dd');

function cloneBlock(block: AESBlock): AESBlock {
  return block.slice() as AESBlock;
}

function ensureLength(value: Uint8Array, expected: number, label: string): void {
  if (value.length !== expected) {
    throw new Error(`${label} must be ${expected} bytes`);
  }
}

function andBlocks(a: AESBlock, b: AESBlock): AESBlock {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i += 1) {
    out[i] = a[i] & b[i];
  }
  return out;
}

function keystream(S: AegisState): AESBlock {
  return xorBlocks(xorBlocks(xorBlocks(S[1], S[4]), S[5]), andBlocks(S[2], S[3]));
}

/**
 * The AEGIS update function - the permutation.
 */
export function update(S: AegisState, M: AESBlock): AegisState {
  const nextS0 = aesRound(S[5], xorBlocks(S[0], M));
  const nextS1 = aesRound(S[0], S[1]);
  const nextS2 = aesRound(S[1], S[2]);
  const nextS3 = aesRound(S[2], S[3]);
  const nextS4 = aesRound(S[3], S[4]);
  const nextS5 = aesRound(S[4], S[5]);

  return [nextS0, nextS1, nextS2, nextS3, nextS4, nextS5];
}

/**
 * Initialize AEGIS-256 state with 256-bit key and 256-bit nonce.
 * Performs 4 rounds of injection as specified.
 */
export function initialize(key: Uint8Array, nonce: Uint8Array): AegisState {
  ensureLength(key, 32, 'key');
  ensureLength(nonce, 32, 'nonce');

  const K0 = key.slice(0, 16);
  const K1 = key.slice(16, 32);
  const N0 = nonce.slice(0, 16);
  const N1 = nonce.slice(16, 32);

  let S: AegisState = [
    xorBlocks(K0, N0),
    xorBlocks(K1, N1),
    cloneBlock(C1),
    cloneBlock(C0),
    xorBlocks(K0, C0),
    xorBlocks(K1, C1),
  ];

  const injections: AESBlock[] = [K0, K1, xorBlocks(K0, N0), xorBlocks(K1, N1)];

  for (let i = 0; i < 4; i += 1) {
    for (const inject of injections) {
      S = update(S, inject);
    }
  }

  return S;
}

/**
 * Absorb an associated data block (no ciphertext output).
 */
export function absorb(S: AegisState, ad: AESBlock): AegisState {
  return update(S, ad);
}

/**
 * Encrypt one plaintext block. Returns (new_state, ciphertext_block).
 */
export function encryptBlock(
  S: AegisState,
  M: AESBlock,
): {
  state: AegisState;
  ciphertext: AESBlock;
} {
  const Z = keystream(S);
  const ciphertext = xorBlocks(M, Z);
  const state = update(S, M);
  return { state, ciphertext };
}

/**
 * Decrypt one ciphertext block. Returns (new_state, plaintext_block).
 */
export function decryptBlock(
  S: AegisState,
  C: AESBlock,
): {
  state: AegisState;
  plaintext: AESBlock;
} {
  const Z = keystream(S);
  const plaintext = xorBlocks(C, Z);
  const state = update(S, plaintext);
  return { state, plaintext };
}

function writeLE64(out: Uint8Array, offset: number, value: bigint): void {
  let n = BigInt.asUintN(64, value);
  for (let i = 0; i < 8; i += 1) {
    out[offset + i] = Number(n & 0xffn);
    n >>= 8n;
  }
}

/**
 * Finalize and produce 128-bit tag.
 */
export function finalize(S: AegisState, adLenBits: bigint, msgLenBits: bigint): AESBlock {
  const t = new Uint8Array(16);
  writeLE64(t, 0, adLenBits);
  writeLE64(t, 8, msgLenBits);

  const tt = xorBlocks(t, S[3]);
  let state = S;
  for (let i = 0; i < 7; i += 1) {
    state = update(state, tt);
  }

  return xorBlocks(
    xorBlocks(xorBlocks(state[0], state[1]), xorBlocks(state[2], state[3])),
    xorBlocks(state[4], state[5]),
  );
}

function absorbData(S: AegisState, data: Uint8Array): AegisState {
  let state = S;
  for (let i = 0; i < data.length; i += 16) {
    const chunk = data.slice(i, i + 16);
    state = absorb(state, padBlock(chunk));
  }
  return state;
}

/**
 * High-level encrypt API.
 * Returns { ciphertext, tag }.
 */
export function aegis256Encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ad: Uint8Array,
  plaintext: Uint8Array,
): { ciphertext: Uint8Array; tag: Uint8Array } {
  let state = initialize(key, nonce);
  state = absorbData(state, ad);

  const chunks: Uint8Array[] = [];
  for (let i = 0; i < plaintext.length; i += 16) {
    const block = plaintext.slice(i, i + 16);
    const padded = padBlock(block);
    const { state: nextState, ciphertext } = encryptBlock(state, padded);
    chunks.push(ciphertext.slice(0, block.length));
    state = nextState;
  }

  const tag = finalize(state, BigInt(ad.length * 8), BigInt(plaintext.length * 8));
  return { ciphertext: concatBytes(chunks), tag };
}

/**
 * Constant-time byte array comparison.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  const maxLen = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;

  for (let i = 0; i < maxLen; i += 1) {
    const ai = i < a.length ? a[i] : 0;
    const bi = i < b.length ? b[i] : 0;
    diff |= ai ^ bi;
  }

  return diff === 0;
}

/**
 * High-level decrypt API.
 * Returns plaintext on success, null on tag mismatch.
 */
export function aegis256Decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ad: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
): Uint8Array | null {
  if (tag.length !== 16) {
    return null;
  }

  let state = initialize(key, nonce);
  state = absorbData(state, ad);

  const chunks: Uint8Array[] = [];
  for (let i = 0; i < ciphertext.length; i += 16) {
    const chunk = ciphertext.slice(i, i + 16);
    if (chunk.length === 16) {
      const { state: nextState, plaintext } = decryptBlock(state, chunk);
      chunks.push(plaintext);
      state = nextState;
    } else {
      const z = keystream(state);
      const partial = new Uint8Array(chunk.length);
      for (let j = 0; j < chunk.length; j += 1) {
        partial[j] = chunk[j] ^ z[j];
      }
      chunks.push(partial);
      state = update(state, padBlock(partial));
    }
  }

  const computedTag = finalize(state, BigInt(ad.length * 8), BigInt(ciphertext.length * 8));
  if (!constantTimeEqual(computedTag, tag)) {
    return null;
  }

  return concatBytes(chunks);
}
