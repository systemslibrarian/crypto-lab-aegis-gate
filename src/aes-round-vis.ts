import { SBOX, mixColumns, shiftRows, subBytes } from './aes';

/**
 * Snapshots of the four intermediate states of ONE AES round, computed with the
 * SAME real functions AEGIS invokes six times per Update. Nothing here is faked
 * or simplified: every byte is the genuine output of FIPS 197 SubBytes,
 * ShiftRows, MixColumns, and the final AddRoundKey (the XOR AEGIS uses to fold
 * one state block into another).
 *
 * The point is pedagogical, not cryptographic: exposing the atomic operation so
 * a learner can watch "AES-based" mean something, rather than take it on trust.
 */
export interface AesRoundTrace {
  /** The 16-byte input block A (the block being transformed). */
  input: Uint8Array;
  /** The 16-byte block B that gets XORed in at the end (the "round key"). */
  roundKey: Uint8Array;
  /** After SubBytes: each byte replaced by SBOX[byte]. */
  afterSub: Uint8Array;
  /** After ShiftRows: rows 1..3 cyclically left-shifted by 1..3. */
  afterShift: Uint8Array;
  /** After MixColumns: each column mixed in GF(2^8). */
  afterMix: Uint8Array;
  /** Final AESRound output: afterMix XOR roundKey. */
  output: Uint8Array;
}

/**
 * Run one real AES round on `input`, folding in `roundKey` at the end, and keep
 * every intermediate state so the UI can show the step-by-step transformation.
 */
export function traceAesRound(input: Uint8Array, roundKey: Uint8Array): AesRoundTrace {
  const afterSub = subBytes(input);
  const afterShift = shiftRows(afterSub);
  const afterMix = mixColumns(afterShift);
  const output = new Uint8Array(16);
  for (let i = 0; i < 16; i += 1) {
    output[i] = afterMix[i] ^ roundKey[i];
  }
  return {
    input: input.slice(),
    roundKey: roundKey.slice(),
    afterSub,
    afterShift,
    afterMix,
    output,
  };
}

/** Look up one S-box substitution, exposed so the UI can show the mapping. */
export function sboxLookup(byte: number): number {
  return SBOX[byte & 0xff];
}

/**
 * ShiftRows source map: for AES's column-major 4x4 layout (byte index
 * i -> row i%4, column floor(i/4)), returns, for each output index, the input
 * index its byte was taken from. Row r is rotated left by r columns.
 */
export function shiftRowsSourceMap(): number[] {
  const map = new Array<number>(16);
  for (let col = 0; col < 4; col += 1) {
    for (let row = 0; row < 4; row += 1) {
      const outIndex = col * 4 + row;
      const srcCol = (col + row) % 4;
      map[outIndex] = srcCol * 4 + row;
    }
  }
  return map;
}
