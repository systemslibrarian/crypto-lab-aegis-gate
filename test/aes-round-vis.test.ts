import { describe, expect, it } from 'vitest';

import { SBOX, aesRound, shiftRows, subBytes } from '../src/aes';
import { shiftRowsSourceMap, traceAesRound } from '../src/aes-round-vis';

function seqBlock(start: number): Uint8Array {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i += 1) {
    out[i] = (start + i * 7) & 0xff;
  }
  return out;
}

describe('AES round visualizer', () => {
  it('final output matches the real aesRound() the demo uses', () => {
    const a = seqBlock(3);
    const b = seqBlock(200);
    const trace = traceAesRound(a, b);
    expect(Array.from(trace.output)).toEqual(Array.from(aesRound(a, b)));
  });

  it('afterSub is exactly SubBytes of the input', () => {
    const a = seqBlock(11);
    const trace = traceAesRound(a, new Uint8Array(16));
    expect(Array.from(trace.afterSub)).toEqual(Array.from(subBytes(a)));
    // and each byte is a genuine S-box entry
    for (let i = 0; i < 16; i += 1) {
      expect(trace.afterSub[i]).toBe(SBOX[a[i]]);
    }
  });

  it('shiftRowsSourceMap describes the real ShiftRows permutation', () => {
    const a = seqBlock(0);
    const shifted = shiftRows(a);
    const map = shiftRowsSourceMap();
    for (let i = 0; i < 16; i += 1) {
      expect(shifted[i]).toBe(a[map[i]]);
    }
  });

  it('does not mutate the caller-supplied input block', () => {
    const a = seqBlock(5);
    const copy = a.slice();
    traceAesRound(a, new Uint8Array(16));
    expect(Array.from(a)).toEqual(Array.from(copy));
  });
});
