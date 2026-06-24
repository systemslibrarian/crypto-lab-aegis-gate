import { describe, expect, it } from 'vitest';

import { bytesToHex, concatBytes, hexToBytes, padBlock } from '../src/bytes';

describe('hexToBytes', () => {
  it('parses valid lowercase and uppercase hex', () => {
    expect(Array.from(hexToBytes('00ff10'))).toEqual([0x00, 0xff, 0x10]);
    expect(Array.from(hexToBytes('00FF10'))).toEqual([0x00, 0xff, 0x10]);
  });

  it('treats an empty string as zero bytes', () => {
    expect(hexToBytes('').length).toBe(0);
  });

  it('rejects odd-length input', () => {
    expect(() => hexToBytes('abc')).toThrow(/even length/);
  });

  it('rejects a trailing invalid nibble that parseInt would silently accept', () => {
    // Number.parseInt('1g', 16) === 1, so a naive per-pair NaN check passes
    // this through as 0x01. It must throw instead.
    expect(() => hexToBytes('1g')).toThrow(/Invalid hex/);
    expect(() => hexToBytes('ff0z')).toThrow(/Invalid hex/);
  });

  it('rejects leading and embedded non-hex characters', () => {
    expect(() => hexToBytes('g1')).toThrow(/Invalid hex/);
    expect(() => hexToBytes('ab cd')).toThrow(); // odd length once spaced
    expect(() => hexToBytes('abxy')).toThrow(/Invalid hex/);
    expect(() => hexToBytes('0x00')).toThrow(/Invalid hex/);
  });

  it('round-trips with bytesToHex', () => {
    const hex = '1001000000000000000000000000000000000000000000000000000000000000';
    expect(bytesToHex(hexToBytes(hex))).toBe(hex);
  });
});

describe('padBlock', () => {
  it('zero-pads a short block to 16 bytes', () => {
    const out = padBlock(hexToBytes('aabb'));
    expect(out.length).toBe(16);
    expect(Array.from(out.slice(0, 2))).toEqual([0xaa, 0xbb]);
    expect(Array.from(out.slice(2)).every((b) => b === 0)).toBe(true);
  });

  it('truncates an over-long block to the target size', () => {
    const out = padBlock(new Uint8Array(20).fill(0x11));
    expect(out.length).toBe(16);
  });
});

describe('concatBytes', () => {
  it('concatenates parts in order', () => {
    const out = concatBytes([hexToBytes('0011'), hexToBytes('2233'), new Uint8Array(0)]);
    expect(bytesToHex(out)).toBe('00112233');
  });

  it('returns an empty array for no parts', () => {
    expect(concatBytes([]).length).toBe(0);
  });
});
