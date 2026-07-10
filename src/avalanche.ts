import { type AegisState, initializeSteps } from './aegis';

/**
 * Avalanche trace: flip a single bit of the nonce and measure, after the
 * seeding step and after each of the 16 initialization updates, how many
 * bits of the 768-bit state differ between the two runs.
 *
 * Ideal diffusion is ~50% of bits differing (~384/768) — this is what the
 * draft's 16 setup updates exist to reach before any keystream is exposed.
 */

export const STATE_BITS = 768;

export interface AvalancheStep {
  /** 'seed' for the pre-update state, then 'update 1'..'update 16'. */
  label: string;
  /** Differing bits per state block S0..S5 (each 0..128). */
  perBlockBits: number[];
  /** Total differing bits across the whole state (0..768). */
  totalBits: number;
}

function popcount(byte: number): number {
  let n = byte;
  let count = 0;
  while (n !== 0) {
    count += n & 1;
    n >>= 1;
  }
  return count;
}

function diffBits(a: AegisState, b: AegisState): { perBlockBits: number[]; totalBits: number } {
  const perBlockBits: number[] = [];
  let totalBits = 0;
  for (let i = 0; i < 6; i += 1) {
    let blockBits = 0;
    for (let j = 0; j < 16; j += 1) {
      blockBits += popcount(a[i][j] ^ b[i][j]);
    }
    perBlockBits.push(blockBits);
    totalBits += blockBits;
  }
  return { perBlockBits, totalBits };
}

/**
 * Run initialization twice — once with `nonce`, once with one bit of it
 * flipped — and report the bit-level state difference at every step.
 */
export function avalancheTrace(
  key: Uint8Array,
  nonce: Uint8Array,
  byteIndex: number,
  bitIndex: number,
): AvalancheStep[] {
  const flipped = nonce.slice();
  flipped[byteIndex % flipped.length] ^= 1 << (bitIndex % 8);

  const a = initializeSteps(key, nonce);
  const b = initializeSteps(key, flipped);

  return a.map((state, i) => {
    const { perBlockBits, totalBits } = diffBits(state, b[i]);
    return {
      label: i === 0 ? 'seed' : `update ${i}`,
      perBlockBits,
      totalBits,
    };
  });
}
