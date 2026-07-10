import { describe, expect, it } from 'vitest';

import { initialize, initializeSteps } from '../src/aegis';
import { STATE_BITS, avalancheTrace } from '../src/avalanche';
import { bytesToHex, randomBytes } from '../src/bytes';

describe('initializeSteps', () => {
  it('returns 17 states whose last entry equals initialize()', () => {
    const key = randomBytes(32);
    const nonce = randomBytes(32);

    const steps = initializeSteps(key, nonce);
    expect(steps.length).toBe(17);

    const final = initialize(key, nonce);
    for (let i = 0; i < 6; i += 1) {
      expect(bytesToHex(steps[16][i])).toBe(bytesToHex(final[i]));
    }
  });
});

describe('avalancheTrace', () => {
  const key = randomBytes(32);
  const nonce = randomBytes(32);
  const trace = avalancheTrace(key, nonce, 5, 3);

  it('produces one step per init state (seed + 16 updates)', () => {
    expect(trace.length).toBe(17);
    expect(trace[0].label).toBe('seed');
    expect(trace[16].label).toBe('update 16');
  });

  it('starts from exactly one differing bit in the seeded state', () => {
    expect(trace[0].totalBits).toBe(1);
  });

  it('reaches ~50% differing bits by the end of initialization', () => {
    const final = trace[16].totalBits;
    // Ideal diffusion is 384/768; allow a generous statistical band.
    expect(final).toBeGreaterThan(STATE_BITS * 0.4);
    expect(final).toBeLessThan(STATE_BITS * 0.6);
  });

  it('per-block bits sum to the total', () => {
    for (const step of trace) {
      const sum = step.perBlockBits.reduce((a, b) => a + b, 0);
      expect(sum).toBe(step.totalBits);
      expect(step.perBlockBits.length).toBe(6);
    }
  });
});
