import { describe, expect, it } from 'vitest';

import { nonceCollisionProbability } from '../src/birthday';

describe('birthday-bound collision probability', () => {
  it('is zero for a single message', () => {
    const { p, log2P } = nonceCollisionProbability(0, 96);
    expect(p).toBe(0);
    expect(log2P).toBeNull();
  });

  it('two messages under b-bit nonces collide with probability ~2^-b', () => {
    const { log2P } = nonceCollisionProbability(1, 96);
    expect(log2P).toBeCloseTo(-96, 0);
  });

  it('matches the classic GCM numbers: 2^32 messages under 96-bit nonces => ~2^-33', () => {
    const { log2P } = nonceCollisionProbability(32, 96);
    expect(log2P).toBeCloseTo(-33, 0);
  });

  it('n = 2^48.5 under 96-bit nonces approaches the 50% birthday point', () => {
    // pairs ~ 2^96, r ~ 1, p = 1 - e^-1 ~ 0.632
    const { p } = nonceCollisionProbability(48.5, 96);
    expect(p).toBeGreaterThan(0.5);
    expect(p).toBeLessThan(0.75);
  });

  it('256-bit nonces stay negligible even at 2^64 messages', () => {
    const { p, log2P } = nonceCollisionProbability(64, 256);
    expect(p).toBeLessThan(1e-35);
    expect(log2P).toBeCloseTo(-129, 0);
  });

  it('is monotonically increasing in the message count', () => {
    let last = 0;
    for (let x = 1; x <= 64; x += 1) {
      const { p } = nonceCollisionProbability(x, 96);
      expect(p).toBeGreaterThanOrEqual(last);
      last = p;
    }
  });
});
