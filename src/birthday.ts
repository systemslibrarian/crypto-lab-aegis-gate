/**
 * Birthday-bound math behind the "how long are random nonces safe?"
 * explorer. For n messages under uniformly random b-bit nonces, the
 * collision probability is approximately
 *
 *   p ~= 1 - exp(-n(n-1)/2 / 2^b)
 *
 * This is the reason AES-GCM's random-nonce use is capped near 2^32
 * messages (keeping p below 2^-32) while AEGIS-256's 256-bit nonce makes
 * random generation safe for any practical message count.
 */

export interface CollisionEstimate {
  /** Collision probability in [0, 1]. */
  p: number;
  /** log2(p), or null when p is exactly 0 (fewer than 2 messages). */
  log2P: number | null;
}

/**
 * Collision probability for 2^log2Messages messages under random
 * nonceBits-bit nonces. log2Messages may be 0..64; nonceBits e.g. 96 or 256.
 */
export function nonceCollisionProbability(log2Messages: number, nonceBits: number): CollisionEstimate {
  if (log2Messages <= 0) {
    return { p: 0, log2P: null };
  }

  // log2 of the number of message pairs n(n-1)/2. For large n this is
  // 2*log2n - 1; compute exactly for small n where n-1 != n.
  const log2Pairs =
    log2Messages < 30
      ? Math.log2((2 ** log2Messages * (2 ** log2Messages - 1)) / 2)
      : 2 * log2Messages - 1;

  // r = pairs / 2^b stays within double range for every slider value:
  // exponent spans about [-256, +31].
  const r = 2 ** (log2Pairs - nonceBits);
  const p = -Math.expm1(-r);

  return { p, log2P: p > 0 ? Math.log2(p) : null };
}
