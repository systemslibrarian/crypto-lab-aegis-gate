/**
 * Shareable-scenario links: the key, nonce, associated data, and plaintext
 * from Exhibit 1 encoded as URL query parameters, so a teacher can hand a
 * class one link that opens the demo in an exact known state.
 */

export interface ShareFields {
  /** 32-byte key, hex. */
  key: string;
  /** 32-byte nonce, hex. */
  nonce: string;
  /** Associated data, UTF-8 text. */
  ad: string;
  /** Plaintext, UTF-8 text. */
  pt: string;
}

const HEX_64 = /^[0-9a-f]{64}$/;

export function buildShareQuery(fields: ShareFields): string {
  const params = new URLSearchParams();
  params.set('key', fields.key);
  params.set('nonce', fields.nonce);
  if (fields.ad !== '') {
    params.set('ad', fields.ad);
  }
  if (fields.pt !== '') {
    params.set('pt', fields.pt);
  }
  return params.toString();
}

/**
 * Parse a query string back into scenario fields. Key and nonce are only
 * returned when they are exactly 64 lowercase hex chars — a malformed link
 * falls back to random values rather than breaking the page.
 */
export function parseShareQuery(search: string): Partial<ShareFields> {
  const params = new URLSearchParams(search);
  const out: Partial<ShareFields> = {};

  const key = params.get('key')?.trim().toLowerCase();
  if (key && HEX_64.test(key)) {
    out.key = key;
  }
  const nonce = params.get('nonce')?.trim().toLowerCase();
  if (nonce && HEX_64.test(nonce)) {
    out.nonce = nonce;
  }
  const ad = params.get('ad');
  if (ad !== null) {
    out.ad = ad;
  }
  const pt = params.get('pt');
  if (pt !== null) {
    out.pt = pt;
  }

  return out;
}
