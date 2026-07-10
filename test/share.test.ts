import { describe, expect, it } from 'vitest';

import { buildShareQuery, parseShareQuery } from '../src/share';

const KEY = 'a'.repeat(64);
const NONCE = 'b'.repeat(64);

describe('shareable scenario links', () => {
  it('round-trips all fields through the query string', () => {
    const query = buildShareQuery({
      key: KEY,
      nonce: NONCE,
      ad: 'header v1',
      pt: 'Hello, AEGIS-256! & <friends>',
    });
    const parsed = parseShareQuery(`?${query}`);
    expect(parsed).toEqual({
      key: KEY,
      nonce: NONCE,
      ad: 'header v1',
      pt: 'Hello, AEGIS-256! & <friends>',
    });
  });

  it('omits empty ad/pt from the link', () => {
    const query = buildShareQuery({ key: KEY, nonce: NONCE, ad: '', pt: '' });
    expect(query).not.toContain('ad=');
    expect(query).not.toContain('pt=');
  });

  it('drops malformed key or nonce instead of propagating bad hex', () => {
    const parsed = parseShareQuery('?key=nothex&nonce=deadbeef&pt=hi');
    expect(parsed.key).toBeUndefined();
    expect(parsed.nonce).toBeUndefined();
    expect(parsed.pt).toBe('hi');
  });

  it('normalizes uppercase hex', () => {
    const parsed = parseShareQuery(`?key=${KEY.toUpperCase()}`);
    expect(parsed.key).toBe(KEY);
  });

  it('returns an empty object for an empty query', () => {
    expect(parseShareQuery('')).toEqual({});
  });
});
