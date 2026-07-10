/**
 * AEGIS-256 pseudocode from draft-irtf-cfrg-aegis-aead-18 (lightly
 * compacted for a narrow pane; logic unchanged), with deep links into the
 * draft. The state-machine exhibit renders these beside the live state and
 * highlights whichever function just executed, so a learner watches the
 * spec text and the bytes move together.
 */

export const DRAFT_URL = 'https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead-18';

export type SpecId = 'update' | 'init' | 'absorb' | 'enc' | 'finalize';

export interface SpecSection {
  id: SpecId;
  /** Section number within draft-18. */
  section: string;
  title: string;
  url: string;
  /** Verbatim pseudocode from the draft. */
  code: string;
}

export const SPEC_SECTIONS: readonly SpecSection[] = [
  {
    id: 'update',
    section: '4.3',
    title: 'The Update Function',
    url: `${DRAFT_URL}#section-4.3`,
    code: `Update(M)
  S'0 = AESRound(S5, S0 ^ M)
  S'1 = AESRound(S0, S1)
  S'2 = AESRound(S1, S2)
  S'3 = AESRound(S2, S3)
  S'4 = AESRound(S3, S4)
  S'5 = AESRound(S4, S5)

  S0..S5 = S'0..S'5`,
  },
  {
    id: 'init',
    section: '4.4',
    title: 'The Init Function',
    url: `${DRAFT_URL}#section-4.4`,
    code: `Init(key, nonce)
  k0, k1 = Split(key, 128)
  n0, n1 = Split(nonce, 128)

  S0 = k0 ^ n0
  S1 = k1 ^ n1
  S2 = C1
  S3 = C0
  S4 = k0 ^ C0
  S5 = k1 ^ C1

  Repeat(4,
    Update(k0)
    Update(k1)
    Update(k0 ^ n0)
    Update(k1 ^ n1))`,
  },
  {
    id: 'absorb',
    section: '4.5',
    title: 'The Absorb Function',
    url: `${DRAFT_URL}#section-4.5`,
    code: `Absorb(ai)
  Update(ai)`,
  },
  {
    id: 'enc',
    section: '4.6',
    title: 'The Enc Function',
    url: `${DRAFT_URL}#section-4.6`,
    code: `Enc(xi)
  z = S1 ^ S4 ^ S5 ^ (S2 & S3)
  Update(xi)
  ci = xi ^ z
  return ci`,
  },
  {
    id: 'finalize',
    section: '4.9',
    title: 'The Finalize Function',
    url: `${DRAFT_URL}#section-4.9`,
    code: `Finalize(ad_len_bits, msg_len_bits)
  t = S3 ^ (LE64(ad_len_bits) ||
            LE64(msg_len_bits))
  Repeat(7, Update(t))

  if tag_len_bits == 128:
    tag = S0 ^ S1 ^ S2 ^
          S3 ^ S4 ^ S5
  else:
    tag = (S0 ^ S1 ^ S2) ||
          (S3 ^ S4 ^ S5)
  return tag`,
  },
] as const;
