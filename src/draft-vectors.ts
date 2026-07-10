/**
 * Official AEGIS-256 test vectors from draft-irtf-cfrg-aegis-aead-18,
 * Appendix A.2. These are public, non-secret values whose only purpose is
 * conformance testing — the demo replays them in the browser so a visitor
 * can watch this implementation reproduce the draft's bytes exactly.
 *
 * Kept in sync with test/vectors/aegis-256-test-vectors.json by
 * test/draft-vectors.test.ts.
 */
export interface DraftVector {
  name: string;
  /** 32-byte key, hex. */
  key: string;
  /** 32-byte nonce, hex. */
  nonce: string;
  /** Associated data, hex (may be empty). */
  ad: string;
  /** Plaintext, hex (may be empty). */
  msg: string;
  /** Expected ciphertext, hex. */
  ct: string;
  /** Expected 128-bit tag, hex. */
  tag128: string;
  /** Expected 256-bit tag, hex. */
  tag256: string;
}

export const DRAFT_VECTORS: readonly DraftVector[] = [
  {
    name: 'Test Vector 1',
    key: '1001000000000000000000000000000000000000000000000000000000000000',
    nonce: '1000020000000000000000000000000000000000000000000000000000000000',
    ad: '',
    msg: '00000000000000000000000000000000',
    ct: '754fc3d8c973246dcc6d741412a4b236',
    tag128: '3fe91994768b332ed7f570a19ec5896e',
    tag256: '1181a1d18091082bf0266f66297d167d2e68b845f61a3b0527d31fc7b7b89f13',
  },
  {
    name: 'Test Vector 2',
    key: '1001000000000000000000000000000000000000000000000000000000000000',
    nonce: '1000020000000000000000000000000000000000000000000000000000000000',
    ad: '',
    msg: '',
    ct: '',
    tag128: 'e3def978a0f054afd1e761d7553afba3',
    tag256: '6a348c930adbd654896e1666aad67de989ea75ebaa2b82fb588977b1ffec864a',
  },
  {
    name: 'Test Vector 3',
    key: '1001000000000000000000000000000000000000000000000000000000000000',
    nonce: '1000020000000000000000000000000000000000000000000000000000000000',
    ad: '0001020304050607',
    msg: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    ct: 'f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711',
    tag128: '8d86f91ee606e9ff26a01b64ccbdd91d',
    tag256: 'b7d28d0c3c0ebd409fd22b44160503073a547412da0854bfb9723020dab8da1a',
  },
  {
    name: 'Test Vector 4',
    key: '1001000000000000000000000000000000000000000000000000000000000000',
    nonce: '1000020000000000000000000000000000000000000000000000000000000000',
    ad: '0001020304050607',
    msg: '000102030405060708090a0b0c0d',
    ct: 'f373079ed84b2709faee37358458',
    tag128: 'c60b9c2d33ceb058f96e6dd03c215652',
    tag256: '8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9',
  },
  {
    name: 'Test Vector 5',
    key: '1001000000000000000000000000000000000000000000000000000000000000',
    nonce: '1000020000000000000000000000000000000000000000000000000000000000',
    ad: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829',
    msg: '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637',
    ct: '57754a7d09963e7c787583a2e7b859bb24fa1e04d49fd550b2511a358e3bca252a9b1b8b30cc4a67',
    tag128: 'ab8a7d53fd0e98d727accca94925e128',
    tag256: 'a3aca270c006094d71c20e6910b5161c0826df233d08919a566ec2c05990f734',
  },
] as const;

/**
 * Official must-reject vectors from draft-irtf-cfrg-aegis-aead-18,
 * Appendix A.2 (Test Vectors 6-9): a swapped key/nonce, a flipped
 * ciphertext bit, altered AD, and a flipped tag bit. A conformant
 * implementation must refuse to decrypt every one of them.
 *
 * Kept in sync with test/vectors/aegis-256-test-vectors.json by
 * test/conformance.test.ts.
 */
export interface RejectionVector {
  name: string;
  /** What the vector tampers with, for display. */
  tampered: string;
  key: string;
  nonce: string;
  ad: string;
  ct: string;
  tag128: string;
  tag256: string;
}

export const REJECTION_VECTORS: readonly RejectionVector[] = [
  {
    name: 'Test Vector 6',
    tampered: 'key and nonce swapped',
    key: '1000020000000000000000000000000000000000000000000000000000000000',
    nonce: '1001000000000000000000000000000000000000000000000000000000000000',
    ad: '0001020304050607',
    ct: 'f373079ed84b2709faee37358458',
    tag128: 'c60b9c2d33ceb058f96e6dd03c215652',
    tag256: '8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9',
  },
  {
    name: 'Test Vector 7',
    tampered: 'ciphertext altered',
    key: '1001000000000000000000000000000000000000000000000000000000000000',
    nonce: '1000020000000000000000000000000000000000000000000000000000000000',
    ad: '0001020304050607',
    ct: 'f373079ed84b2709faee37358459',
    tag128: 'c60b9c2d33ceb058f96e6dd03c215652',
    tag256: '8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9',
  },
  {
    name: 'Test Vector 8',
    tampered: 'associated data altered',
    key: '1001000000000000000000000000000000000000000000000000000000000000',
    nonce: '1000020000000000000000000000000000000000000000000000000000000000',
    ad: '0001020304050608',
    ct: 'f373079ed84b2709faee37358458',
    tag128: 'c60b9c2d33ceb058f96e6dd03c215652',
    tag256: '8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9',
  },
  {
    name: 'Test Vector 9',
    tampered: 'tag altered',
    key: '1001000000000000000000000000000000000000000000000000000000000000',
    nonce: '1000020000000000000000000000000000000000000000000000000000000000',
    ad: '0001020304050607',
    ct: 'f373079ed84b2709faee37358458',
    tag128: 'c60b9c2d33ceb058f96e6dd03c215653',
    tag256: '8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2da',
  },
] as const;

export interface ConformanceRow {
  name: string;
  ctOk: boolean;
  tag128Ok: boolean;
  tag256Ok: boolean;
  /** Decrypt returns the original plaintext for both tag lengths. */
  roundTripOk: boolean;
  pass: boolean;
}

export interface RejectionRow {
  name: string;
  tampered: string;
  /** Decrypt refused the forgery with a 128-bit tag. */
  rejected128: boolean;
  /** Decrypt refused the forgery with a 256-bit tag. */
  rejected256: boolean;
  pass: boolean;
}

export interface ConformanceReport {
  rows: ConformanceRow[];
  rejections: RejectionRow[];
  passed: number;
  total: number;
  allPass: boolean;
}
