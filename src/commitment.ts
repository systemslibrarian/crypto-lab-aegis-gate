import { absorb, aegis256Decrypt, aegis256Encrypt, initialize, type AegisState, type TagLength } from './aegis';
import { bytesToHex, hexToBytes } from './bytes';
import vector from './commitment-vector.json';

export type CommitmentCase = 'collision' | 'same-ad' | 'tampered-ad';

/** Count differing bits in each of the six real state blocks. */
function differences(a: AegisState, b: AegisState): number[] {
  return a.map((block, i) => block.reduce((sum, value, j) => {
    let x = value ^ b[i][j];
    while (x !== 0) { sum += x & 1; x >>>= 1; }
    return sum;
  }, 0));
}

/** Replay the published known-key collision; the controls change only B's AD. */
export function runCommitment(scenario: CommitmentCase, tagLength: TagLength) {
  const keyA = hexToBytes(vector.keyA);
  const keyB = hexToBytes(vector.keyB);
  const nonce = hexToBytes(vector.nonceA);
  const adA = hexToBytes(vector.adA);
  const adB = hexToBytes(scenario === 'same-ad' ? vector.adA : vector.adB);
  if (scenario === 'tampered-ad') adB[0] ^= 1;
  let stateA = initialize(keyA, nonce);
  let stateB = initialize(keyB, nonce);
  const trace = [{ stage: 'After initialization', bits: differences(stateA, stateB) }];
  for (let i = 0; i < adA.length; i += 16) {
    stateA = absorb(stateA, adA.slice(i, i + 16));
    stateB = absorb(stateB, adB.slice(i, i + 16));
    trace.push({ stage: `After AD block ${i / 16 + 1}`, bits: differences(stateA, stateB) });
  }
  const plaintext = hexToBytes(vector.plaintext);
  // Use the published bytes at 128 bits; generate the 256-bit variant through
  // A's real encryptor. Never manufacture B's verification result from a case ID.
  const published = hexToBytes(vector.ciphertextAndTag128);
  const encryptedA = aegis256Encrypt(keyA, nonce, adA, plaintext, tagLength);
  const ciphertext = tagLength === 16 ? published.slice(0, 16) : encryptedA.ciphertext;
  const tag = tagLength === 16 ? published.slice(16) : encryptedA.tag;
  const encryptedB = aegis256Encrypt(keyB, nonce, adB, plaintext, tagLength);
  const openedA = aegis256Decrypt(keyA, nonce, adA, ciphertext, tag, tagLength);
  const openedB = aegis256Decrypt(keyB, nonce, adB, ciphertext, tag, tagLength);
  const stateEqual = differences(stateA, stateB).every(n => n === 0);
  const acceptedA = openedA !== null;
  const acceptedB = openedB !== null;
  return {
    scenario, tagLength, trace, stateEqual, acceptedA, acceptedB,
    ambiguous: acceptedA && acceptedB && vector.keyA !== vector.keyB,
    keyA: vector.keyA, keyB: vector.keyB, nonce: vector.nonceA,
    adA: vector.adA, adB: bytesToHex(adB), ciphertext: bytesToHex(ciphertext),
    tag: bytesToHex(tag), tagB: bytesToHex(encryptedB.tag),
    ciphertextB: bytesToHex(encryptedB.ciphertext),
    plaintextA: openedA === null ? null : bytesToHex(openedA),
    plaintextB: openedB === null ? null : bytesToHex(openedB),
  };
}
