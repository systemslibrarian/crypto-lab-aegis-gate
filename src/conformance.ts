import { aegis256Decrypt, aegis256Encrypt } from './aegis';
import {
  type ConformanceReport,
  type ConformanceRow,
  DRAFT_VECTORS,
  REJECTION_VECTORS,
  type RejectionRow,
} from './draft-vectors';
import { bytesToHex, hexToBytes } from './bytes';

/**
 * Replay every official draft vector through this implementation in the
 * visitor's browser and report, byte for byte, whether it conforms — so the
 * "verified against official vectors" claim is something they can watch,
 * not just take on faith. Three checks per encryption vector (ciphertext,
 * both tag lengths) plus a decrypt round-trip, and every must-reject
 * forgery vector (draft vectors 6-9) must be refused.
 */
export function runConformance(): ConformanceReport {
  const rows: ConformanceRow[] = DRAFT_VECTORS.map((v) => {
    const key = hexToBytes(v.key);
    const nonce = hexToBytes(v.nonce);
    const ad = hexToBytes(v.ad);
    const msg = hexToBytes(v.msg);

    const tag128 = aegis256Encrypt(key, nonce, ad, msg, 16);
    const tag256 = aegis256Encrypt(key, nonce, ad, msg, 32);

    const ctOk = bytesToHex(tag128.ciphertext) === v.ct;
    const tag128Ok = bytesToHex(tag128.tag) === v.tag128;
    const tag256Ok = bytesToHex(tag256.tag) === v.tag256;

    const rt128 = aegis256Decrypt(key, nonce, ad, tag128.ciphertext, tag128.tag, 16);
    const rt256 = aegis256Decrypt(key, nonce, ad, tag256.ciphertext, tag256.tag, 32);
    const roundTripOk =
      rt128 !== null &&
      rt256 !== null &&
      bytesToHex(rt128) === v.msg &&
      bytesToHex(rt256) === v.msg;

    return {
      name: v.name,
      ctOk,
      tag128Ok,
      tag256Ok,
      roundTripOk,
      pass: ctOk && tag128Ok && tag256Ok && roundTripOk,
    };
  });

  const rejections: RejectionRow[] = REJECTION_VECTORS.map((v) => {
    const key = hexToBytes(v.key);
    const nonce = hexToBytes(v.nonce);
    const ad = hexToBytes(v.ad);
    const ct = hexToBytes(v.ct);

    const rejected128 = aegis256Decrypt(key, nonce, ad, ct, hexToBytes(v.tag128), 16) === null;
    const rejected256 = aegis256Decrypt(key, nonce, ad, ct, hexToBytes(v.tag256), 32) === null;

    return {
      name: v.name,
      tampered: v.tampered,
      rejected128,
      rejected256,
      pass: rejected128 && rejected256,
    };
  });

  const passed = rows.filter((r) => r.pass).length + rejections.filter((r) => r.pass).length;
  const total = rows.length + rejections.length;
  return { rows, rejections, passed, total, allPass: passed === total };
}
