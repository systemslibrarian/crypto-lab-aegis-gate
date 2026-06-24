import { aegis256Encrypt } from './aegis';
import { type ConformanceReport, type ConformanceRow, DRAFT_VECTORS } from './draft-vectors';
import { bytesToHex, hexToBytes } from './bytes';

/**
 * Replay every official draft vector through this implementation's encrypt
 * path and report, byte for byte, whether the ciphertext and both tag
 * lengths match the draft. Runs entirely in the visitor's browser so the
 * "verified against official vectors" claim is something they can watch,
 * not just take on faith.
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

    return { name: v.name, ctOk, tag128Ok, tag256Ok, pass: ctOk && tag128Ok && tag256Ok };
  });

  const passed = rows.filter((r) => r.pass).length;
  return { rows, passed, total: rows.length, allPass: passed === rows.length };
}
