export function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.trim().toLowerCase();
  if (normalized.length % 2 !== 0) {
    throw new Error('Hex string must have even length');
  }
  // Validate the whole string up front: Number.parseInt('1g', 16) stops at the
  // bad character and silently returns 0x01, so a per-pair NaN check is not
  // enough to reject malformed input like "1g" or "ff0z".
  if (!/^[0-9a-f]*$/.test(normalized)) {
    throw new Error('Invalid hex string');
  }

  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  // Web Crypto limits a single getRandomValues call to 65536 bytes.
  const chunkSize = 65536;
  for (let offset = 0; offset < length; offset += chunkSize) {
    const end = Math.min(offset + chunkSize, length);
    crypto.getRandomValues(out.subarray(offset, end));
  }
  return out;
}

export function utf8ToBytes(input: string): Uint8Array {
  return new TextEncoder().encode(input);
}

export function bytesToUtf8(input: Uint8Array): string {
  return new TextDecoder().decode(input);
}

export function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function splitBlocks(input: Uint8Array, blockSize = 16): Uint8Array[] {
  if (blockSize <= 0) {
    throw new Error('blockSize must be > 0');
  }
  const blocks: Uint8Array[] = [];
  for (let i = 0; i < input.length; i += blockSize) {
    blocks.push(input.slice(i, i + blockSize));
  }
  if (input.length === 0) {
    return [];
  }
  return blocks;
}

export function padBlock(block: Uint8Array, size = 16): Uint8Array {
  const out = new Uint8Array(size);
  out.set(block.slice(0, size));
  return out;
}
