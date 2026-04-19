import { aegis256Encrypt } from './aegis';
import { randomBytes } from './bytes';

/**
 * Benchmark AEGIS-256 encryption throughput.
 * Measures MB/s for various message sizes.
 */
export interface BenchmarkResult {
  algorithm: string;
  messageSizeBytes: number;
  throughputMBps: number;
  timeMs: number;
  iterations: number;
}

function nowMs(): number {
  return performance.now();
}

function toCryptoBytes(bytes: Uint8Array): Uint8Array {
  return Uint8Array.from(bytes);
}

function requestIdleYield(): Promise<void> {
  if ('requestIdleCallback' in globalThis) {
    return new Promise((resolve) => {
      (globalThis as unknown as { requestIdleCallback: (cb: () => void) => void }).requestIdleCallback(
        () => resolve(),
      );
    });
  }
  return new Promise((resolve) => setTimeout(resolve, 0));
}

/**
 * Run AEGIS-256 throughput benchmark.
 * Encrypts random data of the specified size N times, measures total time.
 */
export async function benchmarkAegis256(
  messageSize: number,
  iterations: number,
): Promise<BenchmarkResult> {
  const key = randomBytes(32);
  const nonce = randomBytes(32);
  const ad = new Uint8Array(0);
  const plaintext = randomBytes(messageSize);

  const start = nowMs();
  for (let i = 0; i < iterations; i += 1) {
    aegis256Encrypt(key, nonce, ad, plaintext);
    if ((i + 1) % 20 === 0) {
      await requestIdleYield();
    }
  }
  const timeMs = nowMs() - start;

  const totalBytes = messageSize * iterations;
  const throughputMBps = (totalBytes / (1024 * 1024)) / (timeMs / 1000);

  return {
    algorithm: 'AEGIS-256 (TypeScript)',
    messageSizeBytes: messageSize,
    throughputMBps,
    timeMs,
    iterations,
  };
}

/**
 * Compare against browser's Web Crypto AES-GCM (same key size).
 */
export async function benchmarkAesGcm(
  messageSize: number,
  iterations: number,
): Promise<BenchmarkResult> {
  const keyBytes = randomBytes(32);
  const key = await crypto.subtle.importKey(
    'raw',
    toCryptoBytes(keyBytes) as BufferSource,
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  );
  const plaintext = toCryptoBytes(randomBytes(messageSize));

  const start = nowMs();
  for (let i = 0; i < iterations; i += 1) {
    const iv = toCryptoBytes(randomBytes(12));
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv as BufferSource },
      key,
      plaintext as BufferSource,
    );
    if ((i + 1) % 20 === 0) {
      await requestIdleYield();
    }
  }
  const timeMs = nowMs() - start;

  const totalBytes = messageSize * iterations;
  const throughputMBps = (totalBytes / (1024 * 1024)) / (timeMs / 1000);

  return {
    algorithm: 'AES-256-GCM (Web Crypto)',
    messageSizeBytes: messageSize,
    throughputMBps,
    timeMs,
    iterations,
  };
}

/**
 * Return side-by-side comparison for UI display.
 */
export async function runComparison(): Promise<{
  aegis256: BenchmarkResult[];
  aesGcm: BenchmarkResult[];
  messageSizes: number[];
}> {
  const messageSizes = [1024, 16 * 1024, 256 * 1024, 1024 * 1024];
  const iterationMap = new Map<number, number>([
    [1024, 400],
    [16 * 1024, 200],
    [256 * 1024, 50],
    [1024 * 1024, 20],
  ]);

  const aegis256: BenchmarkResult[] = [];
  const aesGcm: BenchmarkResult[] = [];

  for (const size of messageSizes) {
    const iterations = iterationMap.get(size) ?? 50;
    aegis256.push(await benchmarkAegis256(size, iterations));
    aesGcm.push(await benchmarkAesGcm(size, iterations));
    await requestIdleYield();
  }

  return { aegis256, aesGcm, messageSizes };
}
