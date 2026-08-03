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

export interface ComparisonResult {
  aegis256: BenchmarkResult[];
  aesGcm: BenchmarkResult[];
  messageSizes: number[];
}

export function summarizeComparison(results: ComparisonResult): string {
  let aegisWins = 0;
  let gcmWins = 0;
  let ties = 0;
  for (let i = 0; i < results.messageSizes.length; i += 1) {
    const a = results.aegis256[i]?.throughputMBps ?? 0;
    const g = results.aesGcm[i]?.throughputMBps ?? 0;
    if (a > g) aegisWins += 1;
    else if (g > a) gcmWins += 1;
    else ties += 1;
  }
  return `Measured winners on this run: AES-GCM ${gcmWins}/${results.messageSizes.length} sizes; AEGIS ${aegisWins}/${results.messageSizes.length}; ties ${ties}. Web Crypto's AES-GCM is native code here while this AEGIS is interpreted TypeScript, so this is an implementation race, not an equal-acceleration algorithm ranking. AEGIS is designed to overlap authentication with AES rounds; GCM uses a separate GHASH operation. The winner with native hardware acceleration is platform-specific and was not measured by this page.`;
}

function nowMs(): number {
  return performance.now();
}

function toCryptoBytes(bytes: Uint8Array): Uint8Array {
  return Uint8Array.from(bytes);
}

/** Longest the benchmark waits for an idle slot before resuming anyway. */
const IDLE_YIELD_TIMEOUT_MS = 50;

/**
 * Yield to the event loop between batches so the UI stays responsive.
 *
 * A bare `requestIdleCallback` is not enough. Chrome services the idle queue
 * only when it has a reason to schedule one (a frame, a timer). A page whose
 * only pending work is this benchmark — a backgrounded tab, or any headless
 * run — can go without an idle period indefinitely and the callback never
 * fires, leaving the exhibit stuck on "Benchmarking..." with no result ever
 * shown. So ask for an idle slot but race it against a plain timer and take
 * whichever arrives first.
 */
function requestIdleYield(): Promise<void> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (): void => {
      if (!settled) {
        settled = true;
        resolve();
      }
    };
    const idle = (
      globalThis as unknown as {
        requestIdleCallback?: (cb: () => void, opts?: { timeout: number }) => void;
      }
    ).requestIdleCallback;
    if (typeof idle === 'function') {
      idle.call(globalThis, finish, { timeout: IDLE_YIELD_TIMEOUT_MS });
    }
    setTimeout(finish, IDLE_YIELD_TIMEOUT_MS);
  });
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
export async function runComparison(): Promise<ComparisonResult> {
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
