import { describe, expect, it } from 'vitest';

import { runComparison, summarizeComparison, type BenchmarkResult, type ComparisonResult } from '../src/benchmark';

function row(throughputMBps: number): BenchmarkResult {
  return { algorithm: 'test', messageSizeBytes: 1, throughputMBps, timeMs: 1, iterations: 1 };
}

describe('benchmark', () => {
  it('runs 1KB, 16KB, 256KB, and 1MB comparisons without errors', async () => {
    const results = await runComparison();

    expect(results.messageSizes).toEqual([1024, 16 * 1024, 256 * 1024, 1024 * 1024]);
    expect(results.aegis256).toHaveLength(4);
    expect(results.aesGcm).toHaveLength(4);

    for (const row of [...results.aegis256, ...results.aesGcm]) {
      expect(row.timeMs).toBeGreaterThan(0);
      expect(row.throughputMBps).toBeGreaterThan(0);
    }
  }, 120000);
});

describe('benchmark conclusion', () => {
  it('counts winners from the measured rows instead of declaring one in advance', () => {
    const result: ComparisonResult = {
      messageSizes: [1, 2, 3, 4],
      aegis256: [row(20), row(5), row(7), row(9)],
      aesGcm: [row(10), row(8), row(7), row(10)],
    };
    const summary = summarizeComparison(result);
    expect(summary).toContain('AES-GCM 2/4 sizes; AEGIS 1/4; ties 1');
    expect(summary).toContain('platform-specific');
  });
});
