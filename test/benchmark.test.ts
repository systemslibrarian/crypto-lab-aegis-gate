import { describe, expect, it } from 'vitest';

import { runComparison } from '../src/benchmark';

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
