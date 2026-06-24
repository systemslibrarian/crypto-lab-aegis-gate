import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { runConformance } from '../src/conformance';
import { DRAFT_VECTORS } from '../src/draft-vectors';

interface JsonVector {
  name: string;
  error?: string;
  msg?: string;
  key?: string;
  nonce?: string;
  ad?: string;
  ct?: string;
  tag128?: string;
  tag256?: string;
}

const thisDir = dirname(fileURLToPath(import.meta.url));
const jsonPath = resolve(thisDir, 'vectors/aegis-256-test-vectors.json');
const jsonVectors = JSON.parse(readFileSync(jsonPath, 'utf8')) as JsonVector[];

describe('in-browser conformance harness', () => {
  it('reports all draft vectors passing', () => {
    const report = runConformance();
    expect(report.allPass).toBe(true);
    expect(report.passed).toBe(report.total);
    expect(report.total).toBe(DRAFT_VECTORS.length);
  });

  it('keeps src/draft-vectors.ts byte-identical to the JSON fixture (no drift)', () => {
    // Every shipped vector must match the authoritative test fixture exactly.
    for (const v of DRAFT_VECTORS) {
      const source = jsonVectors.find((j) => j.name === v.name);
      expect(source, `JSON fixture is missing ${v.name}`).toBeTruthy();
      expect({
        key: v.key,
        nonce: v.nonce,
        ad: v.ad,
        msg: v.msg,
        ct: v.ct,
        tag128: v.tag128,
        tag256: v.tag256,
      }).toEqual({
        key: source?.key,
        nonce: source?.nonce,
        ad: source?.ad,
        msg: source?.msg,
        ct: source?.ct,
        tag128: source?.tag128,
        tag256: source?.tag256,
      });
    }
  });

  it('ships every non-failure encryption vector from the fixture', () => {
    const shippableNames = jsonVectors
      .filter((j) => typeof j.msg === 'string' && !j.error)
      .map((j) => j.name)
      .sort();
    const shippedNames = DRAFT_VECTORS.map((v) => v.name).sort();
    expect(shippedNames).toEqual(shippableNames);
  });
});
