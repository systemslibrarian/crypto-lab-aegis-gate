import { expect, test, type Page } from '@playwright/test';

/**
 * Claims gate. The a11y suite proves the page is reachable; this suite proves
 * the page is *right*. Every headline verdict, counter, and failure path the
 * README advertises is driven in a real browser and asserted against numbers
 * the page itself computed — never against a string this file also hardcodes,
 * except where the string IS the claim (e.g. "TAMPER DETECTED").
 */

// Fixed scenario so every run exercises the same bytes.
const KEY = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const NONCE = '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f';
const PLAINTEXT = 'Hello, AEGIS-256!';
/** First 16-byte block of PLAINTEXT — the block Exhibit 2 encrypts. */
const FIRST_BLOCK = 'Hello, AEGIS-256';

function hexToBytes(hex: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    out.push(Number.parseInt(hex.slice(i, i + 2), 16));
  }
  return out;
}

function utf8ToBytes(text: string): number[] {
  return Array.from(new TextEncoder().encode(text));
}

function xorHex(aHex: string, b: number[]): string {
  const a = hexToBytes(aHex);
  return a
    .map((byte, i) => (byte ^ (b[i] ?? 0)).toString(16).padStart(2, '0'))
    .join('');
}

/** Pull the first integer out of a phrase. */
function firstInt(text: string | null): number {
  const match = /(-?\d+)/.exec(text ?? '');
  expect(match, `expected a number in ${JSON.stringify(text)}`).not.toBeNull();
  return Number(match![1]);
}

/** Read the count the page rendered in a hex-diff label: "(13 bytes differ)". */
async function diffCount(page: Page, selector: string): Promise<number> {
  const label = await page.locator(`${selector} .hexdiff-label`).textContent();
  const match = /\((\d+) bytes? differ\)/.exec(label ?? '');
  expect(match, `no diff count in ${JSON.stringify(label)}`).not.toBeNull();
  return Number(match![1]);
}

async function loadScenario(page: Page): Promise<void> {
  await page.goto('.');
  await page.locator('#key-input').fill(KEY);
  await page.locator('#nonce-input').fill(NONCE);
  await page.locator('#ad-input').fill('');
  await page.locator('#pt-input').fill(PLAINTEXT);
}

// --- The headline verdict: live conformance against the draft vectors -----

test('conformance badge passes and its counters are internally consistent', async ({ page }) => {
  await page.goto('.');

  const badge = page.locator('.conformance-badge');
  await expect(badge).toHaveText('PASS');
  await expect(badge).toHaveAttribute('data-state', 'pass');
  await expect(page.locator('#conformance')).toHaveAttribute('data-state', 'pass');

  const summary = (await page.locator('.conformance-text').textContent()) ?? '';
  // "P/T official draft vectors conform - E encryptions ..., F forgeries rejected."
  const counts = /(\d+)\/(\d+) official draft vectors conform - (\d+) encryptions [^,]+, (\d+) forgeries rejected/.exec(
    summary,
  );
  expect(counts, `unparseable conformance summary: ${summary}`).not.toBeNull();
  const [passed, total, encryptions, forgeries] = counts!.slice(1).map(Number);

  // A "PASS" badge must mean every vector passed, and the parts must sum to
  // the whole the badge is claiming.
  expect(passed).toBe(total);
  expect(encryptions + forgeries).toBe(total);
  expect(total).toBeGreaterThan(0);

  // ... and the tables must actually contain that many vectors.
  await page.locator('#conformance-details-btn').click();
  await expect(page.locator('#conformance-details')).toBeVisible();
  await expect(page.locator('#conformance-encrypt-body tr')).toHaveCount(encryptions);
  await expect(page.locator('#conformance-reject-body tr')).toHaveCount(forgeries);
});

test('every conformance cell is a match and none is a mismatch', async ({ page }) => {
  await page.goto('.');
  await page.locator('#conformance-details-btn').click();

  const encryptRows = await page.locator('#conformance-encrypt-body tr').count();
  const rejectRows = await page.locator('#conformance-reject-body tr').count();

  // Four checks per encryption vector (ciphertext, 128-bit tag, 256-bit tag,
  // round-trip) and two per forgery vector (rejected at both tag lengths).
  const expectedChecks = encryptRows * 4 + rejectRows * 2;
  await expect(page.locator('#conformance-details span.ok')).toHaveCount(expectedChecks);
  await expect(page.locator('#conformance-details span.fail')).toHaveCount(0);
});

// --- Exhibit 1: encrypt / decrypt / tamper --------------------------------

test('encrypt then decrypt returns the exact plaintext at both tag lengths', async ({ page }) => {
  await loadScenario(page);

  for (const [value, tagHexChars] of [
    ['16', 32],
    ['32', 64],
  ] as const) {
    await page.locator('#tag-length').selectOption(value);
    await page.locator('#encrypt-btn').click();

    const ct = (await page.locator('#ct-output').inputValue()).trim();
    const tag = (await page.locator('#tag-output').inputValue()).trim();

    // Ciphertext is the same length as the plaintext (AEAD, not a block mode
    // that pads), and the tag is exactly the length the selector asked for.
    expect(ct).toMatch(/^[0-9a-f]+$/);
    expect(ct.length).toBe(utf8ToBytes(PLAINTEXT).length * 2);
    expect(tag).toMatch(/^[0-9a-f]+$/);
    expect(tag.length).toBe(tagHexChars);

    await page.locator('#decrypt-btn').click();
    await expect(page.locator('#decrypt-status')).toHaveText(`Decrypt OK: ${PLAINTEXT}`);
  }
});

test('Exhibit 1 ciphertext equals the state machine own C = P xor Z', async ({ page }) => {
  await loadScenario(page);
  await page.locator('#encrypt-btn').click();
  const ct = (await page.locator('#ct-output').inputValue()).trim();

  // Exhibit 2 runs the same primitives by hand. With empty AD, one Init plus
  // one Enc must reproduce Exhibit 1's first ciphertext block — two
  // independent paths through the page agreeing byte for byte.
  await page.locator('#sm-init').click();
  await expect(page.locator('#state-hexagon .state-card')).toHaveCount(6);
  await expect(page.locator('#keystream-strip')).toBeVisible();

  await page.locator('#sm-encrypt').click();
  const log = (await page.locator('#state-log').textContent()) ?? '';
  const z = /Z \(from pre-update state\): ([0-9a-f]{32})/.exec(log);
  const cipherBlock = /cipher block:\s+([0-9a-f]{32})/.exec(log);
  expect(z, `no keystream in state log: ${log}`).not.toBeNull();
  expect(cipherBlock, `no cipher block in state log: ${log}`).not.toBeNull();

  // The page prints Z and C; C must actually be P xor Z.
  expect(xorHex(z![1], utf8ToBytes(FIRST_BLOCK))).toBe(cipherBlock![1]);
  // ... and that block must be the first block of Exhibit 1's ciphertext.
  expect(ct.slice(0, 32)).toBe(cipherBlock![1]);
});

test('a flipped ciphertext bit is rejected and avalanches the recomputed tag', async ({ page }) => {
  await loadScenario(page);
  await page.locator('#encrypt-btn').click();
  const before = (await page.locator('#ct-output').inputValue()).trim();

  await page.locator('#tamper-ct-btn').click();
  const after = (await page.locator('#ct-output').inputValue()).trim();
  expect(after).not.toBe(before);
  expect(after.length).toBe(before.length);

  // The page says where the tamper landed; exactly one byte may differ.
  await expect(page.locator('#ct-diff')).toBeVisible();
  expect(await diffCount(page, '#ct-diff')).toBe(1);
  const bytesDiffering = hexToBytes(before).filter((b, i) => b !== hexToBytes(after)[i]).length;
  expect(bytesDiffering).toBe(1);

  await page.locator('#decrypt-btn').click();
  const status = (await page.locator('#decrypt-status').textContent()) ?? '';
  expect(status).toContain('TAMPER DETECTED');
  expect(status).toContain('tag mismatch');

  // One flipped ciphertext bit must change (almost) the whole tag — the
  // avalanche claim the README and the exhibit both make.
  await expect(page.locator('#tag-compare')).toBeVisible();
  const tagBytesDiffering = await diffCount(page, '#tag-compare');
  expect(tagBytesDiffering).toBeGreaterThanOrEqual(12);
  expect(tagBytesDiffering).toBeLessThanOrEqual(16);
  // The status must quote the same count the diff rendered, not a guess.
  expect(status).toContain(`${tagBytesDiffering} of 16 bytes`);
  await expect(page.locator('#why-avalanche')).toBeVisible();
});

test('a flipped tag bit is rejected and reports exactly the one byte altered', async ({ page }) => {
  await loadScenario(page);
  await page.locator('#encrypt-btn').click();
  const before = (await page.locator('#tag-output').inputValue()).trim();

  await page.locator('#tamper-tag-btn').click();
  const after = (await page.locator('#tag-output').inputValue()).trim();
  expect(after).not.toBe(before);
  await expect(page.locator('#tag-diff')).toBeVisible();
  expect(await diffCount(page, '#tag-diff')).toBe(1);

  await page.locator('#decrypt-btn').click();
  const status = (await page.locator('#decrypt-status').textContent()) ?? '';
  expect(status).toContain('TAMPER DETECTED');

  // Tampering the TAG leaves the ciphertext intact, so the recomputed tag is
  // the original one and differs in exactly the byte that was flipped. The
  // page must say that rather than repeating the avalanche story.
  const differing = await diffCount(page, '#tag-compare');
  expect(differing).toBe(1);
  expect(status).toContain('1 of 16 bytes');
  expect(status).toContain('still recomputes to the original tag');
  // The avalanche story does not apply here and must not be told.
  expect(status).not.toContain('every byte');
  expect(status).not.toContain('avalanche');
  await expect(page.locator('#why-avalanche')).toBeHidden();
});

test('decrypting a truncated ciphertext is rejected, not silently accepted', async ({ page }) => {
  await loadScenario(page);
  await page.locator('#encrypt-btn').click();
  const ct = (await page.locator('#ct-output').inputValue()).trim();
  // The field is readonly by design, so drop the last byte the way a hostile
  // network would rather than the way the UI allows.
  await page
    .locator('#ct-output')
    .evaluate((el, value) => {
      (el as HTMLTextAreaElement).value = value;
    }, ct.slice(0, ct.length - 2));

  await page.locator('#decrypt-btn').click();
  await expect(page.locator('#decrypt-status')).toContainText('TAMPER DETECTED');
});

test('a malformed key is refused with a reason instead of a bogus ciphertext', async ({ page }) => {
  await loadScenario(page);
  await page.locator('#key-input').fill('00ff');
  await page.locator('#encrypt-btn').click();
  await expect(page.locator('#decrypt-status')).toContainText('32 bytes');
  await expect(page.locator('#decrypt-status')).toContainText('Error');
});

// --- Exhibit 2: avalanche and the AES round --------------------------------

test('avalanche trace starts at one bit and reaches ~half the state', async ({ page }) => {
  await loadScenario(page);
  await page.locator('#avalanche-btn').click();
  await expect(page.locator('#avalanche-result')).toBeVisible();

  const rows = page.locator('#avalanche-table tbody tr');
  // Seed state plus the draft's 16 initialization updates.
  await expect(rows).toHaveCount(17);

  const totals: number[] = [];
  const count = await rows.count();
  for (let i = 0; i < count; i += 1) {
    const cells = rows.nth(i).locator('td');
    const values = (await cells.allTextContents()).map((t) => t.trim());
    const perBlock = values.slice(0, 6).map(Number);
    const total = firstInt(values[6]);
    // Parts sum to the whole: the six per-block counts must equal the total.
    expect(perBlock.reduce((a, b) => a + b, 0)).toBe(total);
    // And the cell must render exactly that total and its percentage of 768.
    expect(values[6]).toBe(`${total} (${((total / 768) * 100).toFixed(1)}%)`);
    totals.push(total);
  }

  // One flipped nonce bit is one differing state bit at the seed...
  expect(totals[0]).toBe(1);
  // ... and full diffusion (~50% of 768) by the end of initialization.
  expect(totals[totals.length - 1]).toBeGreaterThan(768 * 0.4);
  expect(totals[totals.length - 1]).toBeLessThan(768 * 0.6);

  const log = (await page.locator('#avalanche-log').textContent()) ?? '';
  expect(log).toContain('differ by exactly 1 bit');
  expect(log).toContain('768');
});

test('the AES round stepper counts surviving bytes correctly', async ({ page }) => {
  await page.goto('.');
  await page.locator('#aesround-panel summary').click();
  await expect(page.locator('#ar-grids')).toBeVisible();

  // One grid before stepping: the untouched input block.
  await expect(page.locator('#ar-grids .ar-grid')).toHaveCount(1);
  for (let i = 0; i < 4; i += 1) {
    await page.locator('#ar-step').click();
  }
  // Input plus SubBytes, ShiftRows, MixColumns, round-key XOR.
  await expect(page.locator('#ar-grids .ar-grid')).toHaveCount(5);

  const label = (await page.locator('#ar-stage-label').textContent()) ?? '';
  expect(label).toContain('Stage 4 of 4');
  const claimed = Number(/(\d+) of 16 bytes still match/.exec(label)![1]);

  const grids = page.locator('#ar-grids .ar-grid');
  const input = await grids.nth(0).locator('.ar-cell').allTextContents();
  const output = await grids.nth(4).locator('.ar-cell').allTextContents();
  expect(input).toHaveLength(16);
  expect(output).toHaveLength(16);
  const surviving = input.filter((cell, i) => cell === output[i]).length;

  // The counter must match the grids it is describing...
  expect(surviving).toBe(claimed);
  // ... and one AES round really does scatter essentially everything.
  expect(surviving).toBeLessThanOrEqual(3);
});

// --- Exhibit 3: the nonce-reuse catastrophe -------------------------------

test('reused nonces leak the guaranteed prefix and recover the secret', async ({ page }) => {
  await page.goto('.');
  // Messages that diverge in their FIRST block, so the leak stops at the two
  // blocks AEGIS guarantees and a genuine garbage tail exists to check.
  const secret = 'BRAVO: hold at 1800 by the south gate then wait.';
  await page.locator('#nr-pt-a').fill('ALPHA: move at 0600 to the north gate now, go.');
  await page.locator('#nr-pt-b').fill(secret);

  await page.locator('#nr-reuse-btn').click();
  await expect(page.locator('#nr-output')).toBeVisible();

  const verdict = page.locator('#nr-verdict');
  await expect(verdict).toHaveClass(/danger/);
  const verdictText = (await verdict.textContent()) ?? '';
  expect(verdictText).toContain('KEYSTREAM CANCELLED');
  const leaked = firstInt(verdictText);

  // AEGIS folds plaintext into S0 only, and it takes two Updates for that to
  // reach the keystream taps, so the first two blocks always leak. These two
  // messages diverge immediately, so the leak should stop right about there.
  expect(leaked).toBeGreaterThanOrEqual(32);
  expect(leaked).toBeLessThan(Math.min(secret.length, 46));

  // The same nonce was genuinely reused.
  const nonceA = (await page.locator('#nr-nonce-a').textContent()) ?? '';
  const nonceB = (await page.locator('#nr-nonce-b').textContent()) ?? '';
  expect(nonceB).toContain('(SAME nonce!)');
  expect(nonceB.trim().startsWith(nonceA.trim())).toBe(true);

  // The claim IS C_A xor C_B = P_A xor P_B over the leaked run — check the two
  // hex rows the page printed agree over exactly that many bytes and no more.
  const xorCt = ((await page.locator('#nr-xor-ct').textContent()) ?? '').trim();
  const xorPt = ((await page.locator('#nr-xor-pt').textContent()) ?? '').trim();
  expect(xorCt.slice(0, leaked * 2)).toBe(xorPt.slice(0, leaked * 2));
  expect(xorCt.slice(leaked * 2, leaked * 2 + 2)).not.toBe(xorPt.slice(leaked * 2, leaked * 2 + 2));

  // And the highlighted run really is the secret, recovered without the key.
  const recovered = (await page.locator('#nr-recovered mark').textContent()) ?? '';
  expect(recovered).toBe(secret.slice(0, leaked));
  expect(recovered).toContain('BRAVO: hold at 1800');

  // Past the leaked run the "recovery" must be shown as garbage, not as more
  // recovered plaintext — the honest half of the exhibit.
  const garbage = (await page.locator('#nr-recovered .nr-garbage').textContent()) ?? '';
  expect(garbage.length).toBe(Math.min(secret.length, 46) - leaked);
  expect(garbage).not.toBe(secret.slice(leaked));

  await expect(page.locator('#nr-log')).toContainText(`${leaked} leading bytes`);
  await expect(page.locator('#nr-hint')).toContainText('32 bytes leak for ANY two messages');
});

test('a shared plaintext prefix extends the leak past the guaranteed two blocks', async ({ page }) => {
  await page.goto('.');
  // The page's own defaults share a full 16-byte first block. The exhibit
  // claims the leak runs "plus any shared prefix" — check that it really does.
  const secret = (await page.locator('#nr-pt-b').inputValue()).trim();
  const known = (await page.locator('#nr-pt-a').inputValue()).trim();
  expect(known.slice(0, 16)).toBe(secret.slice(0, 16));

  await page.locator('#nr-reuse-btn').click();
  const leaked = firstInt((await page.locator('#nr-verdict').textContent()) ?? '');
  expect(leaked).toBeGreaterThan(32);

  const recovered = (await page.locator('#nr-recovered mark').textContent()) ?? '';
  expect(recovered).toBe(secret.slice(0, leaked));
});

test('fresh nonces leak nothing and say so from the measured run', async ({ page }) => {
  await page.goto('.');
  await page.locator('#nr-fresh-btn').click();
  await expect(page.locator('#nr-output')).toBeVisible();

  const verdict = page.locator('#nr-verdict');
  await expect(verdict).toHaveClass(/ok/);
  const verdictText = (await verdict.textContent()) ?? '';
  expect(verdictText).toContain('FRESH NONCES');

  // The leaked-run figure must be the measured one, and it must be far below
  // the 32 bytes that reuse guarantees.
  const leaked = firstInt(verdictText);
  expect(leaked).toBeLessThan(16);

  const nonceA = ((await page.locator('#nr-nonce-a').textContent()) ?? '').trim();
  const nonceB = ((await page.locator('#nr-nonce-b').textContent()) ?? '').trim();
  expect(nonceB).toContain('(fresh)');
  expect(nonceB.startsWith(nonceA)).toBe(false);

  const xorCt = ((await page.locator('#nr-xor-ct').textContent()) ?? '').trim();
  const xorPt = ((await page.locator('#nr-xor-pt').textContent()) ?? '').trim();
  expect(xorCt).not.toBe(xorPt);
});

// --- Exhibit 4: the birthday bound ----------------------------------------

test('birthday explorer shows the 96-bit vs 256-bit nonce gap', async ({ page }) => {
  await page.goto('.');
  const slider = page.locator('#bd-slider');
  const output = page.locator('#bd-output');

  const readLines = async (): Promise<{ bits96: string; bits256: string }> => {
    const text = (await output.textContent()) ?? '';
    const lines = text.split('\n');
    return {
      bits96: lines.find((l) => l.includes('96-bit')) ?? '',
      bits256: lines.find((l) => l.includes('256-bit')) ?? '',
    };
  };

  await slider.fill('0');
  await slider.dispatchEvent('input');
  await expect(page.locator('#bd-exp')).toHaveText('0');
  expect((await readLines()).bits96).toContain('a single message cannot collide');

  // At 2^64 messages 96-bit nonces have certainly collided while 256-bit
  // nonces are still astronomically safe. That gap is the whole exhibit.
  await slider.fill('64');
  await slider.dispatchEvent('input');
  await expect(page.locator('#bd-exp')).toHaveText('64');
  const wide = await readLines();
  expect(wide.bits96).toContain('100.0%');
  const exp256 = Number(/~2\^(-?\d+)/.exec(wide.bits256)![1]);
  expect(exp256).toBeLessThan(-100);

  // Probability must rise with message count, never fall.
  await slider.fill('32');
  await slider.dispatchEvent('input');
  const mid = await readLines();
  const exp96Mid = Number(/~2\^(-?\d+)/.exec(mid.bits96)![1]);
  const exp256Mid = Number(/~2\^(-?\d+)/.exec(mid.bits256)![1]);
  expect(exp96Mid).toBeLessThan(0);
  expect(exp96Mid).toBeGreaterThan(exp256Mid);
  // 256 - 96 = 160 bits of headroom, exactly.
  expect(exp256Mid - exp96Mid).toBeCloseTo(-160, 0);
});

// --- Exhibit 5: the benchmark ---------------------------------------------

test('benchmark reports one row per size and a tally that sums', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('.');
  await page.locator('#benchmark-btn').click();

  const log = page.locator('#benchmark-log');
  await expect(log).toContainText('Measured winners on this run', { timeout: 150_000 });
  const text = (await log.textContent()) ?? '';

  const sizeLines = text.split('\n').filter((l) => /^\d+ KB: AEGIS /.test(l));
  expect(sizeLines).toHaveLength(4);
  // Every measurement must be a real, positive throughput.
  for (const line of sizeLines) {
    const nums = [...line.matchAll(/([\d.]+) MB\/s/g)].map((m) => Number(m[1]));
    expect(nums).toHaveLength(2);
    for (const n of nums) {
      expect(n).toBeGreaterThan(0);
      expect(Number.isFinite(n)).toBe(true);
    }
  }

  // The chart must draw what the log reported.
  await expect(page.locator('#benchmark-chart .bar-row')).toHaveCount(sizeLines.length);

  // Winner tally: the parts must sum to the number of sizes measured.
  const tally = /AES-GCM (\d+)\/(\d+) sizes; AEGIS (\d+)\/\d+; ties (\d+)/.exec(text);
  expect(tally, `unparseable benchmark summary: ${text}`).not.toBeNull();
  const [gcmWins, sizes, aegisWins, ties] = tally!.slice(1).map(Number);
  expect(sizes).toBe(sizeLines.length);
  expect(gcmWins + aegisWins + ties).toBe(sizes);
});

// --- Shareable scenarios ---------------------------------------------------

test('a shared link restores the exact scenario', async ({ page }) => {
  const params = new URLSearchParams({ key: KEY, nonce: NONCE, ad: 'hdr-42', pt: 'shared state' });
  await page.goto(`?${params.toString()}`);

  await expect(page.locator('#key-input')).toHaveValue(KEY);
  await expect(page.locator('#nonce-input')).toHaveValue(NONCE);
  await expect(page.locator('#ad-input')).toHaveValue('hdr-42');
  await expect(page.locator('#pt-input')).toHaveValue('shared state');
  await expect(page.locator('#decrypt-status')).toContainText('Scenario loaded from shared link');

  // A malformed key in the link must fall back to a fresh random key rather
  // than loading a broken scenario.
  await page.goto('?key=nothex&nonce=alsonothex');
  const key = await page.locator('#key-input').inputValue();
  expect(key).toMatch(/^[0-9a-f]{64}$/);
  expect(key).not.toBe('nothex');
});
