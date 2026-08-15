import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';

/**
 * WCAG regression gate. Deploys are already gated on the AEGIS conformance
 * vectors; this gates them on accessibility the same way.
 *
 * Three things this suite deliberately does that a plain "goto then axe" does
 * not, each of them a hole this gate previously had:
 *
 *  1. It scans the page's *states*, not just its first paint. Every panel that
 *     reports a result — the tamper verdict, the state hexagon, the avalanche
 *     heatmap, the nonce-reuse recovery, the benchmark bars — starts `hidden`
 *     or empty. A load-time-only scan checked none of them. The `.chg` badges
 *     in the state hexagon carried a prohibited `aria-label`, and they only
 *     exist after the *second* state render, which is why nothing caught it.
 *
 *  2. It asserts on `incomplete`, not only on `violations`. axe parks a finding
 *     it cannot decide in `incomplete`, where a violations-only assertion never
 *     looks. On this page that bucket held the `aria-label` defect above.
 *
 *  3. It measures contrast arithmetically. axe cannot compute contrast over a
 *     background gradient, and this lab paints the body, every panel and the
 *     hero with one: axe resolved 15 nodes and dropped ~300 into `incomplete`.
 *     Contrast here was, in effect, ungated. `auditContrast` composites the
 *     real painted stack (translucent layers included, gradients judged at
 *     their worst stop) so a ratio is measured against the surface the text is
 *     actually drawn on.
 *
 * Motion is settled through `page.emulateMedia({ reducedMotion: 'reduce' })`,
 * which exercises the stylesheet's real reduced-motion path, plus a poll until
 * nothing is animating. Note that `test.use({ reducedMotion: 'reduce' })` is a
 * silent no-op on Playwright 1.61.1 — the page still reports
 * `matchMedia('(prefers-reduced-motion: reduce)').matches === false` — so the
 * emulation is asserted below and cannot regress into doing nothing.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * The only axe rule allowed to stay undecided. Contrast is covered
 * arithmetically instead, because axe refuses to resolve it over a gradient.
 */
const CONTRAST_HANDLED_ARITHMETICALLY = 'color-contrast';

async function openAllDetails(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const details of document.querySelectorAll('details')) {
      details.open = true;
    }
  });
}

/** Wait until no CSS animation or transition is still running. */
async function settle(page: Page): Promise<void> {
  await page.waitForFunction(() => document.getAnimations().length === 0, undefined, {
    timeout: 5_000,
  });
}

async function scan(page: Page, state: string): Promise<void> {
  await settle(page);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(violations).toEqual([]);

  // Undecided findings are findings. Anything axe could not rule on — other
  // than contrast, which is measured below — has to be looked at.
  const undecided = results.incomplete
    .filter((v) => v.id !== CONTRAST_HANDLED_ARITHMETICALLY)
    .map((v) => ({
      state,
      id: v.id,
      impact: v.impact,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
    }));
  expect(undecided).toEqual([]);

  const contrast = formatContrastFailures(await auditContrast(page)).map((f) => `${state}: ${f}`);
  expect(contrast).toEqual([]);
}

/** Drive the page through every panel that renders a result, scanning each. */
async function scanEveryState(page: Page, theme: string): Promise<void> {
  await openAllDetails(page);
  await scan(page, `${theme}/load`);

  // Exhibit 1: a real encryption, then both tamper paths and the error path.
  await page.locator('#encrypt-btn').click();
  await scan(page, `${theme}/encrypted`);

  await page.locator('#tamper-ct-btn').click();
  await page.locator('#decrypt-btn').click();
  await expect(page.locator('#decrypt-status')).toContainText('TAMPER DETECTED');
  await expect(page.locator('#why-avalanche')).toBeVisible();
  await scan(page, `${theme}/ciphertext-tampered`);

  await page.locator('#tamper-tag-btn').click();
  await page.locator('#decrypt-btn').click();
  await expect(page.locator('#decrypt-status')).toContainText('TAMPER DETECTED');
  await scan(page, `${theme}/tag-tampered`);

  await page.locator('#key-input').fill('00ff');
  await page.locator('#encrypt-btn').click();
  await expect(page.locator('#decrypt-status')).toContainText('Error');
  await scan(page, `${theme}/key-error`);
  await page.locator('#key-input').fill('00'.repeat(32));

  // Exhibit 2: the state hexagon needs two renders before the per-block change
  // badges appear at all, so step it right through Finalize.
  await page.locator('#sm-init').click();
  await page.locator('#ad-input').fill('hdr-42');
  await page.locator('#sm-absorb').click();
  await page.locator('#sm-encrypt').click();
  await expect(page.locator('#state-hexagon .chg')).toHaveCount(6);
  await page.locator('#sm-finalize').click();
  await scan(page, `${theme}/state-machine`);

  // The AES round stepper, at the stage where the changed cells are highlighted.
  for (let i = 0; i < 4; i += 1) {
    await page.locator('#ar-step').click();
  }
  await expect(page.locator('#ar-grids .ar-grid')).toHaveCount(5);
  await expect(page.locator('#ar-grids .ar-cell.ar-hot').first()).toBeVisible();
  await scan(page, `${theme}/aes-round-stage-4`);

  // The avalanche heatmap tints each cell with a computed alpha, so its text
  // sits on a surface no static rule describes.
  await page.locator('#avalanche-btn').click();
  await expect(page.locator('#avalanche-result')).toBeVisible();
  await scan(page, `${theme}/avalanche-heatmap`);

  // Exhibit 3, both verdicts: the danger panel with its recovered/garbage runs,
  // then the ok panel.
  await page.locator('#nr-reuse-btn').click();
  await expect(page.locator('#nr-verdict')).toHaveClass(/danger/);
  await expect(page.locator('#nr-recovered mark')).toBeVisible();
  await scan(page, `${theme}/nonce-reuse-danger`);

  await page.locator('#nr-fresh-btn').click();
  await expect(page.locator('#nr-verdict')).toHaveClass(/ok/);
  await scan(page, `${theme}/nonce-fresh-ok`);

  // The per-vector conformance tables.
  await page.locator('#conformance-details-btn').click();
  await expect(page.locator('#conformance-details')).toBeVisible();
  await scan(page, `${theme}/conformance-details`);
}

test.beforeEach(async ({ page }) => {
  // Real reduced-motion emulation, then proof it took. test.use() for this
  // does nothing on 1.61.1, so the assertion is the guard against silently
  // scanning a page that is still mid-transition.
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');
  const reduced = await page.evaluate(
    () => matchMedia('(prefers-reduced-motion: reduce)').matches,
  );
  expect(reduced, 'reduced-motion emulation silently did nothing').toBe(true);
});

test('no WCAG A/AA violations in dark theme, in every state', async ({ page }) => {
  test.setTimeout(120_000);
  await scanEveryState(page, 'dark');
});


test('the benchmark chart is accessible once it has drawn its bars', async ({ page }) => {
  test.setTimeout(180_000);
  await page.locator('#benchmark-btn').click();
  await expect(page.locator('#benchmark-log')).toContainText('Measured winners on this run', {
    timeout: 150_000,
  });
  await expect(page.locator('#benchmark-chart .bar-row')).toHaveCount(4);
  await scan(page, 'dark/benchmark-bars');
});

test('the stylesheet honours prefers-reduced-motion for every transition', async ({ page }) => {
  // Highlighting the spec pane transitions ten .spec-block borders. Under
  // `reduce` nothing may animate at all: with only the dataflow pulse guarded,
  // these ten kept running and took the best part of a second to drain.
  await page.locator('#sm-init').click();
  expect(await page.evaluate(() => document.getAnimations().length)).toBe(0);
  await page.locator('#sm-encrypt').click();
  expect(await page.evaluate(() => document.getAnimations().length)).toBe(0);
});

test('motion still runs, and still finishes, when it has not been suppressed', async ({ page }) => {
  // The mirror of the test above: with no preference expressed the transitions
  // must genuinely happen (so the gate is not just measuring a dead stylesheet)
  // and must genuinely finish.
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await page.goto('.');
  await page.locator('#sm-init').click();
  expect(await page.evaluate(() => document.getAnimations().length)).toBeGreaterThan(0);
  await settle(page);
});

test('every scrollable result container is reachable by keyboard', async ({ page }) => {
  // A capped or wide container only overflows after the user has produced a
  // result, and at a narrow viewport — which is exactly why a load-time scan
  // never reports it. Anything that scrolls needs a tab stop (WCAG 2.1.1) and
  // a visible focus ring.
  await page.locator('#avalanche-btn').click();
  await expect(page.locator('#avalanche-result')).toBeVisible();
  await page.locator('#nr-reuse-btn').click();
  await page.locator('#conformance-details-btn').click();
  await page.locator('#encrypt-btn').click();
  await openAllDetails(page);

  for (const width of [1280, 900, 380]) {
    await page.setViewportSize({ width, height: 900 });
    const unreachable = await page.evaluate(() => {
      const out: string[] = [];
      for (const el of Array.from(document.querySelectorAll('*'))) {
        const cs = getComputedStyle(el);
        const scrolls =
          (/(auto|scroll)/.test(cs.overflowX) && el.scrollWidth > el.clientWidth + 1) ||
          (/(auto|scroll)/.test(cs.overflowY) && el.scrollHeight > el.clientHeight + 1);
        if (!scrolls) continue;
        if (
          el.hasAttribute('tabindex') ||
          ['A', 'BUTTON', 'INPUT', 'SELECT', 'TEXTAREA'].includes(el.tagName)
        ) {
          continue;
        }
        const cls = el.getAttribute('class');
        out.push(el.tagName.toLowerCase() + (el.id ? `#${el.id}` : '') + (cls ? `.${cls}` : ''));
      }
      return out;
    });
    expect(unreachable, `scrollable but not focusable at ${width}px`).toEqual([]);
  }

  // ... and the tab stop has to be visible when it lands. Press Tab first so
  // Chromium treats the focus that follows as keyboard modality, which is what
  // :focus-visible keys off; a bare programmatic focus() would report no
  // outline even on a page that styles the ring correctly.
  await page.setViewportSize({ width: 380, height: 900 });
  await page.keyboard.press('Tab');
  const wrap = page.locator('.table-wrap').first();
  await wrap.focus();
  const ring = await wrap.evaluate((el) => {
    const cs = getComputedStyle(el);
    return {
      focusVisible: el.matches(':focus-visible'),
      outline: `${cs.outlineStyle} ${cs.outlineWidth}`,
    };
  });
  expect(ring.focusVisible, 'the focused container did not match :focus-visible').toBe(true);
  expect(ring.outline).not.toMatch(/^none/);
  expect(ring.outline).not.toMatch(/ 0px$/);
});
