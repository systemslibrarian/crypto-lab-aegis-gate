// @vitest-environment happy-dom
import { beforeAll, describe, expect, it } from 'vitest';

/**
 * Smoke test: the page must actually mount. main.ts assigns the app markup
 * and wires every control at module load, so importing it in a DOM proves
 * there are no broken selectors or render-time throws that would blank the
 * whole demo. The in-browser conformance strip must also reach PASS.
 */
describe('app boot', () => {
  beforeAll(async () => {
    document.body.innerHTML = '<div id="app"></div>';
    await import('../src/main');
  });

  it('renders all six exhibits', () => {
    for (let i = 1; i <= 6; i += 1) {
      expect(document.querySelector(`#exhibit-${i}`), `exhibit ${i} missing`).toBeTruthy();
    }
  });

  it('wires the core controls', () => {
    for (const id of [
      '#encrypt-btn',
      '#decrypt-btn',
      '#sm-init',
      '#benchmark-btn',
      '#share-btn',
      '#tag-length',
      '#avalanche-btn',
      '#nr-reuse-btn',
      '#nr-fresh-btn',
      '#bd-slider',
    ]) {
      expect(document.querySelector(id), `${id} missing`).toBeTruthy();
    }
  });

  it('pre-fills a random key and nonce (64 hex chars each)', () => {
    const key = document.querySelector<HTMLTextAreaElement>('#key-input');
    const nonce = document.querySelector<HTMLTextAreaElement>('#nonce-input');
    expect(key?.value).toMatch(/^[0-9a-f]{64}$/);
    expect(nonce?.value).toMatch(/^[0-9a-f]{64}$/);
  });

  it('runs the in-browser conformance check and reaches PASS, including forgery rejection', () => {
    const badge = document.querySelector<HTMLSpanElement>('.conformance-badge');
    expect(badge?.textContent).toBe('PASS');
    expect(badge?.dataset.state).toBe('pass');

    const text = document.querySelector('.conformance-text');
    expect(text?.textContent).toContain('forgeries rejected');

    // 5 encryption vectors + 4 must-reject vectors rendered in the details.
    expect(document.querySelectorAll('#conformance-encrypt-body tr').length).toBe(5);
    expect(document.querySelectorAll('#conformance-reject-body tr').length).toBe(4);
  });

  it('renders the draft pseudocode pane with deep links into draft-18', () => {
    const blocks = document.querySelectorAll('.spec-block');
    expect(blocks.length).toBe(5);
    const link = document.querySelector<HTMLAnchorElement>('.spec-block h4 a');
    expect(link?.href).toContain('draft-irtf-cfrg-aegis-aead-18');
  });

  it('encrypts and then decrypts back to the original plaintext through the UI', () => {
    const click = (id: string) => document.querySelector<HTMLButtonElement>(id)?.click();

    click('#encrypt-btn');
    const ct = document.querySelector<HTMLTextAreaElement>('#ct-output');
    const tag = document.querySelector<HTMLInputElement>('#tag-output');
    expect(ct?.value).toMatch(/^[0-9a-f]+$/);
    expect(tag?.value).toMatch(/^[0-9a-f]{32}$/);

    click('#decrypt-btn');
    const status = document.querySelector('#decrypt-status');
    expect(status?.textContent).toContain('Hello, AEGIS-256!');
  });

  it('rejects tampered ciphertext through the UI and shows where the tamper landed', () => {
    const click = (id: string) => document.querySelector<HTMLButtonElement>(id)?.click();
    click('#encrypt-btn');
    click('#tamper-ct-btn');

    const ctDiff = document.querySelector<HTMLDivElement>('#ct-diff');
    expect(ctDiff?.hidden).toBe(false);
    expect(ctDiff?.querySelectorAll('mark').length).toBe(1);

    click('#decrypt-btn');
    const status = document.querySelector('#decrypt-status');
    expect(status?.textContent).toContain('TAMPER DETECTED');

    // The failed decrypt shows recomputed-vs-presented tag with diffs marked.
    const tagCompare = document.querySelector<HTMLDivElement>('#tag-compare');
    expect(tagCompare?.hidden).toBe(false);
    expect(tagCompare?.querySelectorAll('mark').length).toBeGreaterThan(0);
  });

  it('supports the 256-bit tag variant through the UI', () => {
    const click = (id: string) => document.querySelector<HTMLButtonElement>(id)?.click();
    const tagLength = document.querySelector<HTMLSelectElement>('#tag-length');
    tagLength!.value = '32';

    click('#encrypt-btn');
    const tag = document.querySelector<HTMLInputElement>('#tag-output');
    expect(tag?.value).toMatch(/^[0-9a-f]{64}$/);

    click('#decrypt-btn');
    expect(document.querySelector('#decrypt-status')?.textContent).toContain('Hello, AEGIS-256!');

    tagLength!.value = '16';
  });

  it('demonstrates the nonce-reuse catastrophe through the UI', () => {
    document.querySelector<HTMLButtonElement>('#nr-reuse-btn')?.click();

    const verdict = document.querySelector('#nr-verdict');
    expect(verdict?.textContent).toContain('KEYSTREAM CANCELLED');
    expect(verdict?.className).toContain('danger');

    // The known-plaintext attack recovers the leaked prefix of secret B.
    // Default messages share "Attack at dawn: " so that leaks cleanly.
    const recovered = document.querySelector('#nr-recovered mark');
    expect(recovered?.textContent).toContain('Attack at dawn');
  });

  it('shows that fresh nonces defeat the same attack', () => {
    document.querySelector<HTMLButtonElement>('#nr-fresh-btn')?.click();

    const verdict = document.querySelector('#nr-verdict');
    expect(verdict?.className).toContain('ok');
    expect(verdict?.textContent).toContain('leaked run: 0 bytes');
    // No leaked (marked) run at all with fresh nonces.
    expect(document.querySelector('#nr-recovered mark')).toBeNull();
  });

  it('runs the avalanche trace: 17 heatmap rows from a single flipped nonce bit', () => {
    document.querySelector<HTMLButtonElement>('#avalanche-btn')?.click();

    const rows = document.querySelectorAll('#avalanche-table tbody tr');
    expect(rows.length).toBe(17);
    expect(document.querySelector('#avalanche-log')?.textContent).toContain('differ by exactly 1 bit');
  });

  it('updates the birthday-bound explorer from the slider', () => {
    const slider = document.querySelector<HTMLInputElement>('#bd-slider');
    slider!.value = '32';
    slider!.dispatchEvent(new Event('input'));

    const output = document.querySelector('#bd-output');
    // n = 2^32 under 96-bit nonces: p ~ n^2/2 / 2^96 = 2^-33.
    expect(output?.textContent).toContain('2^-33');
    expect(output?.textContent).toContain('256-bit random nonces');
  });

  it('skips absorbing when AD is empty instead of silently diverging from the spec', () => {
    const click = (id: string) => document.querySelector<HTMLButtonElement>(id)?.click();
    const ad = document.querySelector<HTMLInputElement>('#ad-input');
    ad!.value = '';

    click('#sm-init');
    const before = document.querySelector('#state-hexagon')?.innerHTML;
    click('#sm-absorb');

    expect(document.querySelector('#state-log')?.textContent).toContain('absorbs nothing');
    expect(document.querySelector('#state-hexagon')?.innerHTML).toBe(before);
  });
});
