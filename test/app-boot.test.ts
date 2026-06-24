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

  it('renders all five exhibits', () => {
    for (let i = 1; i <= 5; i += 1) {
      expect(document.querySelector(`#exhibit-${i}`), `exhibit ${i} missing`).toBeTruthy();
    }
  });

  it('wires the core controls', () => {
    for (const id of ['#encrypt-btn', '#decrypt-btn', '#sm-init', '#benchmark-btn']) {
      expect(document.querySelector(id), `${id} missing`).toBeTruthy();
    }
  });

  it('pre-fills a random key and nonce (64 hex chars each)', () => {
    const key = document.querySelector<HTMLTextAreaElement>('#key-input');
    const nonce = document.querySelector<HTMLTextAreaElement>('#nonce-input');
    expect(key?.value).toMatch(/^[0-9a-f]{64}$/);
    expect(nonce?.value).toMatch(/^[0-9a-f]{64}$/);
  });

  it('runs the in-browser conformance check and reaches PASS', () => {
    const badge = document.querySelector<HTMLSpanElement>('.conformance-badge');
    expect(badge?.textContent).toBe('PASS');
    expect(badge?.dataset.state).toBe('pass');
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

  it('rejects tampered ciphertext through the UI', () => {
    const click = (id: string) => document.querySelector<HTMLButtonElement>(id)?.click();
    click('#encrypt-btn');
    click('#tamper-ct-btn');
    click('#decrypt-btn');
    const status = document.querySelector('#decrypt-status');
    expect(status?.textContent).toContain('TAMPER DETECTED');
  });
});
