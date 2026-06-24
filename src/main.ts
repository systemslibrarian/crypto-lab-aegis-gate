import './style.css';

import {
  type AegisState,
  aegis256Decrypt,
  aegis256Encrypt,
  absorb,
  encryptBlock,
  finalize,
  initialize,
} from './aegis';
import { runComparison } from './benchmark';
import { runConformance } from './conformance';
import { bytesToHex, bytesToUtf8, hexToBytes, padBlock, randomBytes, utf8ToBytes } from './bytes';

function must<T extends Element>(selector: string): T {
  const el = document.querySelector<T>(selector);
  if (!el) {
    throw new Error(`Missing element: ${selector}`);
  }
  return el;
}

function flipOneBit(input: Uint8Array): Uint8Array {
  if (input.length === 0) {
    return input.slice();
  }
  const out = input.slice();
  const rand = new Uint32Array(2);
  crypto.getRandomValues(rand);
  const byteIndex = rand[0] % out.length;
  const bitIndex = rand[1] % 8;
  out[byteIndex] ^= 1 << bitIndex;
  return out;
}

function formatBlock(block: Uint8Array): string {
  return bytesToHex(block).match(/.{1,8}/g)?.join(' ') ?? '';
}

function blockLabel(i: number): string {
  return `S${i}`;
}

document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
  <a class="skip-link" href="#exhibit-1">Skip to interactive demo</a>
  <main class="shell">
    <header class="hero">
      <p class="eyebrow">crypto-lab-aegis-gate</p>
      <h1>AEGIS-256: Fast AES-Based AEAD</h1>
      <p class="subtitle">Six-state AES sponge construction, implemented from the CFRG draft and verified with official vectors.</p>
      <div class="warning">Nonce reuse is catastrophic. Never encrypt two messages with the same key+nonce pair.</div>
      <div id="conformance" class="conformance" role="status" aria-live="polite">
        <span class="conformance-badge" data-state="pending">checking…</span>
        <span class="conformance-text">Replaying official draft vectors in your browser…</span>
        <button id="conformance-details-btn" type="button" class="link-btn" aria-expanded="false" aria-controls="conformance-details" hidden>Show details</button>
      </div>
      <div id="conformance-details" class="table-wrap" role="region" aria-label="Per-vector conformance results" tabindex="0" hidden>
        <table class="conformance-table">
          <caption class="visually-hidden">Per-vector conformance results: ciphertext, 128-bit tag, and 256-bit tag for each official draft test vector</caption>
          <thead><tr><th scope="col">Draft vector</th><th scope="col">Ciphertext</th><th scope="col">128-bit tag</th><th scope="col">256-bit tag</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
    </header>

    <section class="panel" id="exhibit-1">
      <h2>Exhibit 1: Key / Nonce / Message</h2>
      <div class="grid2">
        <label>Key (32 bytes hex)<textarea id="key-input" rows="2"></textarea></label>
        <label>Nonce (32 bytes hex)<textarea id="nonce-input" rows="2"></textarea></label>
      </div>
      <div class="actions">
        <button id="gen-key" type="button">Generate Random Key</button>
        <button id="gen-nonce" type="button">Generate Random Nonce</button>
      </div>
      <label>Associated Data (UTF-8)<input id="ad-input" type="text" value="" /></label>
      <label>Plaintext (UTF-8)<textarea id="pt-input" rows="4">Hello, AEGIS-256!</textarea></label>
      <div class="actions">
        <button id="encrypt-btn" type="button">Encrypt</button>
        <button id="decrypt-btn" type="button">Decrypt</button>
        <button id="tamper-ct-btn" type="button">Tamper One Bit of Ciphertext</button>
        <button id="tamper-tag-btn" type="button">Tamper One Bit of Tag</button>
      </div>
      <label>Ciphertext (hex)<textarea id="ct-output" rows="3" readonly></textarea></label>
      <label>Tag (hex, 16 bytes)<input id="tag-output" type="text" readonly /></label>
      <pre id="decrypt-status" class="status" role="status" aria-live="polite">Ready.</pre>
    </section>

    <section class="panel" id="exhibit-2">
      <h2>Exhibit 2: The AEGIS State Machine</h2>
      <div class="actions">
        <button id="sm-init" type="button">Initialize with K||N</button>
        <button id="sm-absorb" type="button">Absorb AD Block</button>
        <button id="sm-encrypt" type="button">Encrypt PT Block</button>
        <button id="sm-finalize" type="button">Finalize (7 updates)</button>
      </div>
      <div id="state-hexagon" class="state-hexagon" role="region" aria-label="AEGIS state blocks"></div>
      <pre id="state-log" class="status" role="status" aria-live="polite">State machine idle.</pre>
    </section>

    <section class="panel" id="exhibit-3">
      <h2>Exhibit 3: Why AEGIS Over AES-GCM?</h2>
      <div class="table-wrap" role="region" aria-label="AEGIS comparison table" tabindex="0">
        <table>
          <thead><tr><th>Property</th><th>AEGIS-256</th><th>AES-256-GCM</th><th>ChaCha20-Poly1305</th></tr></thead>
          <tbody>
            <tr><td>Key size</td><td>256 bits</td><td>256 bits</td><td>256 bits</td></tr>
            <tr><td>Nonce size</td><td><strong>256 bits</strong></td><td>96 bits</td><td>96 bits</td></tr>
            <tr><td>Random nonce safety</td><td><strong>Indefinite practical use</strong></td><td>~2^32 messages</td><td>~2^32 messages</td></tr>
            <tr><td>Hardware AES throughput</td><td><strong>Typically faster than GCM</strong></td><td>Fast</td><td>No AES acceleration</td></tr>
            <tr><td>No AES hardware</td><td>Slow</td><td>Slow</td><td>Fast</td></tr>
            <tr><td>Nonce reuse catastrophe</td><td>Severe</td><td>Severe</td><td>Severe</td></tr>
            <tr><td>Standardization</td><td>CFRG Draft</td><td>NIST / RFC ecosystem</td><td>RFC 8439</td></tr>
          </tbody>
        </table>
      </div>
      <p class="note">This browser demo is pure TypeScript, so Web Crypto AES-GCM will be faster here. Native AEGIS with AES-NI/ARM crypto extensions is where AEGIS targets top throughput.</p>
    </section>

    <section class="panel" id="exhibit-4">
      <h2>Exhibit 4: Live Throughput Benchmark</h2>
      <button id="benchmark-btn" type="button">Run Benchmark</button>
      <pre id="benchmark-log" class="status" role="status" aria-live="polite">Not started.</pre>
      <div id="benchmark-chart" class="chart"></div>
    </section>

    <section class="panel" id="exhibit-5">
      <h2>Exhibit 5: Why This Matters</h2>
      <p>AEGIS has implementations across the ecosystem &mdash; including libsodium and the Zig standard library &mdash; and is of active interest for high-throughput systems where AES hardware acceleration is available.</p>
      <p>AEGIS is still a CFRG informational draft rather than a finalized TLS cipher suite standard, which is the main reason adoption is not yet universal.</p>
      <ul>
        <li>See also: crypto-lab-aes-modes</li>
        <li>See also: crypto-lab-chacha20-stream</li>
        <li>See also: crypto-lab-nonce-guard</li>
        <li>See also: crypto-lab-ascon</li>
        <li>See also: crypto-lab-padding-oracle</li>
      </ul>
    </section>
  </main>
`;

const keyInput = must<HTMLTextAreaElement>('#key-input');
const nonceInput = must<HTMLTextAreaElement>('#nonce-input');
const adInput = must<HTMLInputElement>('#ad-input');
const ptInput = must<HTMLTextAreaElement>('#pt-input');
const ctOutput = must<HTMLTextAreaElement>('#ct-output');
const tagOutput = must<HTMLInputElement>('#tag-output');
const decryptStatus = must<HTMLPreElement>('#decrypt-status');
const stateHexagon = must<HTMLDivElement>('#state-hexagon');
const stateLog = must<HTMLPreElement>('#state-log');
const benchmarkLog = must<HTMLPreElement>('#benchmark-log');
const benchmarkChart = must<HTMLDivElement>('#benchmark-chart');

let visualizationState: AegisState | null = null;

function renderState(state: AegisState | null): void {
  if (!state) {
    stateHexagon.innerHTML = '<div class="state-card">Initialize to view state.</div>';
    return;
  }

  const positions = ['p0', 'p1', 'p2', 'p3', 'p4', 'p5'];
  stateHexagon.innerHTML = state
    .map(
      (block, i) => `
      <article class="state-card ${positions[i]}">
        <h3>${blockLabel(i)}</h3>
        <p>${formatBlock(block)}</p>
      </article>
    `,
    )
    .join('');
}

function readKeyNonce(): { key: Uint8Array; nonce: Uint8Array } {
  const key = hexToBytes(keyInput.value.trim());
  const nonce = hexToBytes(nonceInput.value.trim());
  if (key.length !== 32 || nonce.length !== 32) {
    throw new Error('Key and nonce must be 32 bytes each (64 hex chars).');
  }
  return { key, nonce };
}

function setStatus(message: string): void {
  decryptStatus.textContent = message;
}

must<HTMLButtonElement>('#gen-key').addEventListener('click', () => {
  keyInput.value = bytesToHex(randomBytes(32));
});

must<HTMLButtonElement>('#gen-nonce').addEventListener('click', () => {
  nonceInput.value = bytesToHex(randomBytes(32));
});

must<HTMLButtonElement>('#encrypt-btn').addEventListener('click', () => {
  try {
    const { key, nonce } = readKeyNonce();
    const ad = utf8ToBytes(adInput.value);
    const plaintext = utf8ToBytes(ptInput.value);
    const { ciphertext, tag } = aegis256Encrypt(key, nonce, ad, plaintext);
    ctOutput.value = bytesToHex(ciphertext);
    tagOutput.value = bytesToHex(tag);
    setStatus('Encryption complete. Decrypt to verify or tamper to test authentication failure.');
  } catch (error) {
    setStatus(`Error: ${(error as Error).message}`);
  }
});

must<HTMLButtonElement>('#decrypt-btn').addEventListener('click', () => {
  try {
    const { key, nonce } = readKeyNonce();
    const ad = utf8ToBytes(adInput.value);
    const ciphertext = hexToBytes(ctOutput.value.trim());
    const tag = hexToBytes(tagOutput.value.trim());
    const plaintext = aegis256Decrypt(key, nonce, ad, ciphertext, tag);

    if (plaintext === null) {
      setStatus('TAMPER DETECTED: tag mismatch. Decryption rejected.');
      return;
    }

    setStatus(`Decrypt OK: ${bytesToUtf8(plaintext)}`);
  } catch (error) {
    setStatus(`Error: ${(error as Error).message}`);
  }
});

must<HTMLButtonElement>('#tamper-ct-btn').addEventListener('click', () => {
  try {
    const ct = hexToBytes(ctOutput.value.trim());
    if (ct.length === 0) {
      setStatus('No ciphertext bytes to tamper. Encrypt a non-empty message first.');
      return;
    }
    ctOutput.value = bytesToHex(flipOneBit(ct));
    setStatus('Ciphertext tampered by 1 bit. Decrypt should fail.');
  } catch {
    setStatus('No valid ciphertext to tamper.');
  }
});

must<HTMLButtonElement>('#tamper-tag-btn').addEventListener('click', () => {
  try {
    const tag = hexToBytes(tagOutput.value.trim());
    if (tag.length === 0) {
      setStatus('No tag to tamper. Encrypt first.');
      return;
    }
    tagOutput.value = bytesToHex(flipOneBit(tag));
    setStatus('Tag tampered by 1 bit. Decrypt should fail.');
  } catch {
    setStatus('No valid tag to tamper.');
  }
});

must<HTMLButtonElement>('#sm-init').addEventListener('click', () => {
  try {
    const { key, nonce } = readKeyNonce();
    visualizationState = initialize(key, nonce);
    renderState(visualizationState);
    stateLog.textContent = 'Initialized state with K||N and constants (16 setup updates complete).';
  } catch (error) {
    stateLog.textContent = `State init error: ${(error as Error).message}`;
  }
});

must<HTMLButtonElement>('#sm-absorb').addEventListener('click', () => {
  if (!visualizationState) {
    stateLog.textContent = 'Initialize state first.';
    return;
  }

  const adBlock = padBlock(utf8ToBytes(adInput.value).slice(0, 16));
  visualizationState = absorb(visualizationState, adBlock);
  renderState(visualizationState);
  stateLog.textContent = `Absorbed AD block: ${bytesToHex(adBlock)}`;
});

must<HTMLButtonElement>('#sm-encrypt').addEventListener('click', () => {
  if (!visualizationState) {
    stateLog.textContent = 'Initialize state first.';
    return;
  }

  const mBlock = padBlock(utf8ToBytes(ptInput.value).slice(0, 16));
  const result = encryptBlock(visualizationState, mBlock);
  visualizationState = result.state;
  renderState(visualizationState);
  stateLog.textContent = `Encrypted PT block. Cipher block: ${bytesToHex(result.ciphertext)}`;
});

must<HTMLButtonElement>('#sm-finalize').addEventListener('click', () => {
  if (!visualizationState) {
    stateLog.textContent = 'Initialize state first.';
    return;
  }

  const adLenBits = BigInt(utf8ToBytes(adInput.value).length * 8);
  const msgLenBits = BigInt(utf8ToBytes(ptInput.value).length * 8);
  const tag = finalize(visualizationState, adLenBits, msgLenBits);
  stateLog.textContent = `Finalize complete after 7 updates. Tag: ${bytesToHex(tag)}`;
});

must<HTMLButtonElement>('#benchmark-btn').addEventListener('click', async () => {
  benchmarkLog.textContent =
    'Benchmarking 1KB, 16KB, 256KB, 1MB... this yields between batches to avoid UI lockups.';
  benchmarkChart.innerHTML = '';

  try {
    const results = await runComparison();
    const maxThroughput = Math.max(
      ...results.aegis256.map((r) => r.throughputMBps),
      ...results.aesGcm.map((r) => r.throughputMBps),
    );

    const lines: string[] = [];
    for (let i = 0; i < results.messageSizes.length; i += 1) {
      const size = results.messageSizes[i];
      const a = results.aegis256[i];
      const g = results.aesGcm[i];

      lines.push(
        `${Math.round(size / 1024)} KB: AEGIS ${a.throughputMBps.toFixed(1)} MB/s | AES-GCM ${g.throughputMBps.toFixed(1)} MB/s`,
      );

      const row = document.createElement('div');
      row.className = 'bar-row';
      row.innerHTML = `
        <span>${Math.round(size / 1024)} KB</span>
        <div class="bar aegis" style="width:${(a.throughputMBps / maxThroughput) * 100}%">AEGIS ${a.throughputMBps.toFixed(1)}</div>
        <div class="bar gcm" style="width:${(g.throughputMBps / maxThroughput) * 100}%">GCM ${g.throughputMBps.toFixed(1)}</div>
      `;
      benchmarkChart.appendChild(row);
    }

    benchmarkLog.textContent = `${lines.join('\n')}\n\nWeb Crypto is native and usually faster in browser demos. Native AEGIS with AES-NI/ARM crypto extensions is where AEGIS is designed to excel.`;
  } catch (error) {
    benchmarkLog.textContent = `Benchmark failed: ${(error as Error).message}`;
  }
});

function renderConformance(): void {
  const wrap = must<HTMLDivElement>('#conformance');
  const badge = must<HTMLSpanElement>('.conformance-badge');
  const text = must<HTMLSpanElement>('.conformance-text');
  const detailsBtn = must<HTMLButtonElement>('#conformance-details-btn');
  const details = must<HTMLDivElement>('#conformance-details');
  const tbody = must<HTMLTableSectionElement>('#conformance-details tbody');

  const report = runConformance();
  const mark = (ok: boolean): string =>
    ok
      ? '<span class="ok" role="img" aria-label="match">✓</span>'
      : '<span class="fail" role="img" aria-label="mismatch">✗</span>';

  tbody.innerHTML = report.rows
    .map(
      (r) => `
      <tr>
        <th scope="row">${r.name}</th>
        <td>${mark(r.ctOk)}</td>
        <td>${mark(r.tag128Ok)}</td>
        <td>${mark(r.tag256Ok)}</td>
      </tr>`,
    )
    .join('');

  wrap.dataset.state = report.allPass ? 'pass' : 'fail';
  badge.dataset.state = report.allPass ? 'pass' : 'fail';
  badge.textContent = report.allPass ? 'PASS' : 'FAIL';
  text.textContent = report.allPass
    ? `${report.passed}/${report.total} official draft vectors reproduced exactly — ciphertext, 128-bit tag, and 256-bit tag.`
    : `${report.passed}/${report.total} draft vectors matched. Something is off — see details.`;
  detailsBtn.hidden = false;

  detailsBtn.addEventListener('click', () => {
    const open = details.hidden;
    details.hidden = !open;
    detailsBtn.setAttribute('aria-expanded', String(open));
    detailsBtn.textContent = open ? 'Hide details' : 'Show details';
  });
}

renderConformance();

keyInput.value = bytesToHex(randomBytes(32));
nonceInput.value = bytesToHex(randomBytes(32));
renderState(null);
