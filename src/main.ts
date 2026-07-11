import './style.css';

import {
  type AegisState,
  type TagLength,
  aegis256DecryptDetailed,
  aegis256Encrypt,
  absorb,
  encryptBlock,
  finalize,
  initialize,
  keystream,
} from './aegis';
import { STATE_BITS, avalancheTrace } from './avalanche';
import { runComparison } from './benchmark';
import { nonceCollisionProbability } from './birthday';
import { runConformance } from './conformance';
import { GUARANTEED_LEAK_BLOCKS, formatPrintable, leakedRunLength, recoverSibling } from './nonce-reuse';
import { buildShareQuery, parseShareQuery } from './share';
import { DRAFT_URL, SPEC_SECTIONS, type SpecId } from './spec';
import {
  bytesToHex,
  bytesToUtf8,
  hexToBytes,
  padBlock,
  randomBytes,
  utf8ToBytes,
  xorBytes,
} from './bytes';

function must<T extends Element>(selector: string): T {
  const el = document.querySelector<T>(selector);
  if (!el) {
    throw new Error(`Missing element: ${selector}`);
  }
  return el;
}

interface BitFlip {
  bytes: Uint8Array;
  byteIndex: number;
  bitIndex: number;
}

function flipOneBit(input: Uint8Array): BitFlip {
  if (input.length === 0) {
    return { bytes: input.slice(), byteIndex: 0, bitIndex: 0 };
  }
  const out = input.slice();
  const rand = new Uint32Array(2);
  crypto.getRandomValues(rand);
  const byteIndex = rand[0] % out.length;
  const bitIndex = rand[1] % 8;
  out[byteIndex] ^= 1 << bitIndex;
  return { bytes: out, byteIndex, bitIndex };
}

function blockLabel(i: number): string {
  return `S${i}`;
}

function escapeHtml(text: string): string {
  return text
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

const specPaneHtml = SPEC_SECTIONS.map(
  (s) => `
    <div class="spec-block" data-spec="${s.id}">
      <h4><a href="${s.url}" target="_blank" rel="noopener">&sect;${s.section} ${s.title}</a></h4>
      <pre>${escapeHtml(s.code)}</pre>
    </div>`,
).join('');

// Fixed teaching diagram of one Update: the S0..S5 ring of AESRound arrows,
// the S5 wrap-around carrying M, and the keystream taps feeding Z. Pulsed
// via CSS classes when the buttons run the real functions.
const dataflowSvg = `
  <svg id="dataflow" class="dataflow" viewBox="0 0 760 250" role="img"
    aria-label="AEGIS-256 update dataflow: each state block passes through the AES round function into the next block; the message block XORs into S0; the keystream Z taps S1, S4, S5, and S2 AND S3.">
    <defs>
      <marker id="df-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
        <path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor"/>
      </marker>
    </defs>
    <g class="df-m">
      <text x="82" y="16" class="df-text">M (message block)</text>
      <path class="flow flow-m" d="M 70 22 V 64" marker-end="url(#df-arrow)"/>
      <text x="82" y="52" class="df-text df-small">&#8853; into S0</text>
    </g>
    <g class="df-boxes">
      ${[0, 1, 2, 3, 4, 5]
        .map(
          (i) => `
      <rect class="df-box" x="${25 + i * 120}" y="70" width="90" height="44" rx="10"/>
      <text x="${70 + i * 120}" y="97" class="df-text df-box-label">S${i}</text>`,
        )
        .join('')}
    </g>
    <g class="df-ring">
      ${[0, 1, 2, 3, 4]
        .map(
          (i) => `
      <path class="flow flow-ring" d="M ${115 + i * 120} 92 H ${141 + i * 120}" marker-end="url(#df-arrow)"/>`,
        )
        .join('')}
      <path class="flow flow-ring flow-wrap" d="M 670 114 V 138 H 70 V 122" marker-end="url(#df-arrow)"/>
      <text x="370" y="133" class="df-text df-small" text-anchor="middle">S'0 = AESRound(S5, S0 &#8853; M) &mdash; every other S'i = AESRound(Si-1, Si)</text>
    </g>
    <g class="df-ks">
      <path class="flow flow-ks" d="M 208 114 V 165"/>
      <path class="flow flow-ks" d="M 310 114 V 165"/>
      <path class="flow flow-ks" d="M 430 114 V 165"/>
      <path class="flow flow-ks" d="M 568 114 V 165"/>
      <path class="flow flow-ks" d="M 688 114 V 165"/>
      <path class="flow flow-ks" d="M 208 165 H 688"/>
      <path class="flow flow-ks" d="M 370 165 V 176" marker-end="url(#df-arrow)"/>
      <text x="376" y="160" class="df-text df-small">S2 &amp; S3 (bitwise AND)</text>
      <rect class="df-box df-z" x="345" y="180" width="50" height="36" rx="10"/>
      <text x="370" y="203" class="df-text df-box-label">Z</text>
      <text x="370" y="240" class="df-text" text-anchor="middle">keystream Z = S1 &#8853; S4 &#8853; S5 &#8853; (S2 &amp; S3), then C = P &#8853; Z</text>
    </g>
  </svg>`;

document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
  <a class="skip-link" href="#exhibit-1">Skip to interactive demo</a>
  <main class="shell">
    <header class="hero">
      <p class="eyebrow">crypto-lab-aegis-gate</p>
      <h1>AEGIS-256: Fast AES-Based AEAD</h1>
      <p class="subtitle">Six-state AES sponge construction, implemented from the CFRG draft and verified with official vectors.</p>
      <div class="warning">Nonce reuse is catastrophic. Never encrypt two messages with the same key+nonce pair &mdash; Exhibit 3 shows you exactly why.</div>
      <div id="conformance" class="conformance" role="status" aria-live="polite">
        <span class="conformance-badge" data-state="pending">checking&hellip;</span>
        <span class="conformance-text">Replaying official draft vectors in your browser&hellip;</span>
        <button id="conformance-details-btn" type="button" class="link-btn" aria-expanded="false" aria-controls="conformance-details" hidden>Show details</button>
      </div>
      <div id="conformance-details" class="table-wrap" role="region" aria-label="Per-vector conformance results" tabindex="0" hidden>
        <table class="conformance-table">
          <caption class="visually-hidden">Per-vector conformance results: ciphertext, 128-bit tag, 256-bit tag, and decrypt round-trip for each official draft test vector</caption>
          <thead><tr><th scope="col">Draft vector</th><th scope="col">Ciphertext</th><th scope="col">128-bit tag</th><th scope="col">256-bit tag</th><th scope="col">Round-trip</th></tr></thead>
          <tbody id="conformance-encrypt-body"></tbody>
        </table>
        <table class="conformance-table">
          <caption class="visually-hidden">Official forgery vectors that a conformant implementation must reject</caption>
          <thead><tr><th scope="col">Forgery vector (must reject)</th><th scope="col">What is tampered</th><th scope="col">128-bit tag</th><th scope="col">256-bit tag</th></tr></thead>
          <tbody id="conformance-reject-body"></tbody>
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
        <button id="share-btn" type="button">Copy Shareable Link</button>
      </div>
      <label>Associated Data (UTF-8)<input id="ad-input" type="text" value="" /></label>
      <label>Plaintext (UTF-8)<textarea id="pt-input" rows="4">Hello, AEGIS-256!</textarea></label>
      <label>Tag length
        <select id="tag-length">
          <option value="16" selected>128-bit (16 bytes)</option>
          <option value="32">256-bit (32 bytes)</option>
        </select>
      </label>
      <p class="predict">Predict: flip a single bit of the ciphertext or tag &mdash; how many bytes of the recomputed tag will change?</p>
      <div class="actions">
        <button id="encrypt-btn" type="button">Encrypt</button>
        <button id="decrypt-btn" type="button">Decrypt</button>
        <button id="tamper-ct-btn" type="button">Tamper One Bit of Ciphertext</button>
        <button id="tamper-tag-btn" type="button">Tamper One Bit of Tag</button>
      </div>
      <label>Ciphertext (hex)<textarea id="ct-output" rows="3" readonly></textarea></label>
      <div id="ct-diff" class="hexdiff" hidden></div>
      <label>Tag (hex)<input id="tag-output" type="text" readonly /></label>
      <div id="tag-diff" class="hexdiff" hidden></div>
      <div id="tag-compare" class="hexdiff" hidden></div>
      <pre id="decrypt-status" class="status" role="status" aria-live="polite">Ready.</pre>
    </section>

    <section class="panel" id="exhibit-2">
      <h2>Exhibit 2: The AEGIS State Machine</h2>
      <p class="note">Watch the spec execute: every button below runs this implementation's real functions on the key/nonce/AD/plaintext from Exhibit 1, the diagram shows where the bytes flow, and the pseudocode pane highlights the part of <a href="${DRAFT_URL}" target="_blank" rel="noopener">draft-18</a> that just ran. Bytes that changed since the previous step glow gold.</p>
      <div class="sm-layout">
        <div class="sm-left">
          <div class="actions">
            <button id="sm-init" type="button">Initialize with K||N</button>
            <button id="sm-absorb" type="button">Absorb AD Block</button>
            <button id="sm-encrypt" type="button">Encrypt PT Block</button>
            <button id="sm-finalize" type="button">Finalize (7 updates)</button>
          </div>
          ${dataflowSvg}
          <div id="state-hexagon" class="state-hexagon" role="region" aria-label="AEGIS state blocks"></div>
          <div id="keystream-strip" class="keystream" hidden>
            <span>Z = S1 &#8853; S4 &#8853; S5 &#8853; (S2 &amp; S3) =</span>
            <code id="keystream-hex"></code>
            <span class="keystream-note">&larr; the keystream the next Enc would use (C = P &#8853; Z)</span>
          </div>
          <pre id="state-log" class="status" role="status" aria-live="polite">State machine idle.</pre>
        </div>
        <aside class="spec-pane" aria-label="AEGIS-256 pseudocode from draft-irtf-cfrg-aegis-aead-18">
          <h3>The spec, live</h3>
          ${specPaneHtml}
        </aside>
      </div>

      <h3>Avalanche: what the 16 setup updates buy</h3>
      <p class="predict">Predict: flip one bit of the 256-bit nonce &mdash; after how many updates will roughly half of the 768 state bits differ?</p>
      <div class="actions">
        <button id="avalanche-btn" type="button">Flip One Nonce Bit &amp; Trace Init</button>
      </div>
      <div id="avalanche-result" class="table-wrap" role="region" aria-label="Avalanche heatmap" tabindex="0" hidden>
        <table class="heatmap" id="avalanche-table">
          <caption class="visually-hidden">Differing state bits per block after the seed and after each of the 16 initialization updates</caption>
          <thead><tr><th scope="col">Step</th><th scope="col">S0</th><th scope="col">S1</th><th scope="col">S2</th><th scope="col">S3</th><th scope="col">S4</th><th scope="col">S5</th><th scope="col">Total / ${STATE_BITS}</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
      <pre id="avalanche-log" class="status" role="status" aria-live="polite">Not run yet.</pre>
    </section>

    <section class="panel" id="exhibit-3">
      <h2>Exhibit 3: The Nonce-Reuse Catastrophe</h2>
      <p class="note">AEGIS encrypts block <em>i</em> as C<sub>i</sub> = P<sub>i</sub> &#8853; Z<sub>i</sub>, with the keystream Z read from the state before the block's plaintext is folded in. Reuse a key+nonce and both messages start from the <em>same</em> state, so C<sub>A</sub> &#8853; C<sub>B</sub> = P<sub>A</sub> &#8853; P<sub>B</sub> wherever the keystreams still match. The key never breaks &mdash; it just stops mattering.</p>
      <p class="note">AEGIS is not a pure stream cipher: the keystream never reads S0 and plaintext only enters S0, so the first <strong>two blocks (32 bytes) always leak</strong> as a two-time pad, plus any shared prefix. Once the messages diverge, the plaintext they absorb pushes the states apart and the tail is protected &mdash; but a leaked 32-byte prefix is already game over.</p>
      <div class="grid2">
        <label>Message A (attacker knows this one)<textarea id="nr-pt-a" rows="2">Attack at dawn: 06:00hrs, north gate.</textarea></label>
        <label>Message B (the secret)<textarea id="nr-pt-b" rows="2">Attack at dawn: 18:00hrs, south gate.</textarea></label>
      </div>
      <p class="predict">Predict: encrypt both with the same key+nonce &mdash; how much of secret B can the attacker read off C<sub>A</sub> &#8853; C<sub>B</sub> &#8853; A?</p>
      <div class="actions">
        <button id="nr-reuse-btn" type="button">Encrypt Both With the SAME Key+Nonce</button>
        <button id="nr-fresh-btn" type="button">Encrypt With Fresh Nonces (Safe)</button>
      </div>
      <div id="nr-output" class="nr-output" hidden>
        <div class="nr-row"><span class="nr-label">shared key</span><code id="nr-key"></code></div>
        <div class="nr-row"><span class="nr-label">nonce A</span><code id="nr-nonce-a"></code></div>
        <div class="nr-row"><span class="nr-label">nonce B</span><code id="nr-nonce-b"></code></div>
        <div class="nr-row"><span class="nr-label">C_A</span><code id="nr-ct-a"></code></div>
        <div class="nr-row"><span class="nr-label">C_B</span><code id="nr-ct-b"></code></div>
        <div class="nr-row"><span class="nr-label">C_A &#8853; C_B</span><code id="nr-xor-ct"></code></div>
        <div class="nr-row"><span class="nr-label">P_A &#8853; P_B</span><code id="nr-xor-pt"></code></div>
        <div class="nr-verdict" id="nr-verdict"></div>
        <div class="nr-row"><span class="nr-label">B recovered from C_A, C_B, and known A</span><code id="nr-recovered" class="nr-recovered"></code></div>
        <p class="nr-hint" id="nr-hint"></p>
      </div>
      <pre id="nr-log" class="status" role="status" aria-live="polite">Ready. No key is ever attacked here &mdash; only the nonce discipline.</pre>
    </section>

    <section class="panel" id="exhibit-4">
      <h2>Exhibit 4: Why AEGIS Over AES-GCM?</h2>
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
      <h3>How long are random nonces safe? The birthday bound, live</h3>
      <label class="bd-label">Messages encrypted under random nonces: 2<sup id="bd-exp">32</sup>
        <input id="bd-slider" type="range" min="0" max="64" step="1" value="32" aria-label="Number of messages as a power of two" />
      </label>
      <pre id="bd-output" class="status">&nbsp;</pre>
      <p class="note">The usual comfort line is a collision probability of 2<sup>-32</sup>: with 96-bit random nonces you cross it near 2<sup>32</sup> messages (hence AES-GCM's limit); with 256-bit nonces you would need about 2<sup>112</sup> messages. That gap is the reason AEGIS-256 exists.</p>
    </section>

    <section class="panel" id="exhibit-5">
      <h2>Exhibit 5: Live Throughput Benchmark</h2>
      <p class="predict">Predict: which wins in a browser &mdash; this pure-TypeScript AEGIS or the browser's native AES-GCM? On CPUs with AES instructions, native AEGIS implementations flip the result.</p>
      <button id="benchmark-btn" type="button">Run Benchmark</button>
      <pre id="benchmark-log" class="status" role="status" aria-live="polite">Not started.</pre>
      <div id="benchmark-chart" class="chart"></div>
    </section>

    <section class="panel" id="exhibit-6">
      <h2>Exhibit 6: Why This Matters</h2>
      <p>AEGIS has implementations across the ecosystem &mdash; including libsodium and the Zig standard library &mdash; and is of active interest for high-throughput systems where AES hardware acceleration is available. AEGIS is still a CFRG informational draft rather than a finalized standard, and a <a href="https://datatracker.ietf.org/doc/draft-denis-tls-aegis/" target="_blank" rel="noopener">companion draft</a> proposes AEGIS cipher suites for TLS 1.3, DTLS 1.3, and QUIC.</p>
      <h3>The AEGIS family (<a href="${DRAFT_URL}#section-5" target="_blank" rel="noopener">draft-18 &sect;3&ndash;5</a>)</h3>
      <div class="table-wrap" role="region" aria-label="AEGIS family comparison table" tabindex="0">
        <table>
          <thead><tr><th>Variant</th><th>Key</th><th>Nonce</th><th>State</th><th>Rate per update</th><th>Design target</th></tr></thead>
          <tbody>
            <tr><td>AEGIS-128L</td><td>128-bit</td><td>128-bit</td><td>8 blocks (1024 bits)</td><td>256 bits</td><td>Fastest single-lane throughput</td></tr>
            <tr><td><strong>AEGIS-256</strong> (this demo)</td><td>256-bit</td><td>256-bit</td><td>6 blocks (768 bits)</td><td>128 bits</td><td>256-bit security, random-nonce safety</td></tr>
            <tr><td>AEGIS-128X2 / X4</td><td>128-bit</td><td>128-bit</td><td>2&times; / 4&times; 128L lanes</td><td>512 / 1024 bits</td><td>SIMD parallelism (wide vector registers)</td></tr>
            <tr><td>AEGIS-256X2 / X4</td><td>256-bit</td><td>256-bit</td><td>2&times; / 4&times; 256 lanes</td><td>256 / 512 bits</td><td>SIMD parallelism at 256-bit security</td></tr>
          </tbody>
        </table>
      </div>
      <ul>
        <li>See also: <a href="https://systemslibrarian.github.io/crypto-lab-aes-modes/">crypto-lab-aes-modes</a></li>
        <li>See also: <a href="https://systemslibrarian.github.io/crypto-lab-chacha20-stream/">crypto-lab-chacha20-stream</a></li>
        <li>See also: <a href="https://systemslibrarian.github.io/crypto-lab-nonce-guard/">crypto-lab-nonce-guard</a></li>
        <li>See also: <a href="https://systemslibrarian.github.io/crypto-lab-ascon/">crypto-lab-ascon</a></li>
        <li>See also: <a href="https://systemslibrarian.github.io/crypto-lab-padding-oracle/">crypto-lab-padding-oracle</a></li>
      </ul>
    </section>
  </main>
<footer style="margin-top:3rem;padding:2rem 1rem;border-top:1px solid rgba(128,128,128,.25);text-align:center;font-size:.85rem;line-height:1.9;font-family:ui-monospace,Menlo,Consolas,monospace">
  <div><strong>Related demos:</strong> <a href="https://systemslibrarian.github.io/crypto-lab-aes-modes/" style="color:#35d6bb">aes-modes</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-ascon/" style="color:#35d6bb">ascon</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-chacha20-stream/" style="color:#35d6bb">chacha20-stream</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-shadow-vault/" style="color:#35d6bb">shadow-vault</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-nonce-guard/" style="color:#35d6bb">nonce-guard</a></div>
  <div style="margin-top:.5rem"><a href="https://github.com/systemslibrarian/crypto-lab-aegis-gate" style="color:#35d6bb">Source on GitHub</a> &middot; <a href="https://crypto-lab.systemslibrarian.dev/" style="color:#35d6bb">More crypto-lab demos</a></div>
  <div style="margin-top:.75rem;color:var(--muted)">&ldquo;So whether you eat or drink or whatever you do, do it all for the glory of God.&rdquo; &mdash; 1 Corinthians 10:31</div>
</footer>
`;

const keyInput = must<HTMLTextAreaElement>('#key-input');
const nonceInput = must<HTMLTextAreaElement>('#nonce-input');
const adInput = must<HTMLInputElement>('#ad-input');
const ptInput = must<HTMLTextAreaElement>('#pt-input');
const tagLengthSelect = must<HTMLSelectElement>('#tag-length');
const ctOutput = must<HTMLTextAreaElement>('#ct-output');
const tagOutput = must<HTMLInputElement>('#tag-output');
const ctDiff = must<HTMLDivElement>('#ct-diff');
const tagDiff = must<HTMLDivElement>('#tag-diff');
const tagCompare = must<HTMLDivElement>('#tag-compare');
const decryptStatus = must<HTMLPreElement>('#decrypt-status');
const stateHexagon = must<HTMLDivElement>('#state-hexagon');
const stateLog = must<HTMLPreElement>('#state-log');
const keystreamStrip = must<HTMLDivElement>('#keystream-strip');
const keystreamHex = must<HTMLElement>('#keystream-hex');
const benchmarkLog = must<HTMLPreElement>('#benchmark-log');
const benchmarkChart = must<HTMLDivElement>('#benchmark-chart');

let visualizationState: AegisState | null = null;
let lastRenderedState: AegisState | null = null;

function selectedTagLength(): TagLength {
  return tagLengthSelect.value === '32' ? 32 : 16;
}

function renderByteSpans(block: Uint8Array, previous: Uint8Array | null): string {
  let html = '';
  for (let j = 0; j < block.length; j += 1) {
    const changed = previous !== null && previous[j] !== block[j];
    html += `<span class="byte${changed ? ' changed' : ''}">${block[j].toString(16).padStart(2, '0')}</span>`;
    if (j % 4 === 3 && j < block.length - 1) {
      html += ' ';
    }
  }
  return html;
}

function renderState(state: AegisState | null): void {
  if (!state) {
    stateHexagon.innerHTML = '<div class="state-card">Initialize to view state.</div>';
    keystreamStrip.hidden = true;
    lastRenderedState = null;
    return;
  }

  const positions = ['p0', 'p1', 'p2', 'p3', 'p4', 'p5'];
  stateHexagon.innerHTML = state
    .map((block, i) => {
      const previous = lastRenderedState ? lastRenderedState[i] : null;
      const changed = previous ? block.reduce((n, b, j) => n + (previous[j] !== b ? 1 : 0), 0) : 0;
      const badge = previous
        ? `<span class="chg" aria-label="${changed} of 16 bytes changed">${changed}/16 changed</span>`
        : '';
      return `
      <article class="state-card ${positions[i]}">
        <h3>${blockLabel(i)} ${badge}</h3>
        <p>${renderByteSpans(block, previous)}</p>
      </article>
    `;
    })
    .join('');

  keystreamHex.textContent = bytesToHex(keystream(state));
  keystreamStrip.hidden = false;
  lastRenderedState = state;
}

/** Re-trigger the dataflow pulse animation for the given flow groups. */
function pulseFlow(kinds: Array<'ring' | 'ks' | 'm'>): void {
  const svg = document.querySelector('#dataflow');
  if (!svg) {
    return;
  }
  svg.classList.remove('pulse-ring', 'pulse-ks', 'pulse-m');
  setTimeout(() => {
    for (const kind of kinds) {
      svg.classList.add(`pulse-${kind}`);
    }
  }, 30);
}

function highlightSpec(ids: SpecId[]): void {
  for (const block of document.querySelectorAll<HTMLElement>('.spec-block')) {
    if (ids.includes(block.dataset.spec as SpecId)) {
      block.setAttribute('data-active', '');
    } else {
      block.removeAttribute('data-active');
    }
  }
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

/**
 * Show a before/after hex view with the differing bytes marked, so a
 * learner sees exactly WHERE a tamper landed, not just that it happened.
 */
function renderHexDiff(el: HTMLElement, label: string, before: Uint8Array, after: Uint8Array): void {
  const spans = Array.from(after, (b, i) => {
    const hex = b.toString(16).padStart(2, '0');
    return i < before.length && before[i] !== b ? `<mark>${hex}</mark>` : hex;
  }).join('');
  const changed = Array.from(after, (b, i) => (i < before.length && before[i] !== b ? 1 : 0)).reduce<number>(
    (a, n) => a + n,
    0,
  );
  el.innerHTML = `<span class="hexdiff-label">${escapeHtml(label)} (${changed} byte${changed === 1 ? '' : 's'} differ):</span> <code>${spans}</code>`;
  el.hidden = false;
}

function hideTamperViews(): void {
  ctDiff.hidden = true;
  tagDiff.hidden = true;
  tagCompare.hidden = true;
}

must<HTMLButtonElement>('#gen-key').addEventListener('click', () => {
  keyInput.value = bytesToHex(randomBytes(32));
});

must<HTMLButtonElement>('#gen-nonce').addEventListener('click', () => {
  nonceInput.value = bytesToHex(randomBytes(32));
});

must<HTMLButtonElement>('#share-btn').addEventListener('click', () => {
  const query = buildShareQuery({
    key: keyInput.value.trim(),
    nonce: nonceInput.value.trim(),
    ad: adInput.value,
    pt: ptInput.value,
  });
  const url = `${location.origin}${location.pathname}?${query}`;
  const clipboard = navigator.clipboard;
  if (clipboard?.writeText) {
    clipboard.writeText(url).then(
      () => setStatus('Shareable link copied. Anyone opening it gets this exact key/nonce/AD/plaintext.'),
      () => setStatus(`Copy failed - share this link manually:\n${url}`),
    );
  } else {
    setStatus(`Share this link:\n${url}`);
  }
});

must<HTMLButtonElement>('#encrypt-btn').addEventListener('click', () => {
  try {
    const { key, nonce } = readKeyNonce();
    const ad = utf8ToBytes(adInput.value);
    const plaintext = utf8ToBytes(ptInput.value);
    const { ciphertext, tag } = aegis256Encrypt(key, nonce, ad, plaintext, selectedTagLength());
    ctOutput.value = bytesToHex(ciphertext);
    tagOutput.value = bytesToHex(tag);
    hideTamperViews();
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
    const { plaintext, computedTag } = aegis256DecryptDetailed(
      key,
      nonce,
      ad,
      ciphertext,
      tag,
      selectedTagLength(),
    );

    if (plaintext === null) {
      renderHexDiff(tagCompare, 'Recomputed tag vs the tag presented', tag, computedTag);
      setStatus(
        'TAMPER DETECTED: tag mismatch. Decryption rejected.\nNote how the recomputed tag differs in (almost) every byte - one flipped input bit avalanches through the whole state.',
      );
      return;
    }

    tagCompare.hidden = true;
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
    const flip = flipOneBit(ct);
    ctOutput.value = bytesToHex(flip.bytes);
    renderHexDiff(ctDiff, `Ciphertext after flipping bit ${flip.bitIndex} of byte ${flip.byteIndex}`, ct, flip.bytes);
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
    const flip = flipOneBit(tag);
    tagOutput.value = bytesToHex(flip.bytes);
    renderHexDiff(tagDiff, `Tag after flipping bit ${flip.bitIndex} of byte ${flip.byteIndex}`, tag, flip.bytes);
    setStatus('Tag tampered by 1 bit. Decrypt should fail.');
  } catch {
    setStatus('No valid tag to tamper.');
  }
});

must<HTMLButtonElement>('#sm-init').addEventListener('click', () => {
  try {
    const { key, nonce } = readKeyNonce();
    lastRenderedState = null;
    visualizationState = initialize(key, nonce);
    renderState(visualizationState);
    pulseFlow(['ring', 'm']);
    highlightSpec(['init', 'update']);
    stateLog.textContent =
      'Initialized state with K||N and constants (16 setup updates complete). See Init (S4.4) in the pane - and the avalanche table below for why 16.';
  } catch (error) {
    stateLog.textContent = `State init error: ${(error as Error).message}`;
  }
});

must<HTMLButtonElement>('#sm-absorb').addEventListener('click', () => {
  if (!visualizationState) {
    stateLog.textContent = 'Initialize state first.';
    return;
  }

  const ad = utf8ToBytes(adInput.value);
  if (ad.length === 0) {
    // Spec fidelity: with empty AD there are zero ad blocks, so Absorb never
    // runs. Absorbing a padded empty block here would silently diverge from
    // the algorithm this page claims to demonstrate.
    highlightSpec(['absorb']);
    stateLog.textContent =
      'AD is empty, so the spec absorbs nothing (zero ad blocks - no Update runs). Type some Associated Data in Exhibit 1 to absorb a block.';
    return;
  }

  const adBlock = padBlock(ad.slice(0, 16));
  visualizationState = absorb(visualizationState, adBlock);
  renderState(visualizationState);
  pulseFlow(['ring', 'm']);
  highlightSpec(['absorb', 'update']);
  stateLog.textContent = `Absorbed AD block (zero-padded to 16 bytes): ${bytesToHex(adBlock)}`;
});

must<HTMLButtonElement>('#sm-encrypt').addEventListener('click', () => {
  if (!visualizationState) {
    stateLog.textContent = 'Initialize state first.';
    return;
  }

  const zBefore = keystream(visualizationState);
  const mBlock = padBlock(utf8ToBytes(ptInput.value).slice(0, 16));
  const result = encryptBlock(visualizationState, mBlock);
  visualizationState = result.state;
  renderState(visualizationState);
  pulseFlow(['ring', 'ks', 'm']);
  highlightSpec(['enc', 'update']);
  stateLog.textContent = `Encrypted PT block: C = P xor Z.\n  Z (from pre-update state): ${bytesToHex(zBefore)}\n  cipher block:              ${bytesToHex(result.ciphertext)}\nThe Z strip above now shows the keystream the NEXT block would use.`;
});

must<HTMLButtonElement>('#sm-finalize').addEventListener('click', () => {
  if (!visualizationState) {
    stateLog.textContent = 'Initialize state first.';
    return;
  }

  const adLenBits = BigInt(utf8ToBytes(adInput.value).length * 8);
  const msgLenBits = BigInt(utf8ToBytes(ptInput.value).length * 8);
  const tag = finalize(visualizationState, adLenBits, msgLenBits, selectedTagLength());
  pulseFlow(['ring']);
  highlightSpec(['finalize', 'update']);
  stateLog.textContent = `Finalize complete: absorbed the AD/message bit lengths into S3, ran 7 closing updates, folded the state.\nTag (${tag.length * 8}-bit): ${bytesToHex(tag)}`;
});

must<HTMLButtonElement>('#avalanche-btn').addEventListener('click', () => {
  const avalancheLog = must<HTMLPreElement>('#avalanche-log');
  try {
    const { key, nonce } = readKeyNonce();
    const rand = new Uint32Array(2);
    crypto.getRandomValues(rand);
    const byteIndex = rand[0] % 32;
    const bitIndex = rand[1] % 8;

    const trace = avalancheTrace(key, nonce, byteIndex, bitIndex);
    const tbody = must<HTMLTableSectionElement>('#avalanche-table tbody');
    tbody.innerHTML = trace
      .map((step) => {
        const cells = step.perBlockBits
          .map((bits) => {
            const alpha = Math.min(1, bits / 128);
            // Cap the tint at 0.45: at 0.55 the near-white cell text drops to
            // ~3.8:1 against the brightest cells; 0.45 keeps it near 5:1.
            return `<td style="background-color:rgba(0,212,255,${(alpha * 0.45).toFixed(3)})">${bits}</td>`;
          })
          .join('');
        const pct = ((step.totalBits / STATE_BITS) * 100).toFixed(1);
        return `<tr><th scope="row">${step.label}</th>${cells}<td>${step.totalBits} (${pct}%)</td></tr>`;
      })
      .join('');
    must<HTMLDivElement>('#avalanche-result').hidden = false;

    const half = trace.findIndex((s) => s.totalBits >= STATE_BITS * 0.45);
    avalancheLog.textContent = `Flipped bit ${bitIndex} of nonce byte ${byteIndex}: the seeded states differ by exactly ${trace[0].totalBits} bit.\nBy ${half > 0 ? `update ${half}` : 'the end of init'} the two states already differ in ~50% of their ${STATE_BITS} bits - full diffusion.\nThat is what the draft's 16 setup updates are for: no keystream is exposed before the nonce has avalanched everywhere.`;
  } catch (error) {
    avalancheLog.textContent = `Avalanche error: ${(error as Error).message}`;
  }
});

function runNonceReuseDemo(reuseNonce: boolean): void {
  const nrLog = must<HTMLPreElement>('#nr-log');
  const ptA = utf8ToBytes(must<HTMLTextAreaElement>('#nr-pt-a').value);
  const ptB = utf8ToBytes(must<HTMLTextAreaElement>('#nr-pt-b').value);
  if (ptA.length === 0 || ptB.length === 0) {
    nrLog.textContent = 'Both messages need at least one byte.';
    return;
  }

  const key = randomBytes(32);
  const nonceA = randomBytes(32);
  const nonceB = reuseNonce ? nonceA : randomBytes(32);
  const empty = new Uint8Array(0);
  const encA = aegis256Encrypt(key, nonceA, empty, ptA);
  const encB = aegis256Encrypt(key, nonceB, empty, ptB);

  const xorCt = xorBytes(encA.ciphertext, encB.ciphertext);
  const xorPt = xorBytes(ptA, ptB);
  const leaked = leakedRunLength(encA.ciphertext, encB.ciphertext, ptA, ptB);

  must<HTMLElement>('#nr-key').textContent = bytesToHex(key);
  must<HTMLElement>('#nr-nonce-a').textContent = bytesToHex(nonceA);
  must<HTMLElement>('#nr-nonce-b').textContent = `${bytesToHex(nonceB)}${reuseNonce ? '  (SAME nonce!)' : '  (fresh)'}`;
  must<HTMLElement>('#nr-ct-a').textContent = bytesToHex(encA.ciphertext);
  must<HTMLElement>('#nr-ct-b').textContent = bytesToHex(encB.ciphertext);
  must<HTMLElement>('#nr-xor-ct').textContent = bytesToHex(xorCt);
  must<HTMLElement>('#nr-xor-pt').textContent = bytesToHex(xorPt);

  const verdict = must<HTMLDivElement>('#nr-verdict');
  const recoveredEl = must<HTMLElement>('#nr-recovered');
  const hint = must<HTMLElement>('#nr-hint');
  const recovered = recoverSibling(encA.ciphertext, encB.ciphertext, ptA);
  const overlap = Math.min(ptA.length, ptB.length);

  // Show the recovered bytes with the genuinely-leaked prefix marked: past
  // the leaked run the "recovery" is garbage, which is the honest picture.
  const printable = formatPrintable(recovered);
  const leakedText = escapeHtml(printable.slice(0, leaked));
  const garbageText = escapeHtml(printable.slice(leaked, overlap));
  recoveredEl.innerHTML =
    leaked > 0
      ? `<mark>${leakedText}</mark><span class="nr-garbage">${garbageText}</span>`
      : `<span class="nr-garbage">${escapeHtml(printable.slice(0, overlap))}</span>`;

  if (reuseNonce) {
    verdict.textContent = `KEYSTREAM CANCELLED over the first ${leaked} bytes - an eavesdropper holding only the two ciphertexts reads that much of secret B straight off C_A xor C_B xor A, no key required.`;
    verdict.className = 'nr-verdict danger';
    hint.textContent = `The highlighted run is genuinely recovered plaintext; the dim tail is garbage where AEGIS's state had diverged. The first ${GUARANTEED_LEAK_BLOCKS * 16} bytes leak for ANY two messages, more when they share a prefix.`;
    nrLog.textContent = `Same key + same nonce -> same starting state. C_A xor C_B = P_A xor P_B for ${leaked} leading bytes.\nSecret B, partially recovered without ever touching the key: see the highlighted run above.`;
  } else {
    verdict.textContent =
      'FRESH NONCES - independent keystreams, so nothing cancels (leaked run: 0 bytes). The same recovery attempt yields pure noise.';
    verdict.className = 'nr-verdict ok';
    hint.textContent = 'Every byte of the "recovered" row is garbage. One rule - never reuse the pair - is the whole difference between the two buttons.';
    nrLog.textContent =
      'Fresh nonce per message: C_A xor C_B is unrelated to P_A xor P_B, and the recovered row is noise end to end.';
  }
  must<HTMLDivElement>('#nr-output').hidden = false;
}

must<HTMLButtonElement>('#nr-reuse-btn').addEventListener('click', () => runNonceReuseDemo(true));
must<HTMLButtonElement>('#nr-fresh-btn').addEventListener('click', () => runNonceReuseDemo(false));

function renderBirthday(): void {
  const slider = must<HTMLInputElement>('#bd-slider');
  const exponent = Number(slider.value);
  must<HTMLElement>('#bd-exp').textContent = String(exponent);

  const describe = (bits: number): string => {
    const { p, log2P } = nonceCollisionProbability(exponent, bits);
    if (p === 0) {
      return 'zero (a single message cannot collide)';
    }
    if (p > 0.01) {
      return `${(p * 100).toFixed(1)}%`;
    }
    return `~2^${log2P === null ? '?' : log2P.toFixed(0)} (${p.toExponential(1)})`;
  };

  const approxCount = exponent < 10 ? String(2 ** exponent) : `about ${(2 ** exponent).toExponential(1)}`;
  must<HTMLPreElement>('#bd-output').textContent = `2^${exponent} messages (${approxCount}):
   96-bit random nonces (AES-GCM):    collision probability ${describe(96)}
  256-bit random nonces (AEGIS-256):  collision probability ${describe(256)}`;
}

must<HTMLInputElement>('#bd-slider').addEventListener('input', renderBirthday);

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
  const encryptBody = must<HTMLTableSectionElement>('#conformance-encrypt-body');
  const rejectBody = must<HTMLTableSectionElement>('#conformance-reject-body');

  const report = runConformance();
  const mark = (ok: boolean): string =>
    ok
      ? '<span class="ok" role="img" aria-label="match">&#10003;</span>'
      : '<span class="fail" role="img" aria-label="mismatch">&#10007;</span>';

  encryptBody.innerHTML = report.rows
    .map(
      (r) => `
      <tr>
        <th scope="row">${r.name}</th>
        <td>${mark(r.ctOk)}</td>
        <td>${mark(r.tag128Ok)}</td>
        <td>${mark(r.tag256Ok)}</td>
        <td>${mark(r.roundTripOk)}</td>
      </tr>`,
    )
    .join('');

  rejectBody.innerHTML = report.rejections
    .map(
      (r) => `
      <tr>
        <th scope="row">${r.name}</th>
        <td>${escapeHtml(r.tampered)}</td>
        <td>${mark(r.rejected128)}</td>
        <td>${mark(r.rejected256)}</td>
      </tr>`,
    )
    .join('');

  wrap.dataset.state = report.allPass ? 'pass' : 'fail';
  badge.dataset.state = report.allPass ? 'pass' : 'fail';
  badge.textContent = report.allPass ? 'PASS' : 'FAIL';
  text.textContent = report.allPass
    ? `${report.passed}/${report.total} official draft vectors conform - ${report.rows.length} encryptions reproduced byte-for-byte (with decrypt round-trip), ${report.rejections.length} forgeries rejected.`
    : `${report.passed}/${report.total} draft vectors conform. Something is off - see details.`;
  detailsBtn.hidden = false;

  detailsBtn.addEventListener('click', () => {
    const open = details.hidden;
    details.hidden = !open;
    detailsBtn.setAttribute('aria-expanded', String(open));
    detailsBtn.textContent = open ? 'Hide details' : 'Show details';
  });
}

renderConformance();

const shared = parseShareQuery(location.search);
keyInput.value = shared.key ?? bytesToHex(randomBytes(32));
nonceInput.value = shared.nonce ?? bytesToHex(randomBytes(32));
if (shared.ad !== undefined) {
  adInput.value = shared.ad;
}
if (shared.pt !== undefined) {
  ptInput.value = shared.pt;
}
if (Object.keys(shared).length > 0) {
  setStatus('Scenario loaded from shared link - key, nonce, AD, and plaintext came from the URL.');
}

renderState(null);
renderBirthday();
