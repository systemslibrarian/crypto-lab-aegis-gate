import { runCommitment, type CommitmentCase } from './commitment';

export const commitmentHtml = `
<section class="panel" id="exhibit-7">
  <h2>Exhibit 7: One ciphertext, two keys</h2>
  <p>A valid tag checks a message in a particular context. Does it also tell you which key was used?
  This published example has two known keys and carefully constructed, different associated data.
  Both contexts use the same nonce. No unknown key is recovered.</p>
  <p class="predict">Will a longer tag force the ciphertext to belong to just one key?</p>
  <div class="grid-2">
    <label>Second context<select id="kc-case">
      <option value="same-ad">Control: use A's associated data with key B</option>
      <option value="collision">Paper example: constructed associated data for B</option>
      <option value="tampered-ad">Control: flip one bit of B's constructed data</option>
    </select></label>
    <label>Tag length<select id="kc-tag"><option value="16">128 bits — published vector</option>
      <option value="32">256 bits — recomputed from the same contexts</option></select></label>
  </div>
  <button id="kc-run" type="button">Compare both contexts</button>
  <p id="kc-status" class="status" role="status" aria-live="polite">Choose a case, then compare.</p>
  <div id="kc-output" hidden>
    <div class="grid-2">
      <p>Context A: <strong id="kc-a"></strong></p>
      <p>Context B: <strong id="kc-b"></strong></p>
    </div>
    <p id="kc-limit"></p>
    <h3>Watch the states converge or stay different</h3>
    <p>Each cell counts differing bits between the two actual 128-bit state blocks. Zero means
    identical. Once every block matches after equal-length associated data, the same plaintext
    continues from the same state and produces the same ciphertext and tag.</p>
    <div class="table-wrap" role="region" tabindex="0" aria-label="State differences for both key contexts">
      <table><caption>Differing state bits after each operation</caption>
        <thead><tr><th scope="col">Operation</th><th scope="col">S0</th><th scope="col">S1</th>
        <th scope="col">S2</th><th scope="col">S3</th><th scope="col">S4</th><th scope="col">S5</th></tr></thead>
        <tbody id="kc-trace"></tbody></table>
    </div>
    <details><summary>Inspect the actual keys, associated data and outputs</summary>
      <pre id="kc-bytes" class="status"></pre>
    </details>
  </div>
  <p class="note">This tests full robustness with attacker-chosen key/AD contexts. It is not
  a forgery under a fixed unknown key, and is not a nonce-reuse attack under one key.
  Teaching implementation, not production cryptography.</p>
  <p>Source: <a href="https://doi.org/10.46586/tosc.v2024.i1.135-157">Derbez et al.,
  Key Committing Attacks against AES-based AEAD Schemes</a>, Section 3 and Appendix A.2
  (journal page 156). Compare <a href="https://systemslibrarian.github.io/crypto-lab-salamander/">Salamander's commitment lesson</a>.</p>
</section>`;

/** Render only outcomes returned by the real encryption and verification paths. */
export function mountCommitment(): void {
  const get = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
  const scenario = get<HTMLSelectElement>('kc-case');
  const tag = get<HTMLSelectElement>('kc-tag');
  const status = get<HTMLElement>('kc-status');
  const output = get<HTMLElement>('kc-output');
  let previous = `${scenario.value}/${tag.value}`;
  const retire = () => {
    const next = `${scenario.value}/${tag.value}`;
    if (next === previous) return;
    previous = next;
    output.hidden = true;
    status.className = 'status';
    status.textContent = 'Inputs changed. Previous result retired; compare again.';
  };
  scenario.addEventListener('change', retire);
  tag.addEventListener('change', retire);
  get('kc-run').addEventListener('click', () => {
    const r = runCommitment(scenario.value as CommitmentCase, tag.value === '32' ? 32 : 16);
    output.hidden = false;
    status.className = `status ${r.ambiguous ? 'danger' : 'ok'}`;
    status.textContent = r.ambiguous
      ? 'BOTH ACCEPTED — the ciphertext does not identify a unique key.'
      : `Only ${Number(r.acceptedA) + Number(r.acceptedB)} of the two contexts accepted this ciphertext and tag.`;
    get('kc-a').textContent = r.acceptedA ? 'ACCEPTED' : 'REJECTED';
    get('kc-b').textContent = r.acceptedB ? 'ACCEPTED' : 'REJECTED';
    get('kc-limit').textContent = r.ambiguous
      ? 'Both authentication checks passed, but key commitment failed for these two different key/AD contexts. A longer tag does not repair this constructed state collision.'
      : 'This control rejects the second context. Ordinary rejection of a changed context does not establish key commitment against deliberately constructed contexts.';
    get('kc-trace').innerHTML = r.trace.map(row => `<tr><th scope="row">${row.stage}</th>${row.bits.map(n => `<td>${n}</td>`).join('')}</tr>`).join('');
    get('kc-bytes').textContent = [
      `Key A: ${r.keyA}`, `Key B: ${r.keyB}`, `Shared nonce: ${r.nonce}`,
      `AD A: ${r.adA}`, `AD B: ${r.adB}`, `Ciphertext sent to both: ${r.ciphertext}`,
      `Tag sent to both: ${r.tag}`, `Ciphertext freshly generated by B: ${r.ciphertextB}`,
      `Tag freshly generated by B: ${r.tagB}`,
      `Plaintext A: ${r.plaintextA ?? 'not released'}`, `Plaintext B: ${r.plaintextB ?? 'not released'}`,
      `States after AD: ${r.stateEqual ? 'identical' : 'different'}`,
    ].join('\n');
  });
}
