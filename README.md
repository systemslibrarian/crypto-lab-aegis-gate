# crypto-lab-aegis-gate

## What It Is
Browser-based AEGIS-256 authenticated encryption demo implementing
[RFC 10032](https://www.rfc-editor.org/rfc/rfc10032) (CFRG, September 2026),
an IRTF Informational RFC rather than an Internet Standard. AEGIS-256 is an
AES-based AEAD designed for high-performance applications, using the AES
round function directly to build a sponge-like construction with 768-bit
state and 256-bit nonces. All 6-state updates, AES round function, and
the authentication tag derivation are implemented from the RFC
and verified against its Appendix A.3 test vectors. Both the 128-bit and
256-bit tag variants are supported. No external crypto libraries are used;
the AES S-box, ShiftRows, MixColumns, and GF(2^8) multiplication are
implemented from FIPS 197.

The page opens by replaying all nine encryption and rejection vectors in RFC 10032 Appendix A.3 through this
implementation's own encrypt path, in your browser, and showing the result
byte-for-byte — both the five encryption vectors (ciphertext, 128-bit tag,
256-bit tag, and a decrypt round-trip) and the four must-reject forgery
vectors, so "verified against the official vectors" is something you watch
happen rather than take on trust. The same vectors are exercised in the test
suite (`npm test`), and a guard test keeps the in-browser copy byte-identical
to the authoritative fixture so the two cannot drift.

A collapsible **"New to AEAD?" primer** sits above Exhibit 1, defining
plaintext, ciphertext, tag, nonce, and associated data in plain language —
before any hex appears — so a newcomer has an on-ramp and a cryptographer can
skip it.

Seven interactive exhibits go beyond a byte dump:

- **Encrypt / tamper (Exhibit 1)** — encrypt your own input with either tag
  length, flip a single bit of ciphertext or tag and see exactly where it
  landed, and watch the recomputed tag diverge in nearly every byte. A failed
  tamper links straight to the avalanche in Exhibit 2 that explains why one bit
  changes the whole tag. Any scenario is shareable as a URL, so a class can open
  one link in a known state.
- **The state machine, live (Exhibit 2)** — step Init / Absorb / Enc / Finalize
  on the real implementation, with an animated dataflow diagram, byte-level
  diff highlighting between steps, the extracted keystream `Z`, and the
  compacted RFC 10032 pseudocode alongside, highlighting whichever function ran.
  A collapsible **"open the black box"** sub-panel runs one real AES round on the
  live S0 block stage by stage — SubBytes (S-box), ShiftRows, MixColumns, and the
  round-key XOR — so "AES-based" becomes a mechanism you watch, not an assertion.
  An avalanche heatmap shows one flipped nonce bit diffusing to ~50% of the
  768-bit state across the 16 setup updates.
- **The nonce-reuse catastrophe (Exhibit 3)** — encrypt two messages under the
  same key+nonce and recover the secret from `C_A ⊕ C_B ⊕ A`, with the
  genuinely-leaked prefix marked. Because AEGIS folds plaintext into its state
  (it is not a pure stream cipher), the first two blocks always leak while the
  tail is protected — an honest, more interesting picture than a full two-time pad.
- **Birthday-bound explorer (Exhibit 4)** — a slider comparing random-nonce
  collision probability for 96-bit vs 256-bit nonces, the reason AEGIS-256 exists.
- **Live throughput benchmark (Exhibit 5)** and the **AEGIS family table
  (Exhibit 6)** covering AEGIS-128L, 256, and the 128X/256X parallel variants.
- **One ciphertext, two keys (Exhibit 7)** — replay the AEGIS-256 vector from
  Derbez et al., [Key Committing Attacks against AES-based AEAD Schemes](https://doi.org/10.46586/tosc.v2024.i1.135-157),
  Appendix A.2 (journal p.156 / PDF p.22). Two known keys with constructed,
  different associated data accept the same ciphertext/tag and plaintext. The
  real six-block state trace shows convergence after AD; using identical AD or
  flipping a bit of the constructed AD rejects the second context. The 128-bit
  tag uses the published bytes; the 256-bit tag is recomputed by the real
  encryptor. This is a full-robustness counterexample, not unknown-key recovery
  or a forgery against a fixed unknown key. Longer tags do not repair this
  constructed state collision. Changing a control retires the previous result.

## When to Use It
- Understanding AES-based AEADs beyond AES-GCM and how nonce size changes deployment risk
- Teaching sponge-like AEAD construction with a 6-block update function
- Comparing nonce handling: 96-bit (AES-GCM) vs 256-bit (AEGIS-256)
- Evaluating AEGIS-256 ideas for high-throughput protocols and systems
- Not for interoperability-critical TLS production paths today; AEGIS is not yet a TLS cipher suite
- Do NOT rely on this pure-TypeScript build as production crypto — it is a teaching demo, not native-speed hardened code

## Live Demo

**[systemslibrarian.github.io/crypto-lab-aegis-gate](https://systemslibrarian.github.io/crypto-lab-aegis-gate/)**

The page replays the nine RFC 10032 Appendix A.3 encryption and rejection vectors in your browser, showing each result byte-for-byte, lets you encrypt and authenticate your own inputs with both the 128-bit and 256-bit tag variants, steps the AEGIS state machine beside the RFC pseudocode, and demonstrates the nonce-reuse catastrophe as a live known-plaintext recovery. The separate Update test vector is checked in the unit suite.

## What Can Go Wrong
- RFC 10032 is a finalized IRTF Informational RFC, not an Internet Standard or a TLS cipher suite
- Nonce reuse is catastrophic: same key+nonce across messages leaks plaintext relationships and breaks security
- This implementation is pure TypeScript for education, not native-speed production crypto
- A successful tag check need not identify a unique key: Exhibit 7 executes a
  known-key/variable-AD counterexample for AEGIS-256. This does not contradict
  fixed-key AEAD authenticity; attacker control and the security notion matter.

## Real-World Usage
- Designed by Hongjun Wu and Bart Preneel as a CAESAR competition finalist and described in RFC 10032 (September 2026)
- Implemented across the ecosystem, including libsodium and the Zig standard library
- Of active interest for high-throughput protocols and networking environments where AES hardware acceleration is available
- RFC publication records CFRG consensus but is not an IETF standards-track approval or regulatory certification; verify such claims independently

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-aegis-gate
cd crypto-lab-aegis-gate
npm install
npm run dev
```

## Build and Verify

```bash
npm ci
npm test
npx playwright install chromium
npm run build
npm run test:a11y
node tools/check-commitment-mutations.mjs
```

The unit suite includes the published commitment vector, both tag lengths,
and identical-AD / tampered-AD rejection controls. Browser checks exercise the
displayed authentication results, state convergence, and result retirement;
the accessibility sweep includes all six commitment scenarios. The mutation
runner independently breaks authentication, state differences, and the negative
claim, requiring each owning browser assertion to fail after a successful build,
then restores the original source and verifies the bundle hash.

## Related Demos
- [crypto-lab-aes-modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) — AES block cipher modes and AEAD (GCM/CCM) behavior.
- [crypto-lab-ascon](https://systemslibrarian.github.io/crypto-lab-ascon/) — lightweight sponge-based AEAD, the NIST Lightweight Cryptography standard.
- [crypto-lab-chacha20-stream](https://systemslibrarian.github.io/crypto-lab-chacha20-stream/) — ARX stream cipher and the danger of nonce reuse.
- [crypto-lab-shadow-vault](https://systemslibrarian.github.io/crypto-lab-shadow-vault/) — ChaCha20-Poly1305 authenticated encryption.
- [crypto-lab-nonce-guard](https://systemslibrarian.github.io/crypto-lab-nonce-guard/) — AES-GCM-SIV nonce-misuse-resistant AEAD.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
