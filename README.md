# crypto-lab-aegis-gate

## What It Is
Browser-based AEGIS-256 authenticated encryption demo implementing
draft-irtf-cfrg-aegis-aead-18 (CFRG, October 2025). AEGIS-256 is an
AES-based AEAD designed for high-performance applications, using the AES
round function directly to build a sponge-like construction with 768-bit
state and 256-bit nonces. All 6-state updates, AES round function, and
the authentication tag derivation are implemented from the draft spec
and verified against the official JSON test vectors. Both the 128-bit and
256-bit tag variants are supported. No external crypto libraries are used;
the AES S-box, ShiftRows, MixColumns, and GF(2^8) multiplication are
implemented from FIPS 197.

The page opens by replaying every official draft test vector through this
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

Six interactive exhibits go beyond a byte dump:

- **Encrypt / tamper (Exhibit 1)** — encrypt your own input with either tag
  length, flip a single bit of ciphertext or tag and see exactly where it
  landed, and watch the recomputed tag diverge in nearly every byte. A failed
  tamper links straight to the avalanche in Exhibit 2 that explains why one bit
  changes the whole tag. Any scenario is shareable as a URL, so a class can open
  one link in a known state.
- **The state machine, live (Exhibit 2)** — step Init / Absorb / Enc / Finalize
  on the real implementation, with an animated dataflow diagram, byte-level
  diff highlighting between steps, the extracted keystream `Z`, and the
  verbatim draft-18 pseudocode alongside, highlighting whichever function ran.
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

## When to Use It
- Understanding AES-based AEADs beyond AES-GCM and how nonce size changes deployment risk
- Teaching sponge-like AEAD construction with a 6-block update function
- Comparing nonce handling: 96-bit (AES-GCM) vs 256-bit (AEGIS-256)
- Evaluating AEGIS-256 ideas for high-throughput protocols and systems
- Not for interoperability-critical TLS production paths today; AEGIS is not yet a TLS cipher suite
- Do NOT rely on this pure-TypeScript build as production crypto — it is a teaching demo, not native-speed hardened code

## Live Demo

**[systemslibrarian.github.io/crypto-lab-aegis-gate](https://systemslibrarian.github.io/crypto-lab-aegis-gate/)**

The page replays every official draft test vector through its own encrypt path in your browser, showing each result byte-for-byte, lets you encrypt and authenticate your own inputs with both the 128-bit and 256-bit tag variants, steps the AEGIS state machine beside the draft pseudocode, and demonstrates the nonce-reuse catastrophe as a live known-plaintext recovery.

## What Can Go Wrong
- AEGIS is a CFRG Informational draft, not a finalized RFC standard
- Nonce reuse is catastrophic: same key+nonce across messages leaks plaintext relationships and breaks security
- This implementation is pure TypeScript for education, not native-speed production crypto
- Key commitment details differ by variant; review draft security considerations for protocol-level assumptions

## Real-World Usage
- Designed by Hongjun Wu and Bart Preneel as a CAESAR competition finalist and specified in draft-irtf-cfrg-aegis-aead through October 2025
- Implemented across the ecosystem, including libsodium and the Zig standard library
- Of active interest for high-throughput protocols and networking environments where AES hardware acceleration is available
- Because it is still a CFRG Informational draft rather than a finalized RFC, treat specific compliance or regulatory claims seen elsewhere as needing independent verification

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-aegis-gate
cd crypto-lab-aegis-gate
npm install
npm run dev
```

## Related Demos
- [crypto-lab-aes-modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) — AES block cipher modes and AEAD (GCM/CCM) behavior.
- [crypto-lab-ascon](https://systemslibrarian.github.io/crypto-lab-ascon/) — lightweight sponge-based AEAD, the NIST Lightweight Cryptography standard.
- [crypto-lab-chacha20-stream](https://systemslibrarian.github.io/crypto-lab-chacha20-stream/) — ARX stream cipher and the danger of nonce reuse.
- [crypto-lab-shadow-vault](https://systemslibrarian.github.io/crypto-lab-shadow-vault/) — ChaCha20-Poly1305 authenticated encryption.
- [crypto-lab-nonce-guard](https://systemslibrarian.github.io/crypto-lab-nonce-guard/) — AES-GCM-SIV nonce-misuse-resistant AEAD.

---

*One of 170+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
