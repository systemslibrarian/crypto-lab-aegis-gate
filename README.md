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
byte-for-byte — so "verified against the official vectors" is something you
watch happen rather than take on trust. The same vectors are exercised in
the test suite (`npm test`), and a guard test keeps the in-browser copy
byte-identical to the authoritative fixture so the two cannot drift.

## When to Use It
- Understanding AES-based AEADs beyond AES-GCM and how nonce size changes deployment risk
- Teaching sponge-like AEAD construction with a 6-block update function
- Comparing nonce handling: 96-bit (AES-GCM) vs 256-bit (AEGIS-256)
- Evaluating AEGIS-256 ideas for high-throughput protocols and systems
- Not for interoperability-critical TLS production paths today; AEGIS is not yet a TLS cipher suite
- Do NOT rely on this pure-TypeScript build as production crypto — it is a teaching demo, not native-speed hardened code

## Live Demo

**[systemslibrarian.github.io/crypto-lab-aegis-gate](https://systemslibrarian.github.io/crypto-lab-aegis-gate/)**

The page replays every official draft test vector through its own encrypt path in your browser, showing each result byte-for-byte, and lets you encrypt and authenticate your own inputs with both the 128-bit and 256-bit tag variants of AEGIS-256.

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

*One of 60+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
