# crypto-lab-aegis-gate

## What It Is
Browser-based AEGIS-256 authenticated encryption demo implementing
draft-irtf-cfrg-aegis-aead-18 (CFRG, October 2025). AEGIS-256 is an
AES-based AEAD designed for high-performance applications, using the AES
round function directly to build a sponge-like construction with 768-bit
state and 256-bit nonces. All 6-state updates, AES round function, and
the authentication tag derivation are implemented from the draft spec
and verified against the official JSON test vectors. No external crypto
libraries are used; the AES S-box, ShiftRows, MixColumns, and GF(2^8)
multiplication are implemented from FIPS 197.

## When to Use It
- Understanding AES-based AEADs beyond AES-GCM and how nonce size changes deployment risk
- Teaching sponge-like AEAD construction with a 6-block update function
- Comparing nonce handling: 96-bit (AES-GCM) vs 256-bit (AEGIS-256)
- Evaluating AEGIS-256 ideas for high-throughput protocols and systems
- Not for interoperability-critical TLS production paths today; AEGIS is not yet a TLS cipher suite

## Live Demo
https://systemslibrarian.github.io/crypto-lab-aegis-gate/

## What Can Go Wrong
- AEGIS is a CFRG Informational draft, not a finalized RFC standard
- Nonce reuse is catastrophic: same key+nonce across messages leaks plaintext relationships and breaks security
- This implementation is pure TypeScript for education, not native-speed production crypto
- Key commitment details differ by variant; review draft security considerations for protocol-level assumptions

## Real-World Usage
Designed by Hongjun Wu and Bart Preneel as a CAESAR finalist and specified
in draft-irtf-cfrg-aegis-aead revisions through October 2025. AEGIS-256 is
approved by OWASP ASVS and approved for government data processing by the
Belgian National Data Protection Authority. Production and ecosystem support
includes libsodium (optional), Zig standard library, .NET 8+, OpenSSL
providers, Rust crates, and high-performance edge/networking environments.