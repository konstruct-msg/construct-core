# construct-core

**The cryptographic core of [Konstruct](https://github.com/konstruct-msg) — a privacy-first,
end-to-end encrypted messenger.**

[![Rust](https://img.shields.io/badge/Rust-1.96-orange.svg)](https://www.rust-lang.org/)
[![Edition](https://img.shields.io/badge/edition-2024-blue.svg)](https://doc.rust-lang.org/edition-guide/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## About

`construct-core` is the Rust crypto engine shared verbatim by every Konstruct client. iOS,
macOS, and Android run the *same* audited code via UniFFI rather than reimplementing crypto
per platform. It provides:

- **X3DH + PQXDH** asynchronous key agreement (classical and post-quantum hybrid)
- **Double Ratchet** for forward secrecy & post-compromise security
- **Crypto-agility** — pluggable cipher suites negotiated per session (`suite_id`)
- **Hybrid signatures** — Ed25519 + ML-DSA-65 (FIPS 204)
- **MLS (RFC 9420)** group primitives via `openmls`
- **Account recovery** — BIP39 mnemonic + SLIP-39 social (Shamir) recovery
- **Key transparency** — RFC 6962-style append-only Merkle log for identity-key auditing
- **Privacy Pass** — OPRF blind-token primitives (Ristretto255)
- **Binary session state** — CFE envelopes (no JSON/base64 in the crypto path)

Platforms: **iOS / macOS** (UniFFI Swift) and **Android** (UniFFI Kotlin). No WASM/Web
target — a cryptographically secure messenger can't be done as a PWA, so that path was
dropped long ago.

## Architecture

```
construct-core/
├── src/
│   ├── crypto/                 # cryptographic primitives
│   │   ├── handshake/          # X3DH key agreement
│   │   ├── messaging/          # Double Ratchet
│   │   ├── suites/             # cipher suites (classic, PQ-hybrid) + provider trait
│   │   ├── privacy_pass/       # OPRF blind tokens (Ristretto255)
│   │   ├── pq_x3dh.rs          # ML-KEM-768 post-quantum key agreement
│   │   ├── recovery.rs         # BIP39 account recovery
│   │   ├── social_recovery.rs  # SLIP-39 Shamir social recovery
│   │   ├── key_transparency.rs # RFC 6962 Merkle log
│   │   └── provider.rs         # CryptoProvider trait (crypto-agility)
│   ├── group/                  # MLS (RFC 9420) group messaging
│   ├── orchestration/          # session orchestration (OrchestratorCore)
│   ├── cfe/                    # CFE binary session-state envelopes
│   ├── traffic_protection/     # cover traffic, message padding, timing obfuscation
│   ├── storage/                # storage traits + in-memory store
│   ├── uniffi_bindings.rs      # UniFFI FFI surface (iOS/Android)
│   ├── construct_core.udl      # UniFFI interface definition
│   ├── pow.rs                  # Argon2id proof-of-work
│   └── device_id.rs            # device-id derivation
└── Cargo.toml
```

## Quick Start

### iOS / macOS

```toml
[dependencies]
construct-core = { git = "https://github.com/konstruct-msg/construct-core", features = ["ios"] }
```

Swift bindings are generated with UniFFI. In the `construct-messenger` app repo,
`./generate_swift_bindings.sh` builds the library and regenerates `construct_core.swift`.

### Android — download a pre-built artifact

You don't need Rust, the NDK, or `uniffi-bindgen` locally. CI builds the
artifact on every push to `main` and republishes a rolling pre-release tagged
`latest`. **Stable URL** (never changes):

```
https://github.com/konstruct-msg/construct-core/releases/download/latest/construct-core-android.tar.gz
```

One-liner to grab + extract:

```bash
curl -L -o construct-core-android.tar.gz \
  https://github.com/konstruct-msg/construct-core/releases/download/latest/construct-core-android.tar.gz
tar -xzf construct-core-android.tar.gz
```

What's inside:

```
jniLibs/
├── arm64-v8a/libconstruct_core.so       # 64-bit modern phones
├── armeabi-v7a/libconstruct_core.so     # 32-bit legacy devices
└── x86_64/libconstruct_core.so          # emulator
kotlin/
└── uniffi/construct_core/...             # auto-generated Kotlin bindings
README.md                                 # drop-in instructions
```

How to wire it into an Android Studio project — see `README.md` inside the
archive. (Short version: drop `jniLibs/` into `app/src/main/`, copy the
Kotlin files into your crypto package, build.)

For a **versioned** build (e.g. for a production release pin), find it on
the [Releases page](https://github.com/konstruct-msg/construct-core/releases)
under the relevant `vX.Y.Z` tag. The `latest` tag is rolling and always
points at the freshest `main`.

## Cryptography

Names follow NIST FIPS; informal names in parens.

### Classic suite (`suite_id = 1`) — production

| Component     | Algorithm             |
|---------------|-----------------------|
| Key agreement | **X25519** (ECDH)     |
| Signatures    | **Ed25519**           |
| AEAD          | **ChaCha20-Poly1305** |
| KDF           | **HKDF-SHA256**       |

### Post-quantum (`suite_id = 2`) — hybrid

| Component     | Algorithm                                       | Status |
|---------------|-------------------------------------------------|--------|
| Key agreement | **X25519 ⊕ ML-KEM-768** (FIPS 203, Kyber-768)   | ✅ Implemented — PQXDH mixes a Kyber OTPK into the root key |
| Signatures    | **Ed25519 + ML-DSA-65** (FIPS 204, Dilithium-3) | 🚧 Implemented (RustCrypto `ml-dsa`, seed-based), **not yet activated on the wire** |
| AEAD / KDF    | ChaCha20-Poly1305 / HKDF-SHA256                 | unchanged |

> **Hybrid = classical AND post-quantum** — both must verify, and an attacker must break
> both to forge. The ML-DSA-65 path uses RustCrypto `ml-dsa` (seed-based), identical to the
> Konstruct server, so hybrid signatures cross-verify byte-for-byte (pinned by an interop
> test). Older docs claiming "Kyber-1024" or "Dilithium deployed" are wrong.

## Features

| Feature         | Purpose                                                        |
|-----------------|----------------------------------------------------------------|
| `ios`           | iOS/macOS bindings via UniFFI (+ VEIL transport, MLS)          |
| `mac`           | Native macOS build (same surface as `ios`)                     |
| `android`       | Android JNI/Kotlin bindings via UniFFI                         |
| `post-quantum`  | ML-KEM-768 + ML-DSA-65 post-quantum cryptography               |
| `desktop`       | Desktop testing support (Tokio runtime)                        |

`default = []` — opt into a platform/feature set explicitly. The `ios`/`mac`/`android`
features pull in `construct-veil` (path dependency) and `openmls`.

## Testing

```bash
# Core crypto, including the PQ suites
cargo test --features post-quantum

# Security audit (advisory policy in .cargo/audit.toml)
cargo audit
```

> `--all-features` requires the sibling `construct-veil` crate checked out at `../construct-veil`
> (pulled in by `ios`/`mac`/`android`).

## License

MIT — see [LICENSE](LICENSE).
