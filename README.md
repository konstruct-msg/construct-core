# construct-core

**The cryptographic core of [Konstruct](https://github.com/konstruct-msg) — a privacy-first,
end-to-end encrypted messenger.**

[![Rust](https://img.shields.io/badge/Rust-1.96-orange.svg)](https://www.rust-lang.org/)
[![Edition](https://img.shields.io/badge/edition-2024-blue.svg)](https://doc.rust-lang.org/edition-guide/)
[![License](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

## About

`construct-core` is the Rust crypto engine shared verbatim by every Konstruct client. iOS,
macOS, and Android run the *same* code via UniFFI rather than reimplementing crypto
per platform. It provides:

- **X3DH** asynchronous key agreement, with an **ML-KEM-768 contribution** mixed into the root
  key when the peer publishes a Kyber prekey (see [Cryptography](#cryptography) for exactly how)
- **Double Ratchet** for forward secrecy & post-compromise security, optionally with a sparse
  continuous **ML-KEM-768 ratchet** (suite 3)
- **Hybrid signatures** — Ed25519 + ML-DSA-65 (FIPS 204) primitives
- **MLS (RFC 9420)** group primitives via `openmls` (`ios` / `mac` / `android` features)
- **Account recovery** — BIP39 mnemonic, and social recovery by Shamir secret sharing over
  GF(2⁸) encoded with the SLIP-39 *word list* (not the SLIP-39 share format — see below)
- **Key transparency** — client-side verification of an RFC 6962-style Merkle log
  (leaf/node hashing, inclusion and consistency proofs)
- **Privacy Pass** — blind-token OPRF over Ristretto255 with batched DLEQ proof verification
  (Construct-specific token derivation; not wire-compatible with RFC 9497)
- **Session orchestration** — a pure state machine (`OrchestratorCore`) that turns incoming events
  into actions for the platform; the core does no I/O itself
- **Binary persistence** — CFE envelopes (16-byte header with length and CRC32, MessagePack payload)

Platforms: **iOS / macOS** (UniFFI Swift) and **Android** (UniFFI Kotlin). No WASM/Web
target — a cryptographically secure messenger can't be done as a PWA, so that path was
dropped long ago.

## Architecture

```
construct-core/
├── src/
│   ├── crypto/                    # cryptographic primitives
│   │   ├── handshake/             # X3DH key agreement
│   │   ├── messaging/             # Double Ratchet (+ sparse PQ ratchet, suite 3)
│   │   ├── suites/                # classic and hybrid CryptoProvider implementations
│   │   ├── provider.rs            # CryptoProvider trait
│   │   ├── suite_id.rs            # suite ids 1 / 2 / 3
│   │   ├── pq_x3dh.rs             # ML-KEM-768 and ML-KEM-1024 keygen / encapsulate / decapsulate
│   │   ├── kyber_prekeys.rs       # the core's ML-KEM-1024 prekeys: SPK rotation, one-time pool
│   │   ├── kyber_prekey_auth.rs   # Kyber prekey signature check + PQ-authentication label
│   │   ├── sealed_sender/         # sealed-sender box + sender certificates
│   │   ├── device_copy_tag.rs     # per-message tag naming the device a copy is for
│   │   ├── invite_crypto.rs       # contact invites with ephemeral keys
│   │   ├── master_key.rs          # key backup / restore
│   │   ├── recovery.rs            # BIP39 account recovery
│   │   ├── social_recovery.rs     # Shamir social recovery (SLIP-39 word list)
│   │   ├── key_transparency.rs    # RFC 6962-style Merkle proof verification
│   │   ├── privacy_pass/          # OPRF blind tokens (Ristretto255)
│   │   ├── secret_bytes.rs        # SecretBytes: zeroed on drop, redacted in Debug
│   │   └── log_fingerprint.rs     # log-safe fingerprints of secrets
│   ├── orchestration/             # OrchestratorCore: session state machine, plans, actions
│   ├── group/                     # MLS (RFC 9420) group state store
│   ├── cfe/                       # CFE binary envelopes + record types
│   ├── wire_payload.rs, intake.rs # message wire format and intake
│   ├── traffic_protection/        # padding, cover-traffic and timing helpers
│   ├── storage/                   # models persisted by master_key
│   ├── uniffi_bindings.rs         # UniFFI FFI surface (iOS/macOS/Android)
│   ├── construct_core.udl         # UniFFI interface definition
│   ├── pow.rs                     # Argon2id proof-of-work
│   ├── device_id.rs               # device-id derivation
│   └── proofs/                    # Kani proofs (compiled only under `cargo kani`)
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

### Suite ids

| `suite_id` | Name | What a session with it is |
|---|---|---|
| 1 | `CLASSIC` | The table above. |
| 2 | `PQ_HYBRID` | **Reserved.** No session negotiates it; the hybrid-signature primitives below live under this name. |
| 3 | `PQ_RATCHET` | Classic Double Ratchet + a sparse continuous **ML-KEM-768** ratchet: a fresh KEM exchange rides on ordinary messages and its secret is mixed into message keys, epoch by epoch. Chosen only when this build has `post-quantum` and the peer's bundle advertises `supports_pq_ratchet`. A device that has advertised or used it before and now arrives without the flag is **refused** (`PQ_DOWNGRADE_REFUSED: PqRatchetWithdrawn`) — the flag is unsigned, and dropping it would otherwise silently downgrade to `CLASSIC`. |

### ML-KEM-768 at session start (independent of `suite_id`)

When the peer's bundle carries a Kyber prekey, the initiator encapsulates to it (ML-KEM-768,
FIPS 203) and mixes the shared secret into the X3DH root key when it sends the first message:
`root = HKDF(salt = rk, ikm = kem_ss, info = "construct-pqxdh-v1")`; the ciphertext travels in
that message, and the responder derives the same root. What that does **not** cover: the
initiator's first sending chain is derived from the X3DH secret *before* the mix, so message 0 and
everything sent before the first reply are protected by X25519 only. Every chain after the first
DH ratchet step depends on both. This is *not* Signal's PQXDH: the KEM secret is mixed in after
X3DH rather than into its initial derivation, and the KEM ciphertext is not bound into the KDF.

**Being replaced by PQXDH v2** (construct-docs `cryptocore/PQXDH_V2_DESIGN.md`,
`decisions/pqxdh-v2-mandatory-pq-cutover.md`): the ML-KEM-1024 secret goes into the initial key,
PQ is mandatory for new sessions, and the Kyber keys, their choice and decapsulation live in the
core. In place so far — the core's own **ML-KEM-1024 prekeys** (`crypto::kyber_prekeys`): a
signed prekey with two-phase rotation and 14-day retention of rotated-out keys, a one-time pool,
64-byte seeds as the only secret, each key signed (Ed25519 and hybrid) over
`"KonstruktX3DH-v1" || 0x00 0x11 || created_at (u64 BE) || kyber_public` so its age is the
device's word, not the server's. The handshake does not use them yet.

The Kyber prekey's Ed25519 signature is verified by the core
(`"KonstruktX3DH-v1" || 0x00 0x10 || kyber_public`, key-service field 12), and the session is
labelled accordingly — `SessionHealthReport.pq_authentication`:

| Bundle | Result |
|---|---|
| signature verifies | `Authenticated` — and the device is remembered as one that signs |
| no signature | `Unauthenticated` — protects against a passive recorder, not against whoever served the bundle |
| signature present and wrong | classical session, logged as a security event |
| no verifiable Kyber key from a device that signed before | session **refused** (`PQ_DOWNGRADE_REFUSED`) |

An unsigned Kyber OTPK is never preferred over a verified SPK (the server bundle does not carry
OTPK signatures yet).

### Hybrid signatures

**Ed25519 + ML-DSA-65** (FIPS 204) — both must verify. RustCrypto `ml-dsa`, seed-based, the same
implementation as the Konstruct server (cross-verification pinned by an interop test). The core
exposes them as primitives; iOS signs the Kyber SPK with them (key-service field 23) and checks
that signature itself. The core signs its own v2 Kyber prekeys with them and can check such a
signature (`check_kyber_prekey_hybrid_signature`), but no session decision uses it yet. Older docs
claiming "Dilithium deployed" are wrong; "Kyber-1024" becomes true with PQXDH v2.

### Social recovery

A 32-byte vault key is split with Shamir secret sharing over GF(2⁸) (threshold and share count
2–10). Each share is `index || 32 bytes || 2-byte SHA-256 checksum`, written as **28 words from the
SLIP-39 word list**. That is the word list only: no RS1024 checksum, identifier, groups or
passphrase encryption — shares are **not** interchangeable with SLIP-39 wallets. The share does
not record the threshold; too few shares reconstruct a wrong key, which the AEAD over the recovery
bundle then rejects.

### Traffic protection

PKCS#7-style padding to fixed blocks is applied inside the ratchet. Cover traffic and timing
helpers are exported for the platform to schedule. Dummy messages carry a plaintext marker so the
server can drop them — they hide patterns from a network observer, not from the server.

## Features

| Feature         | Purpose                                                        |
|-----------------|----------------------------------------------------------------|
| `ios`           | iOS/macOS bindings via UniFFI (+ VEIL transport, MLS)          |
| `mac`           | Native macOS build (same surface as `ios`)                     |
| `android`       | Android JNI/Kotlin bindings via UniFFI                         |
| `post-quantum`  | ML-KEM-768 + ML-DSA-65 post-quantum cryptography               |

`default = []` — opt into a platform/feature set explicitly. The `ios`/`mac`/`android`
features pull in `post-quantum`, `construct-veil` and `openmls`: a platform library always has
ML-KEM (a platform feature without `post-quantum` is a `compile_error!`). A build with no
platform feature and no `post-quantum` is classic-only and negotiates `CLASSIC` with everyone. `construct-veil` is a git dependency pinned
by commit (`rev` in `Cargo.toml`) — no sibling checkout is needed for any build.

## Testing

```bash
# Core crypto, including the PQ suites
cargo test --features post-quantum

# The exported UniFFI surface (compiled only with a platform feature)
cargo test --features mac

# Security audit (advisory policy in .cargo/audit.toml)
cargo audit
```

### Working on construct-veil at the same time

`Cargo.toml` pins `construct-veil` by commit. To build against a local checkout instead, patch it
from outside the repository — for one command:

```bash
cargo --config 'patch."https://github.com/konstruct-msg/construct-veil".construct-veil.path="../construct-veil"' \
  test --features mac
```

or persistently in your own `~/.cargo/config.toml`:

```toml
[patch."https://github.com/konstruct-msg/construct-veil"]
construct-veil = { path = "/path/to/construct-veil" }
```

While patched, cargo rewrites `Cargo.lock` to the local path — **do not commit that lock**; CI's
`cargo metadata --locked` step rejects it. To take a veil change for real: push it to
construct-veil, set `rev` in `Cargo.toml` to that commit, run `cargo update -p construct-veil`,
and commit both files.

### Pre-push

After clone, point git at the tracked hooks (local config, not copied by clone):

```bash
git config core.hooksPath .githooks
```

`pre-push` runs the same first steps as the Linux `Lint + Tests` job: `cargo fmt --all -- --check`, then clippy default and clippy `--features post-quantum`, both `-D warnings`. Bypass with `git push --no-verify` or skip clippy with `SKIP_CLIPPY=1`.

## License

Apache-2.0 — see [LICENSE](LICENSE). NOTICE file carries attribution.

## Trademark

**Konstruct™** / **Конструкт™** and the logo are trademarks of Maxim Eliseyev. The open-source
license on this code does **not** grant trademark rights — see [TRADEMARK.md](TRADEMARK.md).
Forks that distribute a modified version must rebrand.
