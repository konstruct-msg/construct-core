# 🔐 Construct Core

**Core cryptographic engine for Construct Messenger with end-to-end encryption**

[![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 🎯 About

Construct Core is the cryptographic engine powering Construct Messenger. It provides:

- ✅ **Double Ratchet Protocol** (Signal Protocol) for forward secrecy
- ✅ **X3DH** for asynchronous key agreement
- ✅ **Crypto-Agility** to support various cryptographic algorithms
- ✅ **Post-Quantum Ready** architecture for hybrid schemes
- ✅ **Multi-Platform** support (iOS via UniFFI, Web via WASM)

## 🏗️ Architecture

```
construct-core/
├── src/
│   ├── crypto/              # Cryptographic primitives
│   │   ├── handshake/        # X3DH key agreement
│   │   ├── messaging/        # Double Ratchet
│   │   ├── suites/           # Crypto suites (Classic, PQ-Hybrid)
│   │   └── provider.rs       # CryptoProvider trait
│   ├── api/                  # High-level API
│   ├── protocol/             # Protocol structures
│   ├── error.rs              # Error types
│   └── platforms/            # Platform-specific code
│       ├── ios/               # iOS bindings (UniFFI)
│       └── wasm/              # WASM bindings
└── Cargo.toml
```

## 🚀 Quick Start

### For iOS

```toml
[dependencies]
construct-core = { git = "https://github.com/construct-msg/construct-core", features = ["ios"] }
```

### For Android — download a pre-built artifact

You don't need Rust, the NDK, or `uniffi-bindgen` locally. CI builds the
artifact on every push to `main` and republishes a rolling pre-release tagged
`latest`. **Stable URL** (never changes):

```
https://github.com/construct-msg/construct-core/releases/download/latest/construct-core-android.tar.gz
```

One-liner to grab + extract:

```bash
curl -L -o construct-core-android.tar.gz \
  https://github.com/construct-msg/construct-core/releases/download/latest/construct-core-android.tar.gz
tar -xzf construct-core-android.tar.gz
```

What's inside:

```
jniLibs/
├── arm64-v8a/libconstruct_core.so       # 64-bit modern phones
├── armeabi-v7a/libconstruct_core.so     # 32-bit legacy devices
└── x86_64/libconstruct_core.so          # emulator
kotlin/
└── uniffi/construct_core/...            # auto-generated Kotlin bindings
README.md                                # drop-in instructions
```

How to wire it into an Android Studio project — see `README.md` inside the
archive. (Short version: drop `jniLibs/` into `app/src/main/`, copy the
Kotlin files into your crypto package, build.)

For a **versioned** build (e.g. for a production release pin), find it on
the [Releases page](https://github.com/construct-msg/construct-core/releases)
under the relevant `vX.Y.Z` tag. The `latest` tag is rolling and always
points at the freshest `main`.

## 🔐 Cryptography

### Classic Suite (v1)

| Component     | Algorithm             |
|---------------|-----------------------|
| Key Agreement | X25519 (ECDH)        |
| Signatures    | Ed25519              |
| AEAD          | ChaCha20-Poly1305    |
| KDF           | HKDF-SHA256          |

### Post-Quantum Hybrid Suite (v2) - In Development

| Component     | Algorithm                |
|---------------|--------------------------|
| Key Agreement | X25519 ⊕ Kyber768        |
| Signatures    | Ed25519 + Dilithium3     |
| AEAD          | ChaCha20-Poly1305        |

## 📦 Features

- `ios` - iOS/macOS bindings via UniFFI
- `wasm` - WebAssembly bindings via wasm-bindgen
- `post-quantum` - Post-quantum cryptography support
- `desktop` - Desktop testing support (Tokio runtime)

## 🧪 Testing

```bash
cargo test --all-features
```

## 📄 License

MIT License - see [LICENSE](LICENSE) for details
