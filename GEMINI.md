# 🔐 Construct Core - Project Context

`construct-core` is the central cryptographic and orchestration engine for **Construct Messenger**. It provides end-to-end encryption (E2EE), session management, and traffic protection for cross-platform clients (iOS, macOS, Desktop).

## 🏗️ Architecture & Core Concepts

- **I/O-Free Core**: The library is designed to be pure and deterministic. All side effects (storage, networking, logging) are delegated to the host platform via the `PlatformBridge` callback interface and the `Action` system.
- **Orchestration Layer**: The `OrchestratorCore` (in `src/orchestration`) is the main entry point. It processes `IncomingEvent`s and returns a sequence of `CfeAction`s for the platform to execute.
- **Crypto-Agility**: Implemented via the `CryptoProvider` trait, supporting both **Classic** (X25519, Ed25519) and **Post-Quantum Hybrid** (ML-KEM/Kyber) suites.
- **CFE (Construct Format Envelope)**: A custom binary format (using Postcard) used for state persistence and migration from legacy JSON formats.
- **UniFFI Bindings**: Cross-platform bindings are defined in `src/construct_core.udl` and implemented in `src/uniffi_bindings.rs`.

## 🛠️ Building and Running

### Key Commands
- **Build**: `cargo build`
- **Test**: `cargo test --all-features` (Required for full coverage including PQ schemes)
- **Benchmarks**: `cargo bench --bench crypto_bench`
- **Desktop Target**: `cargo build --features desktop` (Enables Tokio runtime)

### Feature Flags
- `ios` / `mac`: Enables UniFFI scaffolding and Swift bindings support.
- `post-quantum`: Enables ML-KEM-768 and ML-DSA support.
- `desktop`: Enables `tokio` runtime for desktop-specific use cases.

## 📜 Development Conventions

### 1. Architectural Integrity
- **Logic vs. I/O**: Keep business logic in the `Orchestrator`. Never perform direct I/O (filesystem, network) inside the core. Use `Action`s to request these operations from the platform.
- **State Management**: Orchestrator state should be exportable/importable via `export_orchestrator_state()` and `import_orchestrator_state()`.

### 2. Cryptography
- Use `CryptoProvider` abstractions instead of hardcoding specific algorithms where possible.
- Sensitive data must be handled with `Zeroize` where appropriate.
- Hybrid PQ-Classic schemes are preferred for long-term security.

### 3. Cross-Platform Boundary (UniFFI)
- When modifying the public API, update `src/construct_core.udl` and ensure the `uniffi_bindings.rs` matches.
- Prefer passing `bytes` (sequence<u8>) or `string` for complex data to ensure compatibility across languages.

### 4. Serialization
- Use **Postcard** for internal binary storage (CFE).
- Use **Serde JSON** only for legacy compatibility or human-readable exports.
- All persistent state should be versioned.

## 📂 Key Files
- `src/construct_core.udl`: UniFFI interface definition (The "Source of Truth" for the cross-platform API).
- `src/orchestration/orchestrator.rs`: Implementation of the main event loop.
- `src/crypto/mod.rs`: Entry point for cryptographic primitives.
- `src/cfe/mod.rs`: Definition of the Construct Format Envelope for state persistence.
- `Cargo.toml`: Workspace configuration and feature flag definitions.
