# Construct Core - Project Context

`construct-core` is the central cryptographic and orchestration engine for **Construct Messenger**. It provides end-to-end encryption (E2EE), session management, and traffic protection for cross-platform clients (iOS, macOS, Desktop).

## Architecture & Core Concepts

- **I/O-Free Core**: The library is designed to be pure and deterministic. All side effects (storage, networking, logging) are delegated to the host platform via the `PlatformBridge` callback interface and the `Action` system.
- **Orchestration Layer**: The `OrchestratorCore` (in `src/orchestration`) is the main entry point. It processes `IncomingEvent`s and returns a sequence of `CfeAction`s for the platform to execute.
- **Crypto-Agility**: Implemented via the `CryptoProvider` trait, supporting both **Classic** (X25519, Ed25519) and **Post-Quantum Hybrid** (ML-KEM/Kyber) suites.
- **CFE (Construct Format Envelope)**: A custom binary format (using Postcard) used for state persistence and migration from legacy JSON formats.
- **UniFFI Bindings**: Cross-platform bindings are defined in `src/construct_core.udl` and implemented in `src/uniffi_bindings.rs`.

## Building and Running

### Key Commands
- **Build**: `cargo build`
- **Test**: `cargo test --all-features` (Required for full coverage including PQ schemes)
- **Benchmarks**: `cargo bench --bench crypto_bench`
- **Desktop Target**: `cargo build --features desktop` (Enables Tokio runtime)

### Feature Flags
- `ios` / `mac`: Enables UniFFI scaffolding and Swift bindings support.
- `post-quantum`: Enables ML-KEM-768 and ML-DSA support.
- `desktop`: Enables `tokio` runtime for desktop-specific use cases.

## Development Conventions

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

## Key Files
- `src/construct_core.udl`: UniFFI interface definition (The "Source of Truth" for the cross-platform API).
- `src/orchestration/orchestrator.rs`: Implementation of the main event loop.
- `src/crypto/mod.rs`: Entry point for cryptographic primitives.
- `src/cfe/mod.rs`: Definition of the Construct Format Envelope for state persistence.
- `Cargo.toml`: Workspace configuration and feature flag definitions.

---

## Shared Construct Docs Workflow

The vault's own `~/Code/construct-docs/AGENTS.md` is **authoritative** for how to contribute docs —
read it. The summary below is the operational subset for coding agents.

> **There is no pipeline anymore.** The old `raw/` → olw → `wiki/` three-way synthesis workflow is
> gone. Agents patch docs **directly** and write session/decision notes by hand. No olw, no
> `wiki/.drafts/`, no "let the pipeline cross-link it". `raw/` and `wiki/` no longer exist — the
> corpus is the flat domain folders (`architecture/`, `backend/`, `client/`, `cryptocore/`,
> `security/`, …) listed under *Documentation* above.

### Where durable reasoning goes

Any reasoning that informed a code change must survive beyond the chat session — conclusions,
trade-offs, and "why we didn't do X". After any session involving architectural changes, design
decisions, API/data-format changes, bug root-cause analysis, or non-obvious implementation choices:

1. **Always** write a session note at `~/Code/construct-docs/sessions/YYYY-MM-DD-<topic>.md`.
2. **Always** fill in `## Why` — the reasoning, considered alternatives, and why they were rejected.
   This is the most important section.
3. If the decision will constrain future work or the same question is likely to recur, also create
   or update `~/Code/construct-docs/decisions/<slug>.md`.
4. Patch the affected spec in its domain folder in the **same** session — keep specs current.
5. Before creating a new note, search for an existing one and extend it rather than duplicating.

Do not skip session notes for "small" changes — if non-trivial reasoning was involved, write it down.

### Session note format

Plain markdown, no YAML frontmatter. `[[wikilinks]]` to other sessions/decisions/specs are welcome
(Obsidian graph). Sections:

1. `## Context` — what problem prompted this work
2. `## What Changed` — concrete file/API/behaviour changes
3. `## Why` — the reasoning: alternatives considered and why rejected
4. `## Decisions` — discrete decisions, each as a one-liner
5. `## Open Questions` — known unknowns, deferred work

Decision records (`decisions/<slug>.md`) use: `## Context`, `## Decision`, `## Rationale`,
`## Consequences`, plus a **Status** (accepted | superseded | deferred) and **Date** header.

### Operational logging

- Append a one-line entry to `~/Code/construct-docs/log.md` after creating/updating a session or
  decision note. Format: `[YYYY-MM-DD HH:MM] note | <topic>`
- Keep detailed rationale out of `log.md` — it belongs in the session/decision note.
