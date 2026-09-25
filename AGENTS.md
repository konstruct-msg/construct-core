# Construct Core - Project Context

`construct-core` is the central cryptographic and orchestration engine for **Construct Messenger**. It provides end-to-end encryption (E2EE), session management, and traffic protection for cross-platform clients (iOS, macOS, Desktop).

## Architecture & Core Concepts

- **I/O-Free Core**: The library is designed to be pure and deterministic. Side effects (storage, networking) are requested from the host platform as `Action`s returned by the orchestrator. `PlatformBridge` is exported over UniFFI but the orchestrator does not call it; logging goes through `tracing`.
- **Orchestration Layer**: The `OrchestratorCore` (in `src/orchestration`) is the main entry point. It processes `IncomingEvent`s and returns a sequence of `CfeAction`s for the platform to execute.
- **Crypto-Agility**: The `CryptoProvider` trait has a **Classic** (X25519, Ed25519) and a **Hybrid** (Ed25519 + ML-DSA-65 signatures) implementation, but every session is built on `ClassicSuiteProvider`. Post-quantum protection comes from **PQXDH v2** — an ML-KEM-1024 secret in the session's initial key, mandatory, with Kyber keys owned by the core (`crypto::kyber_prekeys`, `orchestration::pq_prekey_plan`) — and the mandatory suite-3 sparse ML-KEM-768 ratchet, not from swapping the provider.
- **CFE (Construct Format Envelope)**: A custom binary format — 16-byte header (magic, version, type, flags, payload length, CRC32) around a MessagePack payload (`rmp_serde::to_vec_named`) — used for state persistence and migration from legacy JSON formats.
- **UniFFI Bindings**: Cross-platform bindings are defined in `src/construct_core.udl` and implemented in `src/uniffi_bindings.rs`.

## Building and Running

### Key Commands
- **Build**: `cargo build`
- **Test**: `cargo test --features post-quantum` for the core; `cargo test --features mac` to include the UniFFI surface. `--all-features` also builds (construct-veil is a pinned git dependency — no sibling checkout needed).
- **Benchmarks**: `cargo bench --bench crypto_bench`
- **Hooks**: `git config core.hooksPath .githooks` — `pre-push` runs `cargo metadata --locked`, `cargo fmt --check`, the key-material-in-logs check, then clippy default + `post-quantum` (`-D warnings`), matching CI. Not a pre-commit hook: clippy is too slow to run on every commit.

### Feature Flags
- `ios` / `mac`: Enables UniFFI scaffolding and Swift bindings support (+ construct-veil, MLS, `post-quantum`).
- `android`: The same surface for Kotlin (UniFFI JNI) + construct-veil + `post-quantum`.
- `post-quantum`: Enables ML-KEM-1024/768 and ML-DSA support. Implied by every platform feature (a `compile_error!` in `lib.rs` guards that). Without it the core opens classical sessions only, which platform builds refuse.

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
- **`construct-tui` is paused** (2026-09-25) until iOS, Android and multi-device are settled. It
  uses this crate's `pub` Rust modules by path, and it already does not build against `main`. A
  change here does not have to keep it building or be checked against it; it will be brought up to
  date in one piece when work on it resumes.

**If two clients must agree on it, this crate must export it — not describe it.** There are two
clients now (`construct-messenger` on iOS, `construct-android`). Anything a client would
otherwise reimplement is a decision that will diverge, and divergence here is silent: the copy is
dropped as foreign, the message never appears, and neither side can say which one is right. The
`content_type` split between iOS and the TUI was found by comparing tables, not by a failure.

So a rule the clients must follow is not documentation — it is a missing export. If you find
yourself writing "the client must compute X the same way", export X.

**What belongs here, restated for the receiving end** (the clients carry the mirror of this in their
own `AGENTS.md`): anything two clients must compute identically, anything that reads or writes
ratchet/session state, **any plan** — "which sessions does this operation touch" — and the
**lifecycle phase of a pair of devices** (absent / opening / established / healing / tearing
down). A plan answers who; the machine answers what state that pair is in. Both are protocol.
Clients rebuild the machine as a pile of cooldowns because each incident feels local. It is
not: two clients that retry on different clocks do not error, they storm. Guide:
`construct-docs/decisions/session-is-one-state-machine.md`.

**What deliberately does not belong here:** `ServerUserId`. This crate speaks `CryptoDeviceId` only
(`contact_id` everywhere; `set_local_user_id` is the one seam), and that stays. The consequence is a
shape to keep in mind when designing an API: **take a set of device ids, return a decision over
it.** A client that translates `account → devices` before calling is doing its own job; a client
that must then also decide *which* of them to act on has been handed a job this crate should have
done, and the next client will do it differently.

Before adding an API, check it is not already there under another name. `derive_device_id`,
`tie_break_role`, `get_all_session_contact_ids` and `get_session_health` all exist, and each has
been reimplemented or ignored client-side at least once.

### 4. Serialization
- CFE payloads are **MessagePack** (named fields, so fields can be added with `#[serde(default)]`). JSON is for legacy migration only. Do not add another format.
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
