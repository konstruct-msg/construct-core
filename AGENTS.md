# AGENTS.md — construct-core

The rules this project paid for in its first year, and the invariants of this repository. Each
line is here because breaking it already cost something; the incident behind it lives in the
vault. If a rule here and your plan disagree, the rule wins until a `decisions/` note says
otherwise.

`construct-core` is the I/O-free cryptographic and orchestration engine of Construct Messenger:
E2EE, session lifecycle, MLS, history transfer, traffic protection. Every client (iOS, macOS,
Android) calls it through UniFFI. **It is where the protocol lives**: a decision two clients must
compute identically is made here, or it is made twice and diverges silently.

## Read first

| Area | File |
|---|---|
| Why these rules exist; the checklist before any new protocol feature | `~/Code/construct-docs/decisions/rules-from-the-first-year.md` |
| The API surface (source of truth, check before adding an export) | `src/construct_core.udl` |
| How the core is driven | `cargo run --example two_devices` · `examples/two_devices.rs` |
| Session lifecycle is one machine | `~/Code/construct-docs/decisions/session-is-one-state-machine.md` · `sessions-renew-by-sending.md` |
| First message opens without the server | `~/Code/construct-docs/decisions/first-message-opens-without-the-server.md` |
| Identity spaces; a peer is a set of devices | `~/Code/construct-docs/decisions/identity-spaces.md` · `a-peer-is-a-set-of-devices.md` |
| One meaning, one carrier (before any field, counter, constant, timeout) | `~/Code/construct-docs/decisions/one-meaning-two-carriers.md` |
| Content types, wire format, testing | `~/Code/construct-protos/conformance/knst_content_types.json` · `decisions/wire-format-one-authority.md` · `decisions/testing-by-pure-decision.md` |
| Everything else | `~/Code/construct-docs` (vault; its own `AGENTS.md` is authoritative) |

## The Zen of Konstruct

```
Someone has solved it before. Read them first.
The core decides; the app executes.
A message names the state it means. Time is not an address.
Reproduce, then fix.
One meaning, one carrier.
Bytes stay bytes.
Measure, then build.
The effect is the proof, not the exit code.
A test that cannot fail is worse than no test.
Boring before new.
Temporary is permanent, unless something checks it.
What nothing reads is not sent.
Silence is the worst failure: a message that never appears raises no error.
```

Canonical source: `~/Code/construct-docs/decisions/rules-from-the-first-year.md` — change it there first.

## Rules

1. **Prior art first.** Before any mechanism, write down how Signal / MLS (RFC 9420) / Matrix solve
   it and why we deviate. Group key management is MLS, not ours. END_SESSION reinvented for eight
   months what Signal has had since 2016.
2. **The core decides.** Anything two clients must compute identically, anything that reads or
   writes ratchet/session state, any *plan* (which sessions an operation touches) and the
   *lifecycle phase* of a device pair is exported from here — not described for clients to
   rebuild. "The client must compute X the same way" means: export X. Take a **set of device ids,
   return a decision over it**.
3. **A control message names the state it refers to** (epoch, ratchet key, number). A fix that
   adds a timer, cooldown, window, tie-break or retry budget means the message has no address —
   stop and give it one. Two clients retrying on different clocks do not error, they storm.
4. **Reproduce before fixing.** A two-party (N-party for groups) test that fails deterministically
   comes first; the fix counts when it turns green.
5. **One meaning, one carrier; different meanings, different types.** Identifiers are distinct
   types. A comment saying two things "must match" means one should be a call to the other.
6. **Bytes stay bytes**, source to destination (see UDL `bytes` below).
7. **Measure, then build** — for anything on the network or performance path.
8. **Verify the effect, not the exit code.** A `cargo test` that did not print `Compiling` may
   have re-run a stale binary: look for it.
9. **A test must be able to fail.** Put the decision in a pure function and test that;
   mutation-check every new test (one mutation at a time, an unapplied mutation is fatal, restore
   by shasum). A bare `cargo test` skips every `mac`-gated session test and still reports green.
10. **Depth before breadth.** No new protocol surface (groups, rooms) until 1:1 sessions are boring
    on the stand and with testers.
11. **A temporary exception has an end date and a check.**
12. **A branch and a PR, always** (see Git).

**A change on the delivery or crypto path answers three questions** in its commit message:
(1) what does the server or any relay learn that it did not before; (2) what can a party —
server, sender, sibling device — withhold or substitute that it could not before; (3) which trust
boundary moves, and which way. An honest "something" to 1 or 2 is a `decisions/` note, not a merge.

**A producer with no consumer is a defect.** A send, signal or action lands with its reader in
the same change, or is removed.

## Invariants of this repo

### Architecture

- **I/O-free and deterministic.** Side effects (storage, network, filesystem) are `Action`s the
  platform executes; `OrchestratorCore` (`src/orchestration`) takes `IncomingEvent`s and returns
  `CfeAction`s. Logging goes through `tracing`. Orchestrator state stays exportable/importable
  (`export_orchestrator_state` / `import_orchestrator_state`). I/O lives in `construct-store`.
- **Crypto-Agility.** `CryptoProvider` is the abstraction (Classic: X25519/Ed25519; Hybrid:
  Ed25519 + ML-DSA-65), but every session is built on `ClassicSuiteProvider`. Post-quantum comes
  from PQXDH v2 (mandatory ML-KEM-1024 in the initial key; `crypto::kyber_prekeys`,
  `orchestration::pq_prekey_plan`) and the suite-3 sparse ML-KEM-768 ratchet, not from swapping
  the provider. Secrets use `Zeroize`.
- **Identity space.** This crate speaks `CryptoDeviceId` only (`contact_id` everywhere;
  `set_local_user_id` is the one seam). It never learns `ServerUserId` — the client translates
  account → devices and hands over the set.

### Session lifecycle

- **A session renews by sending.** A message carrying the handshake header (ML-KEM ciphertext)
  opens a new state beside the held one; previous states are kept and the one that decrypts is
  promoted. INITIATOR and RESPONDER paths are distinct (`init_session` vs `open_receiving`).
- **An unreadable message is answered with DECRYPTION_ERROR (type 28) naming the state** it was
  written on; the writer's core retires that state only if it is current, and resends the named
  message once. Reset, chat/contact deletion and logout are **local** — nothing is sent.
- **Never rebuild:** END_SESSION, SESSION_RESET_INIT, `session_ready`, ping, confirm windows,
  tie-breaks, heal, cooldowns, stale-by-timestamp checks.
- **Receiving fetches nothing:** a first message opens with the key its sender certificate names,
  once the core has checked the server's signature.
- **The core owns the queue of messages waiting for a session**; clients keep envelopes only.
- **Ask the core for the operation, never for the key** (`signWithDeviceKey`,
  `openSealedToDevice`, `deviceCopyTag*`, MLS stores). Sealed boxes, media sealing, history
  transfer (CTH1/CTT1/CTHF, `src/history/`) are protocol and live here, not written twice.
- **Sealed sender:** after unseal only the inner `contentType` routes; the outer one is generic
  on purpose. A new content type adds its row to `knst_content_types.json` in the same change.
- Before adding an API, check it is not already exported under another name
  (`derive_device_id`, `get_all_session_contact_ids`, `get_session_health` were each reimplemented
  or ignored client-side).

### UniFFI boundary and serialization

- **Byte data is `bytes` in the UDL, never `sequence<u8>`.** Both are `Vec<u8>` in Rust, so nothing
  here tells them apart; the bindings do: `bytes` is `Data`/`ByteArray` (one block copy),
  `sequence<u8>` is `[UInt8]` copied per byte (`List<UByte>`, an object per byte, in Kotlin).
  `tests/udl_bytes_test.rs` fails on a new one.
- Changing the public API means updating `src/construct_core.udl` and `src/uniffi_bindings.rs`
  together; the UDL is the source of truth.
- CFE payloads are MessagePack (`rmp_serde::to_vec_named`, named fields so fields can be added with
  `#[serde(default)]`) in a 16-byte header (magic, version, type, flags, length, CRC32). JSON is
  legacy migration and human-readable export only; do not add another format. Persistent state is
  versioned. Session state persists as CFE from `export_session_bytes_for`.
- `construct-tui` is paused (2026-09-25) and does not build against `main`; a change here need not
  keep it building. It is brought up to date in one piece when work resumes.

### Versioning (§5)

- **A commit that changes what a client can observe bumps `version` in `Cargo.toml` in the same
  commit**, with `Cargo.lock`, and names it in the subject — `feat(pqxdh)!: … (0.22.0)`.
  Observable: the UDL, a wire or file format, persisted state, a protocol decision.
- `0.x.y`: a breaking change (`!`) or a new export is **minor**; a fix that changes no signature is
  **patch**. Refactors, tests and docs do not bump. `construct-store` (`store/Cargo.toml`) follows
  the same rule on its own version.
- Why: apps stamp `0.22.0+<hash>`, Android's pairing lock and release notes name it; fifteen
  commits (four breaking) once shipped as one number.

### Build, test, checks

- `cargo build` · `cargo test` · **`cargo test --features mac`** for the UniFFI surface and the
  PQ-gated session tests (bare `cargo test` skips them and reports green) · `cargo bench --bench
  crypto_bench`. Features: `ios`/`mac` (UniFFI + construct-veil + MLS), `android` (same for
  Kotlin), `store` (store + `history::project` without UniFFI; the platform features include it).
  `post-quantum` is an empty alias kept for old commands: ML-KEM and ML-DSA are unconditional.
  `--all-features` builds; construct-veil is a pinned git dependency, no sibling checkout needed.
- **Pre-push checks, before committing:** `git config core.hooksPath .githooks` (per clone). The
  `pre-push` hook runs `cargo metadata --locked`, `cargo fmt --all -- --check`,
  `.github/scripts/check-secret-logging.sh` (key material in logs), then
  `cargo clippy --all-targets -- -D warnings` — the CI order. Also clippy `--features post-quantum`
  when touching gated code (a shrinking change once tripped `large_enum_variant`).
- A `rustc` older than `rust-version` makes cargo re-run a stale binary and report green; the
  toolchain is pinned in `rust-toolchain.toml`.
- The version stamp (`+<hash>`) only refreshes when `.git/HEAD` changes: `touch .git/HEAD` after
  a fresh commit before building the xcframework.

## Git and process

- **Never commit on `main`.** Topic branch (`feat|fix|docs|chore|test/<topic>`) from an up-to-date
  `main`, PR into `main`; `main` is what a release is built from and **the owner merges**. Agents
  push and open the PR only when asked.
- Check `git branch --show-current` and `git status` before every commit: other sessions share
  the tree. Never `checkout -- .`, `restore .`, `reset --hard` or `stash`; name the files. Never
  rewrite pushed history. A commit made on `main` by mistake and not pushed moves with
  `git branch <topic> && git reset --keep origin/main && git switch <topic>`.
- Conventional Commits.

## Docs

The vault (`~/Code/construct-docs`, its `AGENTS.md` authoritative) holds everything not in this
repo; search it before an architectural decision. After work: progress into the task note
(`todo/NNN-*.md`); a `decisions/<slug>.md` for anything that constrains future work; a session
note only for a root cause found the hard way (`## Why` mandatory); one line in `log.md`.
