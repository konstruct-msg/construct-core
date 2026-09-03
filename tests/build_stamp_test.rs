//! The build stamp is read by `strings`, not by code, so nothing in the crate
//! would notice it going wrong. These tests pin the two halves a reader depends
//! on: the exact token the Android README greps for, and a commit that actually
//! names a build.
//!
//! The other half of this check lives in `.github/workflows/ci.yml`, which runs
//! the README's own command against every shipped `.so`. This file pins the
//! format; that step proves the string survived into the artifact.

use std::path::Path;

/// The token in the README, spelled out rather than derived, so a rename here
/// has to be a deliberate edit in both places.
const README_GREP: &str = "CONSTRUCT_CORE_VERSION=";

/// The stamp without its terminator — what a reader of the artifact sees.
fn stamp() -> &'static str {
    construct_core::CONSTRUCT_CORE_VERSION
        .strip_suffix('\0')
        .expect("stamp lost its NUL terminator")
}

#[test]
fn the_stamp_ends_where_it_says_it_does() {
    // Without the terminator the value runs into whichever literal the linker
    // placed next to it: `opt-level = "z"` packs `.rodata` with no separators,
    // and the archive published on 2026-09-04 came back as
    // `…+847067fdfef7primary_send_coveredrecipient_is_self…`. `strings` ends a
    // run at the first non-printable byte, so this is what bounds the value in
    // the artifact rather than in the command someone runs against it.
    assert!(
        construct_core::CONSTRUCT_CORE_VERSION.ends_with('\0'),
        "the stamp must be NUL-terminated to survive `strings` on a release .so"
    );
}

#[test]
fn the_stamp_is_the_string_the_readme_greps_for() {
    assert!(
        stamp().starts_with(README_GREP),
        "the README tells integrators to grep for {README_GREP:?}; the stamp is {:?}",
        stamp()
    );
}

#[test]
fn the_stamp_names_this_crate_version() {
    let version = env!("CARGO_PKG_VERSION");
    assert!(
        stamp().contains(version),
        "stamp {:?} does not name crate version {version}",
        stamp()
    );
}

#[test]
fn the_stamp_names_a_commit_when_one_is_knowable() {
    let commit = stamp()
        .rsplit_once('+')
        .expect("stamp carries no `+commit` component")
        .1;

    // A build from a source tarball has no history and no CI environment; the
    // honest answer there is `unknown`, and it is only honest when it is true.
    let has_history = Path::new(env!("CARGO_MANIFEST_DIR")).join(".git").exists();
    let in_ci = std::env::var_os("GITHUB_SHA").is_some();
    if !has_history && !in_ci {
        assert_eq!(commit, "unknown");
        return;
    }

    assert_ne!(
        commit, "unknown",
        "a checkout with history produced no commit — build.rs stopped resolving one"
    );
    assert!(
        commit.len() == 12 && commit.chars().all(|c| c.is_ascii_hexdigit()),
        "expected 12 hex characters of a commit sha, got {commit:?}"
    );
}
