use std::process::Command;

fn main() {
    // Generate UniFFI bindings
    uniffi::generate_scaffolding("src/construct_core.udl").unwrap();

    // Rerun if UDL file changes
    println!("cargo:rerun-if-changed=src/construct_core.udl");

    // The commit this library was built from, stamped into the library itself
    // (see `CONSTRUCT_CORE_VERSION` in src/lib.rs for why it has to live there
    // and not beside it).
    //
    // `GITHUB_SHA` first: in CI the checkout is what was built, and asking git
    // in a workspace that also contains a sibling checkout is one more thing to
    // get wrong. Locally, git answers. Neither → `unknown`, which is the honest
    // answer for a build from a tarball with no history.
    let commit = std::env::var("GITHUB_SHA")
        .ok()
        .or_else(|| {
            Command::new("git")
                .args(["rev-parse", "HEAD"])
                .output()
                .ok()
                .filter(|out| out.status.success())
                .and_then(|out| String::from_utf8(out.stdout).ok())
        })
        .map(|sha| sha.trim().chars().take(12).collect::<String>())
        .filter(|sha| !sha.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=CONSTRUCT_CORE_COMMIT={commit}");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    // Catches a branch switch, not a new commit on the same branch: a stale
    // stamp is possible on a dev machine and never on a release, which builds
    // from a fresh checkout. The releases are what integrators identify builds
    // by, so that is where it has to be right.
    println!("cargo:rerun-if-changed=.git/HEAD");
}
