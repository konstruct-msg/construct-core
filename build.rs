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
        .or_else(|| git(&["rev-parse", "HEAD"]))
        .map(|sha| sha.chars().take(12).collect::<String>())
        .filter(|sha| !sha.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=CONSTRUCT_CORE_COMMIT={commit}");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");

    // What moves when the commit does. `.git/HEAD` alone moves on a branch
    // switch but not on a commit to the branch checked out — that writes the
    // branch's ref — so every local build after a fresh commit stamped the
    // commit before it, and `build_crypto_lib.sh` reported the slices as built
    // from a core they were not built from (2026-09-23). Paths come from
    // `--git-path` because in a worktree `.git` is a file, not a directory.
    //
    // The branch refs are watched as a directory, which cargo scans
    // recursively: a ref that `git gc` packed has no file of its own until the
    // next commit writes one, and a path that does not exist would make cargo
    // rerun this script on every build. `packed-refs` only when it exists, for
    // the same reason.
    let head = git(&["rev-parse", "--git-path", "HEAD"]).unwrap_or_else(|| ".git/HEAD".to_string());
    let mut watched = vec![head];
    watched.extend(git(&["rev-parse", "--git-path", "refs/heads"]));
    watched.extend(
        git(&["rev-parse", "--git-path", "packed-refs"])
            .filter(|p| std::path::Path::new(p).exists()),
    );
    for path in watched {
        println!("cargo:rerun-if-changed={path}");
    }
}

/// One line of git's output, or nothing when git is absent or the command fails.
fn git(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}
