//! `konstruct-root` — the offline root of the server keys.
//!
//! Runs on the offline machine of the root ceremony
//! (`construct-docs/manuals&instructions/server-root-key-ceremony.md`). It is the same code that
//! checks delegations in every client (`construct_core::crypto::server_trust`), so what it signs is
//! what they accept. It never touches the network.
//!
//! ```text
//! konstruct-root init --label primary [--no-save] [--dir DIR]
//! konstruct-root restore --check ROOT.pub          (words from stdin; compares, writes nothing)
//! konstruct-root restore --out ROOT.key            (words from stdin; writes the key file)
//! konstruct-root delegate --root ROOT.key --purpose sender-cert|kt-head|sticker-manifest
//!                         --pub SERVER.pub --days 90 [--not-before UNIX] --out FILE.delegation
//! konstruct-root verify --root A.pub [--root B.pub] --delegation FILE.delegation
//! konstruct-root fingerprint FILE.pub
//! ```
//!
//! Files: `.pub` and `.delegation` are one line of hex — public, safe to carry on the transfer
//! stick. `.key` is the root's two seeds as hex, mode 0600, and stays on the encrypted storage.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use construct_core::crypto::server_trust::{
    Delegation, Purpose, fingerprint, issue_delegation, kid_of, root_words, verify_rooted,
};
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

const DAY: i64 = 86_400;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("init") => init(&args[1..]),
        Some("restore") => restore(&args[1..]),
        Some("delegate") => delegate(&args[1..]),
        Some("verify") => verify(&args[1..]),
        Some("fingerprint") => fingerprint_cmd(&args[1..]),
        Some("--version") => {
            println!("konstruct-root {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => Err(usage()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> String {
    "usage: konstruct-root init | restore | delegate | verify | fingerprint | --version \
     (see the header of src/bin/konstruct-root.rs)"
        .into()
}

/// `--name value` pairs and bare flags.
struct Args<'a>(&'a [String]);

impl Args<'_> {
    fn value(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .position(|a| a == name)
            .and_then(|i| self.0.get(i + 1))
            .map(String::as_str)
    }
    fn values(&self, name: &str) -> Vec<&str> {
        self.0
            .windows(2)
            .filter(|w| w[0] == name)
            .map(|w| w[1].as_str())
            .collect()
    }
    fn flag(&self, name: &str) -> bool {
        self.0.iter().any(|a| a == name)
    }
    fn required(&self, name: &str) -> Result<&str, String> {
        self.value(name)
            .ok_or_else(|| format!("{name} is required"))
    }
}

fn init(args: &[String]) -> Result<(), String> {
    let a = Args(args);
    let label = a.required("--label")?;
    let dir = PathBuf::from(a.value("--dir").unwrap_or("."));
    let pub_path = dir.join(format!("root-{label}.pub"));
    let key_path = dir.join(format!("root-{label}.key"));
    refuse_overwrite(&pub_path)?;
    if !a.flag("--no-save") {
        refuse_overwrite(&key_path)?;
    }

    let mut seeds = Zeroizing::new([0u8; 64]);
    OsRng.fill_bytes(seeds.as_mut());
    let (_, public) = root_words::keypair(&seeds);
    let words = root_words::encode(
        seeds[..32].try_into().expect("32"),
        seeds[32..].try_into().expect("32"),
    );

    println!(
        "ROOT \"{label}\" — write these {} words on paper, numbered:\n",
        root_words::WORD_COUNT
    );
    for (i, w) in words.split_whitespace().enumerate() {
        print!("{:>2}. {:<10}", i + 1, w);
        if (i + 1) % 4 == 0 {
            println!();
        }
    }
    println!(
        "\nFingerprint (write it under the words):\n  {}\n",
        fingerprint(&public)
    );

    write_public(&pub_path, &hex::encode(&public))?;
    println!("public key  → {}", pub_path.display());
    if a.flag("--no-save") {
        println!("private key → paper only (--no-save)");
    } else {
        write_secret(&key_path, &Zeroizing::new(hex::encode(seeds.as_ref())))?;
        println!("private key → {} (0600)", key_path.display());
    }
    println!(
        "\nNow check the paper: konstruct-root restore --check {}",
        pub_path.display()
    );
    Ok(())
}

fn restore(args: &[String]) -> Result<(), String> {
    let a = Args(args);
    eprintln!(
        "Type the {} words from the paper (any spacing, Enter between lines), then Ctrl-D:",
        root_words::WORD_COUNT
    );
    let mut input = Zeroizing::new(String::new());
    for line in std::io::stdin().lock().lines() {
        let line = Zeroizing::new(line.map_err(|e| e.to_string())?);
        input.push_str(&line);
        input.push(' ');
        if input.split_whitespace().count() >= root_words::WORD_COUNT {
            break;
        }
    }
    let seeds = root_words::decode(&input)?;
    let (_, public) = root_words::keypair(&seeds);

    if let Some(check) = a.value("--check") {
        let expected = read_hex(Path::new(check))?;
        if expected == public {
            println!("MATCHES {check}\n  {}", fingerprint(&public));
            Ok(())
        } else {
            Err(format!(
                "does NOT match {check}: the paper restores {}",
                fingerprint(&public)
            ))
        }
    } else if let Some(out) = a.value("--out") {
        let out = Path::new(out);
        refuse_overwrite(out)?;
        write_secret(out, &Zeroizing::new(hex::encode(seeds.as_ref())))?;
        println!(
            "restored → {} (0600)\n  {}",
            out.display(),
            fingerprint(&public)
        );
        Ok(())
    } else {
        Err("restore needs --check ROOT.pub or --out ROOT.key".into())
    }
}

fn delegate(args: &[String]) -> Result<(), String> {
    let a = Args(args);
    let seeds_hex =
        Zeroizing::new(std::fs::read_to_string(a.required("--root")?).map_err(|e| e.to_string())?);
    let seeds_vec =
        Zeroizing::new(hex::decode(seeds_hex.trim()).map_err(|_| "root key is not hex")?);
    let seeds: Zeroizing<[u8; 64]> = Zeroizing::new(
        seeds_vec
            .as_slice()
            .try_into()
            .map_err(|_| "root key is not 64 bytes")?,
    );
    let (root_private, root_public) = root_words::keypair(&seeds);

    let purpose_name = a.required("--purpose")?;
    let purpose = Purpose::from_name(purpose_name)
        .ok_or_else(|| format!("unknown purpose {purpose_name}"))?;
    let server_public = read_hex(Path::new(a.required("--pub")?))?;
    let days: i64 = a
        .required("--days")?
        .parse()
        .map_err(|_| "--days is not a number")?;
    if !(1..=120).contains(&days) {
        return Err("--days must be 1..=120".into());
    }
    let not_before = match a.value("--not-before") {
        Some(v) => v.parse().map_err(|_| "--not-before is not a unix time")?,
        None => now_secs(),
    };
    let not_after = not_before + days * DAY;
    let out = Path::new(a.required("--out")?);
    refuse_overwrite(out)?;

    println!("Root:          {}", fingerprint(&root_public));
    println!("Purpose:       {}", purpose.name());
    println!("Server key:    {}", fingerprint(&server_public));
    println!("Key id (kid):  {}", hex::encode(kid_of(&server_public)));
    println!(
        "Valid:         {} → {} ({days} days)",
        utc(not_before),
        utc(not_after)
    );
    print!("\nCompare the server key fingerprint with the one the server printed. Sign? [y/N] ");
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|e| e.to_string())?;
    if answer.trim() != "y" {
        return Err("not signed".into());
    }

    let d = issue_delegation(
        &root_private,
        purpose,
        not_before,
        not_after,
        &server_public,
    )
    .map_err(|e| e.to_string())?;
    write_public(out, &hex::encode(d.encode()))?;
    println!("delegation → {}", out.display());
    Ok(())
}

fn verify(args: &[String]) -> Result<(), String> {
    let a = Args(args);
    let roots: Vec<Vec<u8>> = a
        .values("--root")
        .into_iter()
        .map(|p| read_hex(Path::new(p)))
        .collect::<Result<_, _>>()?;
    let d = Delegation::decode(&read_hex(Path::new(a.required("--delegation")?))?)
        .map_err(|e| e.to_string())?;
    verify_rooted(&d, &roots).map_err(|e| e.to_string())?;
    println!("OK — signed by a given root");
    println!("Purpose:       {}", d.purpose.name());
    println!("Server key:    {}", fingerprint(&d.public_key));
    println!("Key id (kid):  {}", hex::encode(d.kid()));
    println!(
        "Valid:         {} → {}",
        utc(d.not_before),
        utc(d.not_after)
    );
    let left = (d.not_after - now_secs()) / DAY;
    println!("Days left:     {left}");
    Ok(())
}

fn fingerprint_cmd(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or("fingerprint needs a .pub file")?;
    println!("{}", fingerprint(&read_hex(Path::new(path))?));
    Ok(())
}

fn refuse_overwrite(path: &Path) -> Result<(), String> {
    if path.exists() {
        Err(format!("{} exists — refusing to overwrite", path.display()))
    } else {
        Ok(())
    }
}

fn read_hex(path: &Path) -> Result<Vec<u8>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    hex::decode(text.trim()).map_err(|_| format!("{} is not hex", path.display()))
}

fn write_public(path: &Path, hex: &str) -> Result<(), String> {
    std::fs::write(path, format!("{hex}\n")).map_err(|e| format!("{}: {e}", path.display()))
}

fn write_secret(path: &Path, hex: &str) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    writeln!(f, "{hex}").map_err(|e| e.to_string())
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `YYYY-MM-DD HH:MM UTC` without a date library (civil-from-days, H. Hinnant).
fn utc(secs: i64) -> String {
    let days = secs.div_euclid(DAY);
    let rem = secs.rem_euclid(DAY);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60
    )
}
