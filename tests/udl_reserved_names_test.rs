//! A method of a UDL `interface` is not named `close` or `destroy`.
//!
//! UniFFI's Kotlin binding makes every object `AutoCloseable` and `Disposable`: it already has
//! `close()` and `destroy()`, which free the Rust object. A UDL method of the same name does not
//! fail here or in the Swift build; it fails only when Android compiles the bindings ("Conflicting
//! overloads"). 0.66.0 shipped `MailboxGapState.close()` that way; core CI generates the Kotlin
//! bindings but does not compile them.

#[test]
fn no_interface_method_takes_a_name_kotlin_reserves() {
    let udl = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/construct_core.udl"
    ))
    .expect("read the UDL");
    let mut in_interface = false;
    let mut hits = Vec::new();
    for (i, line) in udl.lines().enumerate() {
        let code = line.split("//").next().unwrap_or("").trim();
        if code.starts_with("interface ") {
            in_interface = true;
            continue;
        }
        if in_interface && code.starts_with("};") {
            in_interface = false;
            continue;
        }
        if in_interface
            && ["close", "destroy"]
                .iter()
                .any(|name| names_method(code, name))
        {
            hits.push((i + 1, line.trim().to_string()));
        }
    }
    assert!(
        hits.is_empty(),
        "Kotlin objects already have close()/destroy(); rename these methods: {hits:?}"
    );
}

/// `code` declares a method `name`: the word itself (not `force_close`), then `(`.
fn names_method(code: &str, name: &str) -> bool {
    code.match_indices(name).any(|(at, _)| {
        let before = code[..at].chars().last();
        let after = code[at + name.len()..].trim_start();
        before.is_none_or(|c| !(c.is_alphanumeric() || c == '_')) && after.starts_with('(')
    })
}

#[test]
fn a_method_is_told_from_a_longer_name() {
    assert!(names_method("    void close();", "close"));
    assert!(names_method("void destroy (u32 a);", "destroy"));
    assert!(!names_method("    void force_close();", "close"));
    assert!(!names_method("    boolean closed;", "close"));
}
