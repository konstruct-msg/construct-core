//! No field of an `[Error] interface` is called `message`.
//!
//! Generated Kotlin errors extend `Exception` and override `message` with a summary of their
//! fields. A field of that name in the same class is a conflicting declaration, so Android stops
//! compiling while the core and its Swift bindings stay green; the core's CI generates the Kotlin
//! and does not compile it. Fields of an ordinary record or enum are not affected.

/// Each `[Error] interface` field called `message`, as `(line number, line)`.
fn message_fields(udl: &str) -> Vec<(usize, String)> {
    let mut hits = Vec::new();
    let mut after_error = false;
    let mut inside = false;
    for (i, line) in udl.lines().enumerate() {
        let line = line.trim();
        if inside {
            if line == "};" {
                inside = false;
            } else if !line.starts_with("//")
                && line
                    .split(['(', ',', ')'])
                    .skip(1)
                    .any(|field| field.split_whitespace().last() == Some("message"))
            {
                hits.push((i + 1, line.to_string()));
            }
        } else if after_error && line.starts_with("interface ") {
            inside = true;
        }
        after_error = line == "[Error]";
    }
    hits
}

#[test]
fn no_error_interface_has_a_field_called_message() {
    let udl = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/construct_core.udl"
    ))
    .expect("read the UDL");
    let hits = message_fields(&udl);
    assert!(hits.is_empty(), "call it `detail`: {hits:?}");
}

#[test]
fn the_scan_finds_the_field_only_inside_an_error_interface() {
    let error = "[Error]\ninterface E {\n    A();\n    B(u32 n, string message);\n};\n";
    assert_eq!(message_fields(error).len(), 1);
    let record = "[Enum]\ninterface E {\n    B(string message);\n};\n";
    assert!(message_fields(record).is_empty());
    let commented = "[Error]\ninterface E {\n    // B(string message);\n    C();\n};\n";
    assert!(message_fields(commented).is_empty());
}
