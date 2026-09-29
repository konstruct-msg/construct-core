//! Byte data crosses the FFI as `bytes`, never `sequence<u8>`.
//!
//! Both are `Vec<u8>` here, so nothing in Rust tells them apart; the difference is entirely in
//! the generated bindings. `bytes` is `Data` in Swift and `ByteArray` in Kotlin, copied as one
//! block. `sequence<u8>` is `[UInt8]` copied one byte per call in both directions, and in Kotlin
//! a `List<UByte>` — an object per byte. The UDL carried 195 of them until 2026-09-29, under a
//! client rule that asked for exactly that type while meaning "binary, not base64".

#[test]
fn the_udl_has_no_sequence_of_u8() {
    let udl = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/construct_core.udl"))
        .expect("read the UDL");
    let hits: Vec<(usize, &str)> = udl
        .lines()
        .enumerate()
        .filter(|(_, line)| line.replace(' ', "").contains("sequence<u8>"))
        .map(|(i, line)| (i + 1, line.trim()))
        .collect();
    assert!(hits.is_empty(), "use `bytes` for byte data across the FFI: {hits:?}");
}
