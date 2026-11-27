//! Shared formatting for diagnostic messages.

/// First eight characters of an identifier, for diagnostics that must not carry a long ID whole.
/// Slice at a UTF-8 character boundary so unexpected identifiers cannot panic the error path.
pub(crate) fn id_prefix(id: &str) -> &str {
    let end = id.char_indices().nth(8).map_or(id.len(), |(i, _)| i);
    &id[..end]
}

#[cfg(test)]
mod tests {
    use super::id_prefix;

    #[test]
    fn id_prefix_keeps_eight_characters_on_a_utf8_boundary() {
        assert_eq!(id_prefix(""), "");
        assert_eq!(id_prefix("short"), "short");
        assert_eq!(id_prefix("12345678-rest"), "12345678");
        assert_eq!(id_prefix("é界123456-rest"), "é界123456");
    }
}
