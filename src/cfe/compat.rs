//! Detection of the legacy JSON storage format.
//!
//! Legacy JSON is no longer migrated: a blob that looks like JSON is refused with
//! `CfeError::LegacyJson` where a CFE envelope was expected.

use crate::cfe::CfeError;

pub fn looks_like_legacy_json(data: &[u8]) -> bool {
    let first_non_ws = data
        .iter()
        .copied()
        .find(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'));
    matches!(first_non_ws, Some(b'{') | Some(b'['))
}

pub fn legacy_json_error_if_detected(data: &[u8]) -> Result<(), CfeError> {
    if looks_like_legacy_json(data) {
        return Err(CfeError::LegacyJson);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_looks_like_legacy_json() {
        assert!(looks_like_legacy_json(b"{\"key\":\"value\"}"));
        assert!(looks_like_legacy_json(b"[1,2,3]"));
        assert!(looks_like_legacy_json(b"   {\"key\":\"value\"}"));
        assert!(looks_like_legacy_json(b"\t{\"key\":\"value\"}"));
        assert!(looks_like_legacy_json(b"\n{\"key\":\"value\"}"));
        assert!(!looks_like_legacy_json(b"not json"));
        assert!(!looks_like_legacy_json(&[0x00, 0x01, 0x02]));
    }
}
