use crate::cfe::CfeError;

pub fn is_cfe_format(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x43 && data[1] == 0x46
}

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
