//! Canonical bytes shared by X3DH prekey signers and verifiers.

use crate::crypto::SuiteID;

/// Domain separator for classic and hybrid X3DH prekey signatures.
pub(crate) const X3DH_SIGN_PROLOGUE: &[u8] = b"KonstruktX3DH-v1";

/// X3DH signature prefix: the domain separator followed by the big-endian suite ID.
pub fn build_prologue(suite_id: SuiteID) -> Vec<u8> {
    prologue_with_capacity(suite_id.as_u16(), 0)
}

/// Canonical prekey signature message: `domain ‖ 0x00 ‖ suite_id ‖ payload`.
pub(crate) fn build_x3dh_sign_message(suite_id: u8, payload: &[u8]) -> Vec<u8> {
    let mut message = prologue_with_capacity(u16::from(suite_id), payload.len());
    message.extend_from_slice(payload);
    message
}

fn prologue_with_capacity(suite_id: u16, payload_len: usize) -> Vec<u8> {
    let suite = suite_id.to_be_bytes();
    let mut message = Vec::with_capacity(X3DH_SIGN_PROLOGUE.len() + suite.len() + payload_len);
    message.extend_from_slice(X3DH_SIGN_PROLOGUE);
    message.extend_from_slice(&suite);
    message
}
