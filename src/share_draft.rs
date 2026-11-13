//! One client's incoming OS share, not an outgoing message or a retry queue.
//!
//! The platform keeps this CFE blob in its encrypted local store. Item ids name locally sealed
//! source files; their keys never go in a URI or in Android saved-instance state. A submitted
//! draft must be reviewed after a crash, never drained by the pending-send consumer.
use crate::cfe::{self, CfeError, CfeMessageType};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareDraftItem {
    pub id: String,
    pub name: String,
    pub mime: String,
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
    pub size: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShareDraftStage {
    Importing,
    Ready,
    Submitted,
    Finished,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareDraft {
    pub id: String,
    pub text: String,
    pub items: Vec<ShareDraftItem>,
    pub contact_id: Option<String>,
    /// Submitted is not permission to submit again after process death.
    pub stage: ShareDraftStage,
}

pub fn encode(draft: &ShareDraft) -> Result<Vec<u8>, CfeError> {
    cfe::encode(CfeMessageType::ClientShareDraft, draft)
}

pub fn decode(kept: &[u8]) -> Result<ShareDraft, CfeError> {
    cfe::decode_as(kept, CfeMessageType::ClientShareDraft)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_draft_keeps_content_recipient_keys_order_and_submit_marker() {
        let draft = ShareDraft {
            id: "request".into(),
            text: "Текст и https://example.org/".into(),
            items: vec![
                ShareDraftItem {
                    id: "a".into(),
                    name: "фото.jpg".into(),
                    mime: "image/jpeg".into(),
                    key: vec![7; 32],
                    size: 101,
                },
                ShareDraftItem {
                    id: "b".into(),
                    name: "report.pdf".into(),
                    mime: "application/pdf".into(),
                    key: vec![9; 32],
                    size: 202,
                },
            ],
            contact_id: Some("local-peer".into()),
            stage: ShareDraftStage::Submitted,
        };
        let kept = encode(&draft).unwrap();
        assert_eq!(
            cfe::decode(&kept).unwrap().msg_type,
            CfeMessageType::ClientShareDraft
        );
        assert!(decode(&kept).unwrap() == draft);
        let other = cfe::encode(CfeMessageType::Generic, &draft).unwrap();
        assert!(decode(&other).is_err());
        let mut damaged = kept;
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert!(decode(&damaged).is_err());
    }
}
