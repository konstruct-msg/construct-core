//! Rows as the clients read and write them. Plain data: no behaviour, no ids invented here.

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Contact {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub local_alias: Option<String>,
    pub avatar: Option<Vec<u8>>,
    pub known_identity_key: Option<Vec<u8>>,
    pub account_address: Option<Vec<u8>>,
    pub is_contact: bool,
    pub is_blocked: bool,
    pub is_sharing_with_me: bool,
    pub am_i_sharing_with: bool,
    pub shared_with_me_at: Option<i64>,
    pub added_at: Option<i64>,
    pub kt_status: i16,
    pub security_notice: i16,
    /// When the peer last edited the profile they share; 0 when never told. A profile that is not
    /// newer than this is not applied.
    pub profile_edited_at_ms: i64,
    /// An avatar the peer announced that has not been downloaded yet, and since when.
    pub pending_avatar_ref: Option<Vec<u8>>,
    pub pending_avatar_since: Option<i64>,
}

/// Our own profile — what we share with the people we share it with. One row.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OwnProfile {
    pub account_id: String,
    pub username: String,
    pub display_name: String,
    pub avatar: Option<Vec<u8>>,
    pub profile_edited_at_ms: i64,
}

/// A contact's pinned identity key, without the rest of the row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityKeyPin {
    pub contact_id: String,
    pub key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Chat {
    pub id: String,
    /// One chat per peer.
    pub peer_id: String,
    /// The list's preview, as the client formatted it.
    pub last_message_text: Option<String>,
    /// Milliseconds since the Unix epoch.
    pub last_message_time: Option<i64>,
    pub is_pinned: bool,
    pub unread_count: i32,
}

/// A message's delivery status. The values are the iOS `deliveryStatusRaw`, which every client
/// stores. The store interprets them in one place: `delivery`, the rule for which writer
/// outranks which.
pub type DeliveryStatus = i16;

/// The delivery statuses, and the rule that decides between two writers who disagree.
///
/// Written from many places that run in no defined order — the send outcome, the peer's receipt,
/// the retry path, a timeout, a session archive. Until 0.37.0 the rule lived in the iOS app
/// (`DeliveryStatusTransition`), so a second client would have kept a copy of it.
pub mod delivery {
    use super::DeliveryStatus;

    pub const SENDING: DeliveryStatus = 0;
    /// The server took it.
    pub const SENT: DeliveryStatus = 1;
    /// The peer's end-to-end receipt.
    pub const DELIVERED: DeliveryStatus = 2;
    /// Not sent yet, and something will try again.
    pub const QUEUED: DeliveryStatus = 3;
    /// Not sent; nothing retries on its own unless the retry budget allows.
    pub const FAILED: DeliveryStatus = 4;

    /// How much a status proves about the message having reached someone else. A transport
    /// failure is ignorance, not a negative result: the statuses about our own attempt rank 0,
    /// interchangeable among themselves, and none of them may overwrite evidence.
    pub fn evidence_rank(status: DeliveryStatus) -> u8 {
        match status {
            DELIVERED => 2,
            SENT => 1,
            _ => 0,
        }
    }

    /// What a session archive does to an outgoing message encrypted under it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ArchiveOutcome {
        /// The peer confirmed it; no session change unsays that.
        Keep,
        /// Send again: it becomes queued.
        Resend,
        /// Attempts exhausted: it becomes failed, so the person sees it did not arrive.
        GiveUp,
    }

    /// `SENT` was evidence of arrival only while the peer could decrypt — and the archive ends
    /// exactly that, so a sent message the peer never confirmed goes back to being an attempt.
    pub fn after_session_archive(
        status: DeliveryStatus,
        retry_count: i16,
        max_retries: i16,
    ) -> ArchiveOutcome {
        if evidence_rank(status) >= evidence_rank(DELIVERED) {
            ArchiveOutcome::Keep
        } else if retry_count < max_retries {
            ArchiveOutcome::Resend
        } else {
            ArchiveOutcome::GiveUp
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Message {
    pub id: String,
    pub chat_id: String,
    pub from_user_id: String,
    pub to_user_id: String,
    pub is_sent_by_me: bool,
    pub timestamp: i64,
    /// Transcript order, server-assigned where the server placed the message. Pages are read in
    /// `(order_key, id)` order — total, so no two reads of one chat disagree.
    pub order_key: String,
    pub body: Vec<u8>,
    pub content_type: i16,
    pub delivery_status: DeliveryStatus,
    pub retry_count: i16,
    pub suite_id: i16,
    pub is_edited: bool,
    pub edited_at: Option<i64>,
    pub reply_to_message_id: Option<String>,
    pub reply_to_content: Option<String>,
    pub transcript_text: Option<String>,
    pub transcript_language: Option<String>,
    pub transcript_generated_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reaction {
    pub target_message_id: String,
    pub reactor_user_id: String,
    pub emoji: String,
    pub timestamp_ms: i64,
    pub received_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CallRecord {
    pub id: String,
    pub peer_user_id: String,
    pub peer_name: String,
    pub direction: i16,
    pub status: i16,
    pub started_at: Option<i64>,
    pub ended_at: Option<i64>,
    pub duration_seconds: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeerDevice {
    pub device_id: String,
    pub account_id: String,
    pub identity_key: Vec<u8>,
    /// Milliseconds since the Unix epoch.
    pub first_seen_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    pub message_id: String,
    pub chat_id: String,
    pub timestamp: i64,
}
