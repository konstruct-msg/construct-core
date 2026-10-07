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

/// Values are the clients' `deliveryStatusRaw`; the store keeps and compares them, it does not
/// interpret them.
pub type DeliveryStatus = i16;

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
