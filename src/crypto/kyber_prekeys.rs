//! The core's Kyber (ML-KEM-1024) prekeys: the signed prekey with its rotation history, and the
//! one-time pool.
//!
//! # Why they live here
//!
//! PQXDH v2 (construct-docs `cryptocore/PQXDH_V2_DESIGN.md`) mixes the ML-KEM secret into the
//! session's initial key, so the responder has to decapsulate *inside* processing the first
//! message, before it can decrypt it. Until now the secrets lived on the platform (iOS Keychain
//! via `PQCKeyManager`; Android had none) and the core handed the platform a ciphertext to
//! decapsulate — which Android fed back as the shared secret. Choosing the key, decapsulating and
//! burning a one-time key are protocol: they belong to the one implementation both clients share.
//!
//! # Shape
//!
//! - A secret is the FIPS 203 64-byte seed. The public key is derived from it; signatures are
//!   made when an upload record is asked for (`KeyManager::kyber_prekey_upload`), not stored.
//! - Ids: signed prekeys count up from 1, one-time prekeys from `KYBER_OTPK_ID_START`. The ranges
//!   never meet, so an id alone names the key a first message used.
//! - SPK rotation is two-phase, like the classic one: `begin` hands out the new key for upload
//!   (and keeps its secret, so a crash after the upload does not strand messages sent to it),
//!   `commit` makes it current once the server confirmed. `begin` again before `commit` returns
//!   the same pending key, so a retried upload uploads the same key.
//! - A rotated-out SPK is kept `SPK_RETENTION_AFTER_ROTATION_SECS` (14 days) for first messages
//!   still in flight to it, then dropped.
//!
//! Everything here takes `now` as a parameter: the store has no clock of its own.

use std::collections::BTreeMap;

use crate::cfe::{CfeKyberPrekeyV1, CfeKyberPrekeysV1, CfeRetiredKyberSpkV1};
use crate::crypto::SecretBytes;
use crate::crypto::keys::SPK_RETENTION_AFTER_ROTATION_SECS;
use crate::crypto::pq_x3dh::MLKEM_SEED_SIZE;

/// First id of the one-time range (signed prekeys count up from 1).
pub const KYBER_OTPK_ID_START: u32 = 1_000_000;

/// One Kyber prekey: its id, its signed creation time, and the seed that is its whole secret.
#[derive(Clone, PartialEq, Eq)]
pub struct KyberPrekey {
    pub key_id: u32,
    pub created_at: u64,
    seed: SecretBytes,
}

impl std::fmt::Debug for KyberPrekey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KyberPrekey")
            .field("key_id", &self.key_id)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

impl KyberPrekey {
    fn generate(key_id: u32, created_at: u64) -> Result<Self, String> {
        let (seed, _public) = crate::crypto::pq_x3dh::mlkem1024_generate()?;
        Ok(Self {
            key_id,
            created_at,
            seed,
        })
    }

    pub fn seed(&self) -> &[u8] {
        self.seed.expose()
    }

    pub fn public_key(&self) -> Result<Vec<u8>, String> {
        crate::crypto::pq_x3dh::mlkem1024_public_from_seed(self.seed.expose())
    }

    fn to_cfe(&self) -> CfeKyberPrekeyV1 {
        CfeKyberPrekeyV1 {
            key_id: self.key_id,
            created_at: self.created_at,
            seed: self.seed.clone(),
        }
    }

    fn from_cfe(record: &CfeKyberPrekeyV1) -> Option<Self> {
        (record.seed.len() == MLKEM_SEED_SIZE).then(|| Self {
            key_id: record.key_id,
            created_at: record.created_at,
            seed: record.seed.clone(),
        })
    }
}

/// What to upload for one Kyber prekey. `created_at` travels with it: the signatures cover it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KyberPrekeyUpload {
    pub key_id: u32,
    /// ML-KEM-1024 public key (1568 bytes).
    pub public_key: Vec<u8>,
    pub created_at: u64,
    /// Ed25519 by the identity signing key over `kyber_prekey_sign_message_v2`.
    pub signature: Vec<u8>,
    /// Ed25519 + ML-DSA-65 by the hybrid identity key over the same message (3373 bytes).
    pub hybrid_signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RetiredSpk {
    prekey: KyberPrekey,
    retired_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KyberPrekeyStore {
    spk: Option<KyberPrekey>,
    pending_spk: Option<KyberPrekey>,
    retired_spks: Vec<RetiredSpk>,
    otpks: BTreeMap<u32, KyberPrekey>,
    next_spk_id: u32,
    next_otpk_id: u32,
}

impl Default for KyberPrekeyStore {
    fn default() -> Self {
        Self {
            spk: None,
            pending_spk: None,
            retired_spks: Vec::new(),
            otpks: BTreeMap::new(),
            next_spk_id: 1,
            next_otpk_id: KYBER_OTPK_ID_START,
        }
    }
}

impl KyberPrekeyStore {
    // ── Signed prekey ─────────────────────────────────────────────────────────

    /// The current signed prekey, if one was ever committed.
    pub fn current_spk(&self) -> Option<&KyberPrekey> {
        self.spk.as_ref()
    }

    /// Start a rotation: the key to upload. Idempotent until `commit`/`rollback`.
    pub fn begin_spk_rotation(&mut self, now: u64) -> Result<KyberPrekey, String> {
        if let Some(pending) = &self.pending_spk {
            return Ok(pending.clone());
        }
        if self.next_spk_id >= KYBER_OTPK_ID_START {
            return Err("Kyber SPK id range exhausted".to_string());
        }
        let prekey = KyberPrekey::generate(self.next_spk_id, now)?;
        self.next_spk_id += 1;
        self.pending_spk = Some(prekey.clone());
        Ok(prekey)
    }

    /// The server confirmed the pending key: it becomes current, and the previous one is kept for
    /// in-flight first messages. `false` if there was nothing pending.
    pub fn commit_spk_rotation(&mut self, now: u64) -> bool {
        let Some(pending) = self.pending_spk.take() else {
            return false;
        };
        if let Some(previous) = self.spk.replace(pending) {
            self.retired_spks.push(RetiredSpk {
                prekey: previous,
                retired_at: now,
            });
        }
        self.prune_retired(now);
        true
    }

    /// The upload failed: forget the pending key (the server never had it).
    pub fn rollback_spk_rotation(&mut self) {
        self.pending_spk = None;
    }

    /// Drop rotated-out SPKs whose retention has run out.
    pub fn prune_retired(&mut self, now: u64) {
        self.retired_spks
            .retain(|r| now.saturating_sub(r.retired_at) < SPK_RETENTION_AFTER_ROTATION_SECS);
    }

    pub fn retired_spk_count(&self) -> usize {
        self.retired_spks.len()
    }

    // ── One-time prekeys ──────────────────────────────────────────────────────

    /// Generate `count` one-time prekeys for upload.
    pub fn generate_otpks(&mut self, count: u32, now: u64) -> Result<Vec<KyberPrekey>, String> {
        let mut out = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let key_id = self.next_otpk_id;
            let next = key_id
                .checked_add(1)
                .ok_or_else(|| "Kyber OTPK id range exhausted".to_string())?;
            let prekey = KyberPrekey::generate(key_id, now)?;
            self.next_otpk_id = next;
            self.otpks.insert(key_id, prekey.clone());
            out.push(prekey);
        }
        Ok(out)
    }

    pub fn otpk_count(&self) -> usize {
        self.otpks.len()
    }

    /// Remove one-time prekeys with `key_id < min_keep_id` (after a replace-all upload, the way
    /// `prune_one_time_prekeys_below` does for the X25519 pool). Ids stay monotonic.
    pub fn prune_otpks_below(&mut self, min_keep_id: u32) -> usize {
        let before = self.otpks.len();
        self.otpks.retain(|&id, _| id >= min_keep_id);
        before - self.otpks.len()
    }

    /// Burn a one-time prekey. Call once the session built on it is persisted, not on an attempt.
    pub fn remove_otpk(&mut self, key_id: u32) -> Option<KyberPrekey> {
        self.otpks.remove(&key_id)
    }

    // ── Lookup ────────────────────────────────────────────────────────────────

    /// The prekey a first message names by id: current, pending or retired SPK, or a one-time key.
    ///
    /// Pending counts: it was uploaded, and the confirmation may simply not have arrived yet.
    pub fn find(&self, key_id: u32) -> Option<&KyberPrekey> {
        if key_id >= KYBER_OTPK_ID_START {
            return self.otpks.get(&key_id);
        }
        self.spk
            .iter()
            .chain(self.pending_spk.iter())
            .chain(self.retired_spks.iter().map(|r| &r.prekey))
            .find(|k| k.key_id == key_id)
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    pub fn to_cfe(&self) -> CfeKyberPrekeysV1 {
        CfeKyberPrekeysV1 {
            spk: self.spk.as_ref().map(KyberPrekey::to_cfe),
            pending_spk: self.pending_spk.as_ref().map(KyberPrekey::to_cfe),
            retired_spks: self
                .retired_spks
                .iter()
                .map(|r| CfeRetiredKyberSpkV1 {
                    prekey: r.prekey.to_cfe(),
                    retired_at: r.retired_at,
                })
                .collect(),
            otpks: self.otpks.values().map(KyberPrekey::to_cfe).collect(),
            next_spk_id: self.next_spk_id,
            next_otpk_id: self.next_otpk_id,
        }
    }

    /// Rebuild from a snapshot. An entry whose seed is not 64 bytes is dropped (it could never
    /// decapsulate); counters never go backwards past an id that is held, so no id is reused.
    pub fn from_cfe(record: &CfeKyberPrekeysV1, now: u64) -> Self {
        let mut store = Self {
            spk: record.spk.as_ref().and_then(KyberPrekey::from_cfe),
            pending_spk: record.pending_spk.as_ref().and_then(KyberPrekey::from_cfe),
            retired_spks: record
                .retired_spks
                .iter()
                .filter_map(|r| {
                    KyberPrekey::from_cfe(&r.prekey).map(|prekey| RetiredSpk {
                        prekey,
                        retired_at: r.retired_at,
                    })
                })
                .collect(),
            otpks: record
                .otpks
                .iter()
                .filter_map(KyberPrekey::from_cfe)
                .map(|k| (k.key_id, k))
                .collect(),
            next_spk_id: record.next_spk_id.max(1),
            next_otpk_id: record.next_otpk_id.max(KYBER_OTPK_ID_START),
        };
        let highest_spk = store
            .spk
            .iter()
            .chain(store.pending_spk.iter())
            .chain(store.retired_spks.iter().map(|r| &r.prekey))
            .map(|k| k.key_id)
            .max();
        if let Some(id) = highest_spk {
            store.next_spk_id = store.next_spk_id.max(id + 1);
        }
        if let Some(&id) = store.otpks.keys().next_back() {
            store.next_otpk_id = store.next_otpk_id.max(id.saturating_add(1));
        }
        store.prune_retired(now);
        store
    }
}

#[cfg(all(test, feature = "post-quantum"))]
mod tests {
    use super::*;

    const DAY: u64 = 24 * 3600;

    #[test]
    fn rotation_is_two_phase_and_begin_is_idempotent() {
        let mut store = KyberPrekeyStore::default();
        let first = store.begin_spk_rotation(100).unwrap();
        assert_eq!(first.key_id, 1);
        assert_eq!(
            store.begin_spk_rotation(200).unwrap(),
            first,
            "a retried upload must upload the same key"
        );
        assert!(store.current_spk().is_none(), "not current before commit");
        assert!(
            store.find(1).is_some(),
            "a pending key already on the server must decapsulate"
        );
        assert!(store.commit_spk_rotation(300));
        assert_eq!(store.current_spk().unwrap().key_id, 1);
        assert!(!store.commit_spk_rotation(301), "nothing pending");
    }

    #[test]
    fn rollback_forgets_the_pending_key() {
        let mut store = KyberPrekeyStore::default();
        store.begin_spk_rotation(0).unwrap();
        store.rollback_spk_rotation();
        assert!(store.find(1).is_none());
        assert_eq!(
            store.begin_spk_rotation(0).unwrap().key_id,
            2,
            "a rolled-back id is not reused"
        );
    }

    #[test]
    fn a_rotated_spk_is_kept_fourteen_days_after_rotation() {
        let mut store = KyberPrekeyStore::default();
        store.begin_spk_rotation(0).unwrap();
        store.commit_spk_rotation(0);
        // Rotated out on day 30 — long after it was created: retention runs from rotation.
        store.begin_spk_rotation(30 * DAY).unwrap();
        store.commit_spk_rotation(30 * DAY);
        assert!(store.find(1).is_some(), "just rotated");

        store.prune_retired(30 * DAY + 14 * DAY - 1);
        assert!(store.find(1).is_some(), "still inside 14 days");
        store.prune_retired(30 * DAY + 14 * DAY);
        assert!(store.find(1).is_none(), "gone at 14 days");
        assert!(store.find(2).is_some(), "the current key is never pruned");
    }

    #[test]
    fn one_time_keys_are_their_own_range_and_burn() {
        let mut store = KyberPrekeyStore::default();
        let keys = store.generate_otpks(3, 5).unwrap();
        let ids: Vec<u32> = keys.iter().map(|k| k.key_id).collect();
        assert_eq!(ids, vec![1_000_000, 1_000_001, 1_000_002]);
        assert_eq!(store.otpk_count(), 3);
        assert!(store.remove_otpk(1_000_001).is_some());
        assert!(store.find(1_000_001).is_none());
        assert_eq!(store.prune_otpks_below(1_000_002), 1);
        assert_eq!(store.otpk_count(), 1);
    }

    #[test]
    fn a_found_key_decapsulates_what_was_encapsulated_to_its_public() {
        let mut store = KyberPrekeyStore::default();
        let otpk = store.generate_otpks(1, 0).unwrap().remove(0);
        let enc =
            crate::crypto::pq_x3dh::mlkem1024_encapsulate(&otpk.public_key().unwrap()).unwrap();
        let held = store.find(otpk.key_id).unwrap();
        let ss =
            crate::crypto::pq_x3dh::mlkem1024_decapsulate(held.seed(), &enc.ciphertext).unwrap();
        assert_eq!(ss.expose(), enc.shared_secret.expose());
    }

    #[test]
    fn the_snapshot_round_trips_and_ids_never_repeat() {
        let mut store = KyberPrekeyStore::default();
        store.begin_spk_rotation(0).unwrap();
        store.commit_spk_rotation(0);
        store.begin_spk_rotation(DAY).unwrap();
        store.commit_spk_rotation(DAY);
        store.begin_spk_rotation(2 * DAY).unwrap(); // pending
        store.generate_otpks(2, 0).unwrap();

        let bytes = crate::cfe::encode(
            crate::cfe::CfeMessageType::KyberPrivateKeys,
            &store.to_cfe(),
        )
        .unwrap();
        let record: CfeKyberPrekeysV1 =
            crate::cfe::decode_as(&bytes, crate::cfe::CfeMessageType::KyberPrivateKeys).unwrap();
        let mut restored = KyberPrekeyStore::from_cfe(&record, 2 * DAY);
        assert_eq!(restored, store);

        // Counters written as zero (a damaged snapshot) still cannot hand out a held id.
        let mut damaged = record.clone();
        damaged.next_spk_id = 0;
        damaged.next_otpk_id = 0;
        let mut from_damaged = KyberPrekeyStore::from_cfe(&damaged, 2 * DAY);
        from_damaged.rollback_spk_rotation();
        assert_eq!(from_damaged.begin_spk_rotation(3 * DAY).unwrap().key_id, 4);
        assert_eq!(
            from_damaged.generate_otpks(1, 0).unwrap()[0].key_id,
            1_000_002
        );

        restored.rollback_spk_rotation();
        assert_eq!(restored.begin_spk_rotation(3 * DAY).unwrap().key_id, 4);
    }

    #[test]
    fn a_seed_of_the_wrong_size_is_dropped_on_restore() {
        let mut store = KyberPrekeyStore::default();
        store.generate_otpks(1, 0).unwrap();
        let mut record = store.to_cfe();
        record.otpks[0].seed = SecretBytes::new(vec![0; 10]);
        assert_eq!(KyberPrekeyStore::from_cfe(&record, 0).otpk_count(), 0);
    }

    #[test]
    fn restore_prunes_expired_retirees() {
        let mut store = KyberPrekeyStore::default();
        store.begin_spk_rotation(0).unwrap();
        store.commit_spk_rotation(0);
        store.begin_spk_rotation(0).unwrap();
        store.commit_spk_rotation(0);
        assert_eq!(store.retired_spk_count(), 1);
        let restored = KyberPrekeyStore::from_cfe(&store.to_cfe(), 15 * DAY);
        assert_eq!(restored.retired_spk_count(), 0);
    }

    #[test]
    fn debug_does_not_print_the_seed() {
        let mut store = KyberPrekeyStore::default();
        let key = store.generate_otpks(1, 0).unwrap().remove(0);
        let printed = format!("{key:?} {store:?}");
        assert!(!printed.contains("seed:"), "{printed}");
    }
}
