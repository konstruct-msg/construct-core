use super::*;
use crate::config::Config;
use crate::crypto::messaging::SecureMessaging;
use crate::crypto::provider::CryptoProvider;
use zeroize::Zeroize;

impl<P: CryptoProvider> DoubleRatchetSession<P> {
    /// Cleanup старых skipped message keys с дефолтным периодом (7 дней)
    pub fn cleanup_old_skipped_keys_default(&mut self) {
        self.cleanup_old_skipped_keys(Config::global().max_skipped_message_age_seconds);
    }

    /// Return a read-only health snapshot of this session. Does not mutate state.
    pub fn health_snapshot(&self) -> DrHealthSnapshot {
        DrHealthSnapshot {
            messages_sent: self.sending_chain_length,
            messages_received: self.receiving_chain_length,
            skipped_keys_count: self.skipped_message_keys.len(),
            // Was `pre_pq_root_key.is_none()`, which only the responder ever sets: every
            // initiator session — classical ones included — reported itself strengthened.
            is_pq_strengthened: self.pq_applied.unwrap_or(false),
            pq_authentication: self.pq_authentication,
            pq_handshake: self.pq_handshake,
            last_ratchet_at: self.last_ratchet_at,
            session_id: self.session_id.clone(),
        }
    }

    /// Deterministic 16-hex-char fingerprint of the salient ratchet state.
    ///
    /// One-way (SHA-256 over a domain tag + counters + chain/root keys + DH publics), so it is
    /// safe to log. It lets two peers — or the same session before and after a persist
    /// round-trip — be compared cheaply: an equal fingerprint ⇒ identical ratchet position; a
    /// mismatch localises a desync instantly instead of hunting through logs. Excludes
    /// timestamps and the *contents* of the skipped-key map (only its count) so it is stable
    /// across export/import and independent of HashMap iteration order.
    pub fn state_fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"ConstructDR-fingerprint-v1");
        h.update(self.suite_id.as_u16().to_be_bytes());
        h.update(self.sending_chain_length.to_be_bytes());
        h.update(self.receiving_chain_length.to_be_bytes());
        h.update(self.previous_sending_length.to_be_bytes());
        h.update(self.current_pq_epoch.to_be_bytes());
        h.update(self.pq_turns_since_mix.to_be_bytes());
        h.update(self.root_key.as_ref());
        h.update(self.sending_chain_key.as_ref());
        h.update(self.receiving_chain_key.as_ref());
        h.update(self.dh_ratchet_public.as_ref());
        match &self.remote_dh_public {
            Some(k) => h.update(k.as_ref()),
            None => h.update([0u8]),
        }
        h.update((self.skipped_message_keys.len() as u32).to_be_bytes());
        hex::encode(&h.finalize()[..8])
    }

    /// This session was built by PQXDH v2: the ML-KEM secret is in its initial key. Records how
    /// (and, for the initiator, whose key it was — `authentication`).
    pub fn mark_pqxdh_v2(&mut self, authentication: PqAuthentication) {
        self.pq_handshake = PqHandshake::InitialV2;
        self.pq_applied = Some(true);
        self.pq_authentication = authentication;
    }

    /// INITIATOR: the header the first flight carries (see `PrekeyHeader`).
    pub fn set_prekey_header(&mut self, header: PrekeyHeader) {
        self.prekey_header = Some(header);
    }

    /// The header to attach to an outgoing message, while the peer has not answered yet.
    pub fn prekey_header(&self) -> Option<&PrekeyHeader> {
        self.prekey_header.as_ref()
    }

    /// Label the PQ layer of a session this device initiated (the Kyber-prekey plan's verdict).
    pub fn set_pq_authentication(&mut self, authentication: PqAuthentication) {
        self.pq_authentication = authentication;
    }

    pub fn pq_authentication(&self) -> PqAuthentication {
        self.pq_authentication
    }

    /// Restore session state from a snapshot taken before a failed decrypt attempt.
    pub(super) fn restore_snapshot(&mut self, snapshot: Option<DecryptSnapshot<P>>) {
        if let Some(s) = snapshot {
            self.root_key = s.root_key;
            self.sending_chain_key = s.sending_chain_key;
            self.sending_chain_length = s.sending_chain_length;
            self.receiving_chain_key = s.receiving_chain_key;
            self.receiving_chain_length = s.receiving_chain_length;
            self.dh_ratchet_private = s.dh_ratchet_private;
            self.dh_ratchet_public = s.dh_ratchet_public;
            self.remote_dh_public = s.remote_dh_public;
            self.previous_sending_length = s.previous_sending_length;
            self.skipped_message_keys = s.skipped_message_keys;
            self.skipped_key_timestamps = s.skipped_key_timestamps;
            self.pq_turns_since_mix = s.pq_turns_since_mix;
            self.current_pq_epoch = s.current_pq_epoch;
            self.pq_chains = s.pq_chains;
            self.pq_skipped_keys = s.pq_skipped_keys;
            self.pq_skipped_key_timestamps = s.pq_skipped_key_timestamps;
            self.pending_pq_exchange = s.pending_pq_exchange;
            self.pending_pq_ciphertext = s.pending_pq_ciphertext;
            self.pq_pending_since = s.pq_pending_since;
            self.identity_proof = s.identity_proof;
            self.pq_authentication = s.pq_authentication;
        }
    }

    /// INITIATOR: this session's first receiving ratchet step will mix the answer to our KEM
    /// identity key (`IdentityProof::AwaitingAnswer`). Set when the first flight names the key.
    pub fn expect_identity_answer(&mut self) {
        self.identity_proof = IdentityProof::AwaitingAnswer;
    }

    /// RESPONDER, right after the session is built and before anything is sent on it: mix the
    /// secret encapsulated to the initiator's KEM identity key into the root and the first
    /// sending chain, and carry `ciphertext` on every message until the initiator proves itself.
    ///
    /// Mixing into the *first* sending chain is the point: a peer without the key cannot read even
    /// the first reply. The initiator mixes the same secret on the same step from its side
    /// (`perform_dh_ratchet`), so both derive from the same root afterwards.
    pub fn answer_initiator_identity(
        &mut self,
        secret: &[u8],
        ciphertext: Vec<u8>,
    ) -> Result<(), String> {
        if self.sending_chain_length != 0 || self.identity_proof != IdentityProof::None {
            return Err(
                "KEM identity answer: the session has already sent or already answered".into(),
            );
        }
        let (root, chain) =
            Self::mix_identity_secret(&self.root_key, &self.sending_chain_key, secret)?;
        self.root_key = root;
        self.sending_chain_key = chain;
        self.identity_proof = IdentityProof::Answered { ciphertext };
        Ok(())
    }

    pub fn identity_proof(&self) -> &IdentityProof {
        &self.identity_proof
    }

    /// `HKDF(salt = secret, ikm = key)` for the root and for the chain the step derived, under
    /// separate labels — the Triple Ratchet's shape (PQ key as the salt), as in
    /// `mix_pq_message_key`.
    fn mix_identity_secret(
        root: &P::AeadKey,
        chain: &P::AeadKey,
        secret: &[u8],
    ) -> Result<(P::AeadKey, P::AeadKey), String> {
        let root = P::hkdf_derive_key(secret, root.as_ref(), b"Construct-KEM-identity-root-v1", 32)
            .map_err(|e| format!("KEM identity root mix failed: {e:?}"))?;
        let chain = P::hkdf_derive_key(
            secret,
            chain.as_ref(),
            b"Construct-KEM-identity-chain-v1",
            32,
        )
        .map_err(|e| format!("KEM identity chain mix failed: {e:?}"))?;
        Ok((
            Self::bytes_to_aead_key(&root)?,
            Self::bytes_to_aead_key(&chain)?,
        ))
    }

    /// RESPONDER: a message on a chain the initiator derived after mixing our answer decrypted —
    /// only the holder of the KEM identity key could derive it. Stop carrying the ciphertext.
    pub(super) fn complete_identity_proof(&mut self) {
        if matches!(self.identity_proof, IdentityProof::Answered { .. }) {
            self.identity_proof = IdentityProof::None;
            self.pq_authentication = PqAuthentication::ReceivedProven;
            tracing::info!(
                target: "crypto::double_ratchet",
                session_id = %self.session_id,
                "initiator proved its KEM identity key"
            );
        }
    }

    /// Выполнить DH ratchet step
    ///
    /// Вызывается когда получаем сообщение с новым DH public key.
    ///
    /// # Процесс
    ///
    /// 1. DH(old_private, new_remote_public) → receiving_chain
    /// 2. Generate new DH pair
    /// 3. DH(new_private, new_remote_public) → sending_chain
    /// 4. Update state
    /// 5. (suite_id = PQ_RATCHET, initiator only) maybe start a new sparse PQ
    ///    exchange — see `maybe_advance_pq_ratchet`. The PQ layer never touches
    ///    `root_key` or chain keys here: PQ secrets are mixed at the
    ///    message-key level only (see `mix_pq_message_key`).
    ///
    /// `identity_secret` — INITIATOR, first step only (`IdentityProof::AwaitingAnswer`): the
    /// secret the responder encapsulated to our KEM identity key, mixed into the root and the
    /// receiving chain exactly as the responder mixed it into its sending chain.
    pub(super) fn perform_dh_ratchet(
        &mut self,
        new_remote_dh: &P::KemPublicKey,
        identity_secret: Option<&[u8]>,
    ) -> Result<(), String> {
        use tracing::debug;

        debug!(
            target: "crypto::double_ratchet",
            "Performing DH ratchet step"
        );

        self.previous_sending_length = self.sending_chain_length;

        // 1. Get new receiving chain key using old DH private and new remote DH
        let dh_private = self
            .dh_ratchet_private
            .as_ref()
            .ok_or("No DH private key")?;
        let dh_receive = P::kem_decapsulate(dh_private, new_remote_dh.as_ref())
            .map_err(|e| format!("DH failed: {}", e))?;

        let (new_root_key, new_receiving_chain) =
            P::kdf_rk(&self.root_key, &dh_receive).map_err(|e| format!("KDF_RK failed: {}", e))?;
        self.root_key = new_root_key;
        self.receiving_chain_key = new_receiving_chain;
        self.receiving_chain_length = 0;

        if self.identity_proof == IdentityProof::AwaitingAnswer {
            let secret = identity_secret.ok_or(
                "KEM identity answer missing: the responder's first reply carries no ciphertext",
            )?;
            let (root, chain) =
                Self::mix_identity_secret(&self.root_key, &self.receiving_chain_key, secret)?;
            self.root_key = root;
            self.receiving_chain_key = chain;
            self.identity_proof = IdentityProof::None;
        }

        // 2. Generate new DH pair for sending
        let (new_dh_private, new_dh_public) =
            P::generate_kem_keys().map_err(|e| format!("Failed to generate DH keys: {}", e))?;

        // 3. Get sending chain key using new DH private and new remote DH
        let dh_send = P::kem_decapsulate(&new_dh_private, new_remote_dh.as_ref())
            .map_err(|e| format!("DH failed: {}", e))?;

        let (new_root_key2, new_sending_chain) =
            P::kdf_rk(&self.root_key, &dh_send).map_err(|e| format!("KDF_RK failed: {}", e))?;
        self.root_key = new_root_key2;
        self.sending_chain_key = new_sending_chain;
        self.sending_chain_length = 0;

        // 4. Update state — zeroize old private key before overwriting (forward secrecy)
        if let Some(old_key) = self.dh_ratchet_private.as_mut() {
            old_key.zeroize();
        }
        self.dh_ratchet_private = Some(new_dh_private);
        self.dh_ratchet_public = new_dh_public;
        self.remote_dh_public = Some(new_remote_dh.clone());
        self.last_ratchet_at = unix_now();

        // Post-condition invariant: a DH ratchet step resets both chains to zero (the old
        // sending length was captured into previous_sending_length above). If this ever fails,
        // a counter is being carried across a ratchet → guaranteed key-derivation desync.
        debug_assert_eq!(
            self.sending_chain_length, 0,
            "DH ratchet must reset the sending chain to 0"
        );
        debug_assert_eq!(
            self.receiving_chain_length, 0,
            "DH ratchet must reset the receiving chain to 0"
        );

        // Ratchet-boundary observability: a DH step is the highest-risk state transition for a
        // desync. Logging the post-step fingerprint lets a captured device transcript (or the
        // soak harness) pinpoint exactly where two peers' ratchets diverge.
        debug!(
            target: "crypto::double_ratchet",
            fp = %self.state_fingerprint(),
            pn = self.previous_sending_length,
            "DH ratchet step complete"
        );

        // 5. Sparse continuous PQ ratchet — maybe *start* a new exchange
        // (initiator only; never touches root/chain keys).
        self.maybe_advance_pq_ratchet()?;

        debug!(
            target: "crypto::double_ratchet",
            "DH ratchet step completed"
        );

        Ok(())
    }

    /// Sparse continuous PQ ratchet — *starts* a new exchange when the cadence
    /// fires. No-op unless this session's suite is `SuiteID::PQ_RATCHET` and
    /// this side is the designated exchange initiator (single-initiator
    /// discipline — see the SPQR-style design doc).
    ///
    /// Never touches `root_key`/chain keys: completed epoch secrets are mixed
    /// at the message-key level only (`mix_pq_message_key`), which is what
    /// makes the construction immune to the root-key synchronization problem
    /// documented in the spec's §A.2.
    pub(super) fn maybe_advance_pq_ratchet(&mut self) -> Result<(), String> {
        if !self.suite_id.is_pq_ratchet() || !self.is_pq_initiator {
            return Ok(());
        }
        self.abandon_unanswered_pq_exchange();
        self.pq_turns_since_mix = self.pq_turns_since_mix.saturating_add(1);
        if self.pq_turns_since_mix < Config::global().pq_ratchet_interval && !self.pq_epoch_is_old()
        {
            return Ok(());
        }
        self.start_pq_exchange()
    }

    /// PQR-1: the same proposal on a send, when the epoch has outlived
    /// `pq_ratchet_max_age_seconds`. A conversation that never changes direction never takes a DH
    /// turn, so the turn count above never reaches the interval and the epoch would last forever —
    /// the state suite 3 existed to leave. Initiator only, like every proposal: a conversation in
    /// which only the responder writes still cannot rekey (that needs roles that alternate).
    pub(super) fn maybe_start_pq_exchange_by_age(&mut self) -> Result<(), String> {
        if !self.suite_id.is_pq_ratchet() || !self.is_pq_initiator {
            return Ok(());
        }
        self.abandon_unanswered_pq_exchange();
        if !self.pq_epoch_is_old() {
            return Ok(());
        }
        self.start_pq_exchange()
    }

    pub(super) fn pq_epoch_is_old(&self) -> bool {
        unix_now().saturating_sub(self.pq_epoch_since)
            >= Config::global().pq_ratchet_max_age_seconds
    }

    /// Abandon an exchange nobody answered — bandwidth hygiene only. Safe because nothing was
    /// activated: the peer's provisional state (if any) is superseded by the next proposal's fresh
    /// keypair, disambiguated by `ek_hash`.
    fn abandon_unanswered_pq_exchange(&mut self) {
        let max_age = Config::global().max_skipped_message_age_seconds.max(0) as u64;
        if self.pq_pending_since != 0
            && unix_now().saturating_sub(self.pq_pending_since) > max_age
            && let Some(mut ex) = self.pending_pq_exchange.take()
        {
            ex.zeroize();
            self.pq_pending_since = 0;
        }
    }

    /// Propose epoch `current + 1` with a fresh ML-KEM-768 keypair, unless one is in flight — one
    /// at a time; the next turn or send tries again.
    fn start_pq_exchange(&mut self) -> Result<(), String> {
        if self.pending_pq_exchange.is_some() {
            return Ok(());
        }
        let keypair = crate::crypto::pq_x3dh::mlkem768_keygen()
            .map_err(|e| format!("PQ ratchet keygen failed: {e}"))?;
        self.pending_pq_exchange = Some(PendingPqExchange {
            epoch: self.current_pq_epoch.saturating_add(1),
            keypair: PqRatchetKeyPair {
                public: keypair.public_key,
                secret: keypair.secret_key.into_vec(),
            },
        });
        self.pq_pending_since = unix_now();
        self.pq_turns_since_mix = 0;
        Ok(())
    }

    /// 8-byte identifier of an ML-KEM encapsulation key, carried alongside a
    /// ciphertext so the initiator can tell which of its (possibly re-proposed)
    /// keypairs the ciphertext completes.
    pub(super) fn pq_ek_hash(ek: &[u8]) -> [u8; 8] {
        let mut out = [0u8; 8];
        if let Ok(bytes) = P::hkdf_derive_key(&[], ek, b"construct-pqr-ekhash-v1", 8) {
            out.copy_from_slice(&bytes);
        }
        out
    }

    /// Commit-phase PQ processing, called from `decrypt()` **only after** the
    /// carrier message authenticated and decrypted successfully (mirrors
    /// libsignal's commit-on-success discipline). By construction an EK/CT
    /// field always rides on messages tagged with a pre-completion epoch, so
    /// decrypting the carrier never depends on the material it carries.
    ///
    /// All failures are logged and swallowed: the classical content was already
    /// delivered, and a malformed PQ field must never poison session state.
    pub(super) fn commit_pq_post_decrypt(&mut self, encrypted: &EncryptedRatchetMessage) {
        if !self.suite_id.is_pq_ratchet() {
            return;
        }

        // 1. Promotion: a peer message tagged >= our provisional epoch proves
        // the initiator decapsulated the same secret (that tag was just used,
        // successfully, to derive this message's key).
        if self
            .pending_pq_ciphertext
            .as_ref()
            .is_some_and(|p| encrypted.pq_message_epoch >= p.epoch)
        {
            let p = self.pending_pq_ciphertext.take().expect("checked above");
            self.current_pq_epoch = self.current_pq_epoch.max(p.epoch);
            self.insert_pq_epoch_chains(p.chains.clone());
            self.pq_epoch_since = unix_now();
        }

        // 2. Field ingestion.
        let Some(field) = &encrypted.pq_ratchet_field else {
            return;
        };
        match field {
            PqRatchetWireField::PublicKey { epoch, key } => {
                if self.is_pq_initiator {
                    tracing::warn!(
                        target: "crypto::double_ratchet",
                        "ignoring PQ public key from peer: we are the exchange initiator"
                    );
                    return;
                }
                if *epoch <= self.current_pq_epoch {
                    return; // stale straggler from an epoch already completed
                }
                let incoming_hash = Self::pq_ek_hash(key);
                if let Some(p) = &self.pending_pq_ciphertext
                    && p.epoch == *epoch
                    && p.ek_hash == incoming_hash
                {
                    return; // duplicate EK — keep resending the existing ciphertext
                }
                // New proposal (new epoch, or same epoch re-proposed with a
                // fresh keypair after abandonment): encapsulate once, replace
                // any previous provisional state.
                match crate::crypto::pq_x3dh::mlkem768_encapsulate(key) {
                    Ok(enc) => {
                        // The secret is spent on the epoch's chains here and never stored.
                        let chains = match Self::pq_epoch_chains(
                            enc.shared_secret.as_ref(),
                            *epoch,
                            self.is_pq_initiator,
                        ) {
                            Ok(chains) => chains,
                            Err(e) => {
                                tracing::warn!(
                                    target: "crypto::double_ratchet",
                                    "PQ epoch chains failed (classical delivery unaffected): {e}"
                                );
                                return;
                            }
                        };
                        if let Some(mut old) = self.pending_pq_ciphertext.take() {
                            old.zeroize();
                        }
                        self.pending_pq_ciphertext = Some(PendingPqCiphertext {
                            epoch: *epoch,
                            ek_hash: incoming_hash,
                            ciphertext: enc.ciphertext,
                            chains,
                        });
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: "crypto::double_ratchet",
                            "ignoring bad PQ public key (classical delivery unaffected): {e}"
                        );
                    }
                }
            }
            PqRatchetWireField::Ciphertext { epoch, ek_hash, ct } => {
                let Some(p) = &self.pending_pq_exchange else {
                    return; // duplicate/stale ct after we already completed or abandoned
                };
                if p.epoch != *epoch || Self::pq_ek_hash(&p.keypair.public) != *ek_hash {
                    return; // ct for an abandoned keypair — ignore, keep re-advertising ours
                }
                match crate::crypto::pq_x3dh::mlkem768_decapsulate(&p.keypair.secret, ct) {
                    Ok(shared_secret) => {
                        let chains = match Self::pq_epoch_chains(
                            shared_secret.as_ref(),
                            *epoch,
                            self.is_pq_initiator,
                        ) {
                            Ok(chains) => chains,
                            Err(e) => {
                                tracing::warn!(
                                    target: "crypto::double_ratchet",
                                    "PQ epoch chains failed (classical delivery unaffected): {e}"
                                );
                                return;
                            }
                        };
                        // Activate: we (the initiator) start sending on this epoch's chain
                        // immediately; the responder promotes on our first message of it.
                        let mut ex = self.pending_pq_exchange.take().expect("checked above");
                        ex.zeroize();
                        self.current_pq_epoch = *epoch;
                        self.insert_pq_epoch_chains(chains);
                        self.pq_pending_since = 0;
                        self.pq_epoch_since = unix_now();
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: "crypto::double_ratchet",
                            "ignoring bad PQ ciphertext (classical delivery unaffected): {e}"
                        );
                    }
                }
            }
        }
    }

    /// The two chains of epoch `epoch`, from its ML-KEM shared secret (PQR-2):
    /// `HKDF(ikm = secret, info = "construct-pqr-chains-v2" ‖ epoch BE, 64)` split into the chain
    /// the PQ-exchange initiator sends on (first half) and the one the responder sends on. The
    /// caller drops the secret after this; nothing else is ever derived from it.
    pub(super) fn pq_epoch_chains(
        secret: &[u8],
        epoch: u32,
        is_pq_initiator: bool,
    ) -> Result<PqEpochChains, String> {
        let mut info = b"construct-pqr-chains-v2".to_vec();
        info.extend_from_slice(&epoch.to_be_bytes());
        let mut out = P::hkdf_derive_key(&[], secret, &info, 64)
            .map_err(|e| format!("PQ epoch chains: {e:?}"))?;
        let initiator_sends = PqChain {
            index: 0,
            key: out[..32].to_vec(),
        };
        let responder_sends = PqChain {
            index: 0,
            key: out[32..].to_vec(),
        };
        out.zeroize();
        let (send, recv) = if is_pq_initiator {
            (initiator_sends, responder_sends)
        } else {
            (responder_sends, initiator_sends)
        };
        Ok(PqEpochChains {
            epoch,
            send: Some(send),
            recv,
        })
    }

    /// One step of a PQ chain: `HKDF(ikm = key, info = "construct-pqr-step-v2", 64)` — the first
    /// half replaces the chain key, the second is the key for index `chain.index`, which the
    /// chain then moves past. Returns `(index, key)`.
    pub(super) fn pq_chain_step(chain: &mut PqChain) -> Result<(u32, Vec<u8>), String> {
        let mut out = P::hkdf_derive_key(&[], &chain.key, b"construct-pqr-step-v2", 64)
            .map_err(|e| format!("PQ chain step: {e:?}"))?;
        let index = chain.index;
        chain.index = index
            .checked_add(1)
            .ok_or("PQ chain index overflow: an epoch has exceeded u32::MAX messages")?;
        chain.key.zeroize();
        chain.key = out[..32].to_vec();
        let key = out[32..].to_vec();
        out.zeroize();
        Ok((index, key))
    }

    /// Keep a completed epoch's chains. Every older epoch stops sending (its send chain is
    /// erased: nothing is written on it again), and beyond `PQ_CHAIN_RETENTION` the oldest
    /// epoch goes entirely.
    pub(super) fn insert_pq_epoch_chains(&mut self, chains: PqEpochChains) {
        let epoch = chains.epoch;
        if let Some(mut replaced) = self
            .pq_chains
            .iter()
            .position(|c| c.epoch == epoch)
            .map(|i| self.pq_chains.remove(i))
        {
            replaced.zeroize();
        }
        for older in self.pq_chains.iter_mut().filter(|c| c.epoch < epoch) {
            if let Some(mut send) = older.send.take() {
                send.zeroize();
            }
        }
        self.pq_chains.push(chains);
        self.pq_chains.sort_by_key(|c| c.epoch);
        while self.pq_chains.len() > PQ_CHAIN_RETENTION {
            let mut old = self.pq_chains.remove(0);
            old.zeroize();
        }
    }

    /// The key for the next outgoing message: `(epoch, index, key)`, or `(0, 0, None)` before the
    /// first epoch completes. The send chain advances here, before the AEAD — a message that is
    /// then not sent leaves a gap the receiver skips like any lost message.
    pub(super) fn pq_send_key(&mut self) -> Result<(u32, u32, Option<Vec<u8>>), String> {
        let epoch = self.current_pq_epoch;
        if !self.suite_id.is_pq_ratchet() || epoch == 0 {
            return Ok((0, 0, None));
        }
        let chain = self
            .pq_chains
            .iter_mut()
            .find(|c| c.epoch == epoch)
            .and_then(|c| c.send.as_mut())
            .ok_or_else(|| format!("PQ epoch {epoch} has no send chain"))?;
        let (index, key) = Self::pq_chain_step(chain)?;
        Ok((epoch, index, Some(key)))
    }

    /// The key a received message names by `(epoch, index)`: a skipped key if one was kept,
    /// otherwise the epoch's receive chain moved up to `index` — keeping the keys it passes, up
    /// to the skipped-key bound. Mutates the chains; `decrypt` restores its snapshot if the
    /// message then fails, so a forged index cannot consume a slot.
    ///
    /// An epoch without chains is a hard error — silently skipping the mix would be a downgrade.
    pub(super) fn pq_receive_key(
        &mut self,
        epoch: u32,
        index: u32,
    ) -> Result<Option<Vec<u8>>, String> {
        if !self.suite_id.is_pq_ratchet() || epoch == 0 {
            if index != 0 {
                return Err(format!("PQ key index {index} without an epoch"));
            }
            return Ok(None);
        }
        if let Some(key) = self.pq_skipped_keys.remove(&(epoch, index)) {
            self.pq_skipped_key_timestamps.remove(&(epoch, index));
            return Ok(Some(key));
        }
        let current = self.current_pq_epoch;
        let max_jump = Config::global().max_message_jump;
        let max_skipped = Config::global().max_skipped_messages as usize;
        let chain = match self.pq_chains.iter_mut().find(|c| c.epoch == epoch) {
            Some(c) => &mut c.recv,
            None => match self.pending_pq_ciphertext.as_mut() {
                Some(p) if p.epoch == epoch => &mut p.chains.recv,
                _ => {
                    return Err(format!(
                        "PQ epoch {epoch} has no chain (current epoch {current}) — \
                         message tagged with an unknown/evicted epoch"
                    ));
                }
            },
        };
        if index < chain.index {
            return Err(format!(
                "{}: PQ key {epoch}/{index} already used (chain at {})",
                super::MESSAGE_KEY_CONSUMED,
                chain.index
            ));
        }
        if index > chain.index.saturating_add(max_jump) {
            return Err(format!(
                "PQ key index jump too large: {} -> {index} (limit +{max_jump})",
                chain.index
            ));
        }
        let now = crate::utils::time::now();
        loop {
            let (i, key) = Self::pq_chain_step(chain)?;
            if i == index {
                return Ok(Some(key));
            }
            if self.pq_skipped_keys.len() >= max_skipped {
                return Err("Too many skipped PQ keys".to_string());
            }
            self.pq_skipped_keys.insert((epoch, i), key);
            self.pq_skipped_key_timestamps.insert((epoch, i), now);
        }
    }

    /// Hybridize a Double Ratchet message key with the message's PQ chain key:
    /// `HKDF(salt = pq_key, ikm = dr_message_key, "construct-pqr-msg-v2")` — the same shape as
    /// libsignal's Triple Ratchet, where the PQ key is the HKDF salt. `None` (no epoch yet, or not
    /// the PQ suite) returns the DR key unchanged.
    pub(super) fn mix_pq_message_key(
        dr_key: &P::AeadKey,
        pq_key: Option<&[u8]>,
    ) -> Result<P::AeadKey, String> {
        let Some(pq_key) = pq_key else {
            return Ok(dr_key.clone());
        };
        let mixed = P::hkdf_derive_key(pq_key, dr_key.as_ref(), b"construct-pqr-msg-v2", 32)
            .map_err(|e| format!("PQ message-key mix failed: {e:?}"))?;
        Self::bytes_to_aead_key(&mixed)
    }

    /// Fetch the pending outgoing PQ-ratchet field, if any (initiator: our
    /// fresh public key; responder: our ciphertext reply). Does not clear the
    /// pending state — the field is re-attached to every outgoing message until
    /// implicitly acknowledged (initiator: matching ciphertext arrives;
    /// responder: a peer message tagged >= the provisional epoch), so dropped
    /// messages are self-healing.
    pub(super) fn take_outgoing_pq_field(&self) -> Option<PqRatchetWireField> {
        if !self.suite_id.is_pq_ratchet() {
            return None;
        }
        if let Some(p) = &self.pending_pq_ciphertext {
            return Some(PqRatchetWireField::Ciphertext {
                epoch: p.epoch,
                ek_hash: p.ek_hash,
                ct: p.ciphertext.clone(),
            });
        }
        self.pending_pq_exchange
            .as_ref()
            .map(|ex| PqRatchetWireField::PublicKey {
                epoch: ex.epoch,
                key: ex.keypair.public.clone(),
            })
    }

    /// Расшифровать с заданным message key.
    ///
    /// For PQ-ratchet sessions the stored DR key is first hybridized with the PQ
    /// epoch secret named by the message's `pq_message_epoch` tag (see
    /// `mix_pq_message_key`) — this also covers skipped-message keys, which are
    /// stored pre-mix.
    ///
    /// One AEAD attempt, with `AD_VERSION`. Until 0.24.2 a failure was retried with AD v2 for
    /// writers older than 2026-05-18 (SEC-006); every session this build can open was made by
    /// PQXDH v2 (2026-09-25), whose writers all use v3, so the retry could no longer succeed —
    /// it only doubled the work of every failure.
    pub(super) fn decrypt_with_key(
        &mut self,
        message_key: &P::AeadKey,
        encrypted: &EncryptedRatchetMessage,
    ) -> Result<Vec<u8>, String> {
        use tracing::trace;

        trace!(
            target: "crypto::double_ratchet",
            msg_num = %encrypted.message_number,
            nonce_len = %encrypted.nonce.len(),
            ciphertext_len = %encrypted.ciphertext.len(),
            "Decrypting with message key"
        );

        let (pq_epoch, pq_index) = if self.suite_id.is_pq_ratchet() {
            (encrypted.pq_message_epoch, encrypted.pq_key_index)
        } else {
            (0, 0)
        };
        let mut pq_key = self.pq_receive_key(pq_epoch, pq_index)?;
        let mixed = Self::mix_pq_message_key(message_key, pq_key.as_deref());
        if let Some(k) = pq_key.as_mut() {
            k.zeroize();
        }
        let message_key = &mixed?;

        self.try_aead_decrypt(message_key, encrypted)
    }

    /// AEAD decryption with the associated data rebuilt from the session and the header.
    pub(super) fn try_aead_decrypt(
        &self,
        message_key: &P::AeadKey,
        encrypted: &EncryptedRatchetMessage,
    ) -> Result<Vec<u8>, String> {
        let ad_version = AD_VERSION;
        use super::storage::id_prefix;
        use tracing::debug;

        // Reconstruct Associated Data: must mirror encrypt() exactly.
        // Decrypt uses contact_id as sender (= local_user_id on encrypt side) and vice versa.
        let session_id_bytes: Vec<u8> = hex::decode(&self.session_id).map_err(|_| {
            format!(
                "AEAD decrypt: session_id '{}' is not valid hex — session may be corrupt; \
                 re-initialise the session",
                &self.session_id
            )
        })?;
        let mut associated_data = Vec::with_capacity(
            1 + self.contact_id.len() + self.local_user_id.len() + 16 + 32 + 4 + 8,
        );
        associated_data.push(ad_version);
        associated_data.extend_from_slice(self.contact_id.as_bytes());
        associated_data.extend_from_slice(self.local_user_id.as_bytes());
        associated_data.extend_from_slice(&session_id_bytes);
        associated_data.extend_from_slice(&encrypted.dh_public_key);
        associated_data.extend_from_slice(&encrypted.message_number.to_be_bytes());
        if self.suite_id.is_pq_ratchet() {
            // Mirrors encrypt(): the AD binds the PQ epoch and key index (see encrypt's doc).
            associated_data.extend_from_slice(&encrypted.pq_message_epoch.to_be_bytes());
            associated_data.extend_from_slice(&encrypted.pq_key_index.to_be_bytes());
        }

        // Prefixes, at debug — the failure branch below is deliberately limited to lengths, and
        // this line used to write all three identifiers in full at info level. One function, one
        // convention: enough to correlate a session across lines, not enough to be a record of who
        // spoke to whom in a log the user can export from Settings.
        debug!(
            target: "crypto::double_ratchet",
            local_user_id = %id_prefix(&self.local_user_id),
            contact_id = %id_prefix(&self.contact_id),
            session_id = %id_prefix(&self.session_id),
            msg_num = %encrypted.message_number,
            ad_version = %ad_version,
            dh_pub_prefix = %crate::crypto::log_fingerprint::public_prefix(&encrypted.dh_public_key),
            ad_len = %associated_data.len(),
            "DECRYPT AD built"
        );

        let padded_plaintext = P::aead_decrypt(
            message_key,
            &encrypted.nonce,
            &encrypted.ciphertext,
            Some(&associated_data),
        )
        .map_err(|e| {
            // Privacy-safe diagnostic: log field lengths, not values. A local_user_id/contact_id
            // mismatch in *kind* shows up immediately as a length difference, and the lengths are
            // the whole diagnosis: 32 is a device id, 36 an account UUID.
            //
            // This advice said the opposite until 2026-08-26 — "both must be server UUIDs
            // (36 chars); a 32-char device-hash on either side will produce a permanent AD
            // mismatch". That was correct when it was written and was inverted by the flip to
            // device addressing, which changed what belongs in these fields without touching this
            // line. A stale diagnostic is worse than none: it is read exactly when someone is
            // already lost, and it sends them the wrong way.
            tracing::error!(
                target: "crypto::double_ratchet",
                local_user_id_len = %self.local_user_id.len(),
                contact_id_len = %self.contact_id.len(),
                ad_total_len = %associated_data.len(),
                ad_version = %ad_version,
                msg_num = %encrypted.message_number,
                "AEAD decryption failed — local_user_id and contact_id must both be crypto \
                 device ids (32 hex chars). A 36-char account UUID on either side is a \
                 permanent AD mismatch: the two sides are naming different pairs"
            );
            format!("Decryption failed: {}", e)
        })?;

        debug!(
            target: "crypto::double_ratchet",
            ad_version = %ad_version,
            "Decryption successful"
        );

        // Remove padding to recover original plaintext (traffic analysis protection)
        use crate::traffic_protection::padding::unpad_message;
        let plaintext =
            unpad_message(&padded_plaintext).map_err(|e| format!("Unpadding failed: {}", e))?;

        Ok(plaintext)
    }

    // Helper functions to convert between bytes and keys
    pub(super) fn bytes_to_aead_key(bytes: &[u8]) -> Result<P::AeadKey, String> {
        Ok(P::aead_key_from_bytes(bytes.to_vec()))
    }

    pub(super) fn bytes_to_kem_public_key(bytes: &[u8]) -> Result<P::KemPublicKey, String> {
        Ok(P::kem_public_key_from_bytes(bytes.to_vec()))
    }

    pub(super) fn bytes_to_kem_private_key(bytes: &[u8]) -> Result<P::KemPrivateKey, String> {
        Ok(P::kem_private_key_from_bytes(bytes.to_vec()))
    }
}
