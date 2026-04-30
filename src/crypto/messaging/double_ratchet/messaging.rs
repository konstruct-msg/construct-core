use super::*;
use crate::config::Config;
use crate::crypto::SuiteID;
use crate::crypto::handshake::InitiatorState;
use crate::crypto::messaging::SecureMessaging;
use crate::crypto::provider::CryptoProvider;
use std::collections::HashMap;

impl<P: CryptoProvider> SecureMessaging<P> for DoubleRatchetSession<P> {
    type EncryptedMessage = EncryptedRatchetMessage;

    /// Создать сессию как инициатор (Alice)
    ///
    /// Alice вызывает это после X3DH handshake.
    ///
    /// # Критически важно
    ///
    /// `initiator_state.ephemeral_private` - это тот же ключ, который использовался в X3DH!
    /// Он становится первым DH ratchet key.
    ///
    /// Это обеспечивает, что Bob сможет:
    /// 1. Извлечь ephemeral_public из первого сообщения
    /// 2. Выполнить X3DH с этим ключом
    /// 3. Получить тот же root_key
    fn new_initiator_session(
        root_key: &[u8],
        initiator_state: InitiatorState<P>,
        remote_identity: &P::KemPublicKey,
        contact_id: String,
        local_user_id: String,
    ) -> Result<Self, String> {
        use tracing::debug;

        debug!(
            target: "crypto::double_ratchet",
            contact_id = %contact_id,
            "Creating initiator session (Alice)"
        );

        // Derive shared session_id from the raw X3DH root key BEFORE the DR HKDF step.
        let shared_session_id = derive_shared_session_id::<P>(root_key)
            .map_err(|e| format!("INITIATOR: session_id derivation failed: {}", e))?;

        tracing::info!(
            target: "crypto::double_ratchet",
            contact_id = %contact_id,
            root_key_prefix = %hex::encode(&root_key[..8.min(root_key.len())]),
            session_id = %shared_session_id,
            "INITIATOR session_id derived"
        );

        // Convert root_key bytes to P::AeadKey
        // ✅ SECURITY: Use dedicated salt for Double Ratchet (different from X3DH)
        let salt = [0xFE_u8; 32];
        let root_key_vec = P::hkdf_derive_key(&salt, root_key, b"InitialRootKey", 32)
            .map_err(|e| format!("Failed to derive root key: {}", e))?;
        let root_key_val = Self::bytes_to_aead_key(&root_key_vec)?;

        // ✅ Use X3DH ephemeral key as first DH ratchet key
        // NOT generating new one!
        let dh_private = initiator_state.ephemeral_private;
        let dh_public = P::from_private_key_to_public_key(&dh_private)
            .map_err(|e| format!("Failed to derive public key: {}", e))?;

        debug!(
            target: "crypto::double_ratchet",
            "Using X3DH ephemeral key as initial DH ratchet key"
        );

        // Perform DH(alice_ephemeral_priv, bob_identity_pub) → sending_chain
        let dh_output_secret = P::kem_decapsulate(&dh_private, remote_identity.as_ref())
            .map_err(|e| format!("Failed to perform DH: {}", e))?;

        let (root_key, chain_key) = P::kdf_rk(&root_key_val, &dh_output_secret)
            .map_err(|e| format!("KDF_RK failed: {}", e))?;

        Ok(Self {
            suite_id: SuiteID::CLASSIC,
            root_key,
            sending_chain_key: chain_key,
            sending_chain_length: 0,
            receiving_chain_key: P::AeadKey::default(),
            receiving_chain_length: 0,
            dh_ratchet_private: Some(dh_private),
            dh_ratchet_public: dh_public,
            remote_dh_public: Some(remote_identity.clone()),
            previous_sending_length: 0,
            skipped_message_keys: HashMap::new(),
            skipped_key_timestamps: HashMap::new(),
            pre_pq_root_key: None,
            session_id: shared_session_id,
            contact_id,
            local_user_id,
            last_ratchet_at: unix_now(),
        })
    }

    /// Создать сессию как получатель (Bob)
    ///
    /// Bob вызывает это при получении первого сообщения от Alice.
    ///
    /// # Процесс
    ///
    /// 1. Извлекает Alice's ephemeral_public из first_message.dh_public_key
    /// 2. Выполняет DH(bob_identity_priv, alice_ephemeral_pub) → receiving_chain
    /// 3. Генерирует новую DH пару для отправки
    /// 4. Выполняет второй DH ratchet для sending_chain
    /// 5. **Расшифровывает первое сообщение**
    fn new_responder_session(
        root_key: &[u8],
        local_identity: &P::KemPrivateKey,
        first_message: &Self::EncryptedMessage,
        contact_id: String,
        local_user_id: String,
    ) -> Result<(Self, Vec<u8>), String> {
        use tracing::debug;

        debug!(
            target: "crypto::double_ratchet",
            contact_id = %contact_id,
            "Creating responder session (Bob)"
        );

        // Extract Alice's ephemeral public key from first message
        let remote_dh_public_bytes = &first_message.dh_public_key;
        let remote_dh_public = Self::bytes_to_kem_public_key(remote_dh_public_bytes)?;

        debug!(
            target: "crypto::double_ratchet",
            "Extracted Alice's ephemeral key from first message"
        );

        // Derive shared session_id from the raw X3DH root key BEFORE the DR HKDF step,
        // so both INITIATOR and RESPONDER compute the same value without a round-trip.
        let shared_session_id = derive_shared_session_id::<P>(root_key)
            .map_err(|e| format!("RESPONDER: session_id derivation failed: {}", e))?;

        tracing::info!(
            target: "crypto::double_ratchet",
            root_key_prefix = %hex::encode(&root_key[..8.min(root_key.len())]),
            session_id = %shared_session_id,
            "RESPONDER session_id derived"
        );

        // Convert root_key bytes to P::AeadKey
        // ✅ SECURITY: Use dedicated salt for Double Ratchet (different from X3DH)
        let salt = [0xFE_u8; 32];
        let root_key_vec = P::hkdf_derive_key(&salt, root_key, b"InitialRootKey", 32)
            .map_err(|e| format!("Failed to derive root key: {}", e))?;
        let mut root_key_val = Self::bytes_to_aead_key(&root_key_vec)?;

        // Perform DH(bob_identity_priv, alice_ephemeral_pub) → receiving_chain
        let dh_output = P::kem_decapsulate(local_identity, remote_dh_public.as_ref())
            .map_err(|e| format!("Failed to perform DH: {}", e))?;
        let (new_root_key, receiving_chain) =
            P::kdf_rk(&root_key_val, &dh_output).map_err(|e| format!("KDF_RK failed: {}", e))?;
        root_key_val = new_root_key;

        // ⚡ Save the root key at this point (RK1) for PQXDH deferred contribution.
        // Both INITIATOR and RESPONDER have RK1 after the first ratchet step, so
        // applying PQ to RK1 produces identical results on both sides.
        // Without this, INITIATOR applies PQ to RK1 but RESPONDER applies PQ to RK2
        // (after the second ratchet below), causing irreversible key divergence.
        let pre_pq_root_key = root_key_val.clone();

        // Generate new DH pair for sending
        let (dh_private, dh_public) =
            P::generate_kem_keys().map_err(|e| format!("Failed to generate DH keys: {}", e))?;

        debug!(
            target: "crypto::double_ratchet",
            "Generated new DH pair for sending"
        );

        // Perform second ratchet for sending chain
        let dh_output2 = P::kem_decapsulate(&dh_private, remote_dh_public.as_ref())
            .map_err(|e| format!("Failed to perform DH: {}", e))?;
        let (final_root_key, sending_chain) =
            P::kdf_rk(&root_key_val, &dh_output2).map_err(|e| format!("KDF_RK failed: {}", e))?;

        // Валидация suite_id из первого сообщения
        let suite_id = SuiteID::new(first_message.suite_id)
            .map_err(|e| format!("Invalid suite_id in first message: {}", e))?;

        let mut session = Self {
            suite_id,
            root_key: final_root_key,
            sending_chain_key: sending_chain,
            sending_chain_length: 0,
            receiving_chain_key: receiving_chain,
            receiving_chain_length: 0,
            dh_ratchet_private: Some(dh_private),
            dh_ratchet_public: dh_public,
            remote_dh_public: Some(remote_dh_public),
            previous_sending_length: 0,
            skipped_message_keys: HashMap::new(),
            skipped_key_timestamps: HashMap::new(),
            pre_pq_root_key: Some(pre_pq_root_key),
            session_id: shared_session_id,
            contact_id: contact_id.clone(),
            local_user_id,
            last_ratchet_at: unix_now(),
        };

        // КРИТИЧЕСКИ ВАЖНО: Расшифровываем первое сообщение!
        // Bob должен прочитать первое сообщение чтобы получить plaintext.
        debug!(
            target: "crypto::double_ratchet",
            "Decrypting first message from Alice"
        );

        let plaintext = session.decrypt(first_message)?;

        debug!(
            target: "crypto::double_ratchet",
            plaintext_len = %plaintext.len(),
            "First message decrypted successfully"
        );

        Ok((session, plaintext))
    }

    /// Зашифровать сообщение
    ///
    /// # Процесс
    ///
    /// 1. Derive message key: (chain_key', msg_key) = KDF_CK(chain_key)
    /// 2. Increment sending_chain_length
    /// 3. Encrypt: ciphertext = AEAD(msg_key, nonce, plaintext)
    /// 4. Return EncryptedMessage with current DH public key
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Self::EncryptedMessage, String> {
        use tracing::trace;

        trace!(
            target: "crypto::double_ratchet",
            plaintext_len = %plaintext.len(),
            chain_length = %self.sending_chain_length,
            "Encrypting message"
        );

        // Apply padding to hide message length (traffic analysis protection)
        use crate::traffic_protection::padding::pad_message_default;
        let padded_plaintext = pad_message_default(plaintext).map_err(|e| {
            tracing::error!(
                target: "crypto::double_ratchet",
                error = %e,
                plaintext_len = plaintext.len(),
                "Padding failed"
            );
            format!("Padding failed: {}", e)
        })?;

        let (message_key, next_chain_key) = P::kdf_ck(&self.sending_chain_key).map_err(|e| {
            tracing::error!(
                target: "crypto::double_ratchet",
                error = %e,
                "KDF (CK) failed"
            );
            format!("KDF (CK) failed: {}", e)
        })?;
        self.sending_chain_key = next_chain_key;

        let message_number = self.sending_chain_length;
        self.sending_chain_length = self
            .sending_chain_length
            .checked_add(1)
            .ok_or("sending_chain_length overflow: session has exceeded u32::MAX messages")?;

        // Generate nonce - use configured nonce length for ChaCha20Poly1305
        let nonce = P::generate_nonce(Config::global().chacha_nonce_length)
            .map_err(|e| format!("Nonce generation failed: {}", e))?;

        // Convert dh_ratchet_public to [u8; 32] first
        let dh_public_key_vec = self.dh_ratchet_public.as_ref().to_vec();
        let dh_public_key: [u8; 32] = dh_public_key_vec
            .try_into()
            .map_err(|_| "Invalid public key length")?;

        // Associated Data v2: version(1B) || sender_id || receiver_id || session_id(16B) || dh_pub(32B) || msg_num(4B)
        // The session_id is derived from the shared X3DH root key so both sides compute the same value.
        let session_id_bytes: Vec<u8> = hex::decode(&self.session_id).map_err(|_| {
            format!(
                "AEAD encrypt: session_id '{}' is not valid hex — session may be corrupt; \
                 re-initialise the session",
                &self.session_id
            )
        })?;
        let mut associated_data =
            Vec::with_capacity(1 + self.local_user_id.len() + self.contact_id.len() + 16 + 32 + 4);
        associated_data.push(AD_VERSION); // AD version (see const AD_VERSION)
        associated_data.extend_from_slice(self.local_user_id.as_bytes());
        associated_data.extend_from_slice(self.contact_id.as_bytes());
        associated_data.extend_from_slice(&session_id_bytes);
        associated_data.extend_from_slice(&dh_public_key);
        associated_data.extend_from_slice(&message_number.to_be_bytes());

        tracing::info!(
            target: "crypto::double_ratchet",
            local_user_id = %self.local_user_id,
            contact_id = %self.contact_id,
            session_id = %self.session_id,
            msg_num = %message_number,
            dh_pub_prefix = %hex::encode(&dh_public_key[..4]),
            ad_len = %associated_data.len(),
            "ENCRYPT AD built"
        );

        let ciphertext = P::aead_encrypt(
            &message_key,
            &nonce,
            &padded_plaintext,
            Some(&associated_data),
        )
        .map_err(|e| {
            tracing::error!(
                target: "crypto::double_ratchet",
                error = %e,
                padded_plaintext_len = padded_plaintext.len(),
                nonce_len = nonce.len(),
                "AEAD encryption failed"
            );
            format!("Encryption failed: {}", e)
        })?;

        trace!(
            target: "crypto::double_ratchet",
            ciphertext_len = %ciphertext.len(),
            "Encryption successful"
        );

        Ok(EncryptedRatchetMessage {
            dh_public_key,
            message_number,
            ciphertext,
            nonce,
            previous_chain_length: self.previous_sending_length,
            suite_id: self.suite_id.as_u16(),
        })
    }

    /// Расшифровать сообщение
    ///
    /// # Процесс
    ///
    /// 1. Check if DH public key changed → perform DH ratchet if needed
    /// 2. Check if message number is ahead → save skipped keys
    /// 3. Derive message key: (chain_key', msg_key) = KDF_CK(chain_key)
    /// 4. Decrypt: plaintext = AEAD_decrypt(msg_key, nonce, ciphertext)
    ///
    /// # DoS Protection
    ///
    /// - Лимит на количество skipped keys (MAX_SKIPPED_MESSAGES)
    /// - Automatic cleanup старых ключей по timestamp
    fn decrypt(&mut self, encrypted: &Self::EncryptedMessage) -> Result<Vec<u8>, String> {
        use tracing::{debug, trace};

        // Periodically evict stale skipped-message keys to bound memory usage.
        // Running every 100 received messages is cheap and avoids a 7-day accumulation.
        if self.receiving_chain_length % 100 == 0 && !self.skipped_message_keys.is_empty() {
            self.cleanup_old_skipped_keys(Config::global().max_skipped_message_age_seconds);
        }

        debug!(
            target: "crypto::double_ratchet",
            msg_num = %encrypted.message_number,
            current_recv_chain_len = %self.receiving_chain_length,
            skipped_keys_count = %self.skipped_message_keys.len(),
            "Decrypting message"
        );

        // CPU DoS guard: reject messages whose sequence number would force the chain
        // to advance by more than max_message_jump steps before hitting the skipped-key
        // memory limit.  Without this, an attacker can send msg_num = 1_000_000 and
        // cause O(N) HKDF work in the tight while-loop below.
        let max_jump = Config::global().max_message_jump;
        if encrypted.message_number > self.receiving_chain_length.saturating_add(max_jump) {
            return Err(format!(
                "Message number jump too large: {} -> {} (limit +{})",
                self.receiving_chain_length, encrypted.message_number, max_jump
            ));
        }
        // Same bound for the previous-chain skip loop (previous_chain_length).
        if encrypted.previous_chain_length > self.receiving_chain_length.saturating_add(max_jump) {
            return Err(format!(
                "Previous chain length jump too large: {} -> {} (limit +{})",
                self.receiving_chain_length, encrypted.previous_chain_length, max_jump
            ));
        }

        // Convert DH public key from message
        let remote_dh_public = Self::bytes_to_kem_public_key(&encrypted.dh_public_key)?;

        // Check if we need to perform DH ratchet
        let needs_ratchet = match &self.remote_dh_public {
            Some(current_remote) => {
                // Compare byte representation
                current_remote.as_ref() != remote_dh_public.as_ref()
            }
            None => true,
        };

        // Snapshot mutable state before any mutations so we can roll back
        // if AEAD decryption ultimately fails — prevents permanent session corruption.
        // This covers both DH ratchet steps AND symmetric chain advances:
        // without this, a tampered message_number (same DH key) permanently
        // consumes a chain key slot and makes the real message undecryptable.
        let snapshot = Some(DecryptSnapshot {
            root_key: self.root_key.clone(),
            sending_chain_key: self.sending_chain_key.clone(),
            sending_chain_length: self.sending_chain_length,
            receiving_chain_key: self.receiving_chain_key.clone(),
            receiving_chain_length: self.receiving_chain_length,
            dh_ratchet_private: self.dh_ratchet_private.clone(),
            dh_ratchet_public: self.dh_ratchet_public.clone(),
            remote_dh_public: self.remote_dh_public.clone(),
            previous_sending_length: self.previous_sending_length,
            skipped_message_keys: self.skipped_message_keys.clone(),
            skipped_key_timestamps: self.skipped_key_timestamps.clone(),
        });

        if needs_ratchet {
            // SkipMessageKeys (Signal DR spec §3.5): save remaining keys from the
            // current receiving chain so out-of-order messages from the old DH epoch
            // can still be decrypted after the ratchet overwrites the chain.
            if let Some(old_remote_dh) = &self.remote_dh_public {
                let old_chain_key_bytes = old_remote_dh.as_ref().to_vec();
                let pn = encrypted.previous_chain_length;
                while self.receiving_chain_length < pn {
                    if self.skipped_message_keys.len()
                        >= crate::config::Config::global().max_skipped_messages as usize
                    {
                        self.restore_snapshot(snapshot);
                        return Err("Too many skipped messages".to_string());
                    }
                    let (msg_key, next_chain) =
                        P::kdf_ck(&self.receiving_chain_key).map_err(|e| {
                            self.restore_snapshot(snapshot.clone());
                            format!("KDF_CK failed: {}", e)
                        })?;
                    let timestamp = crate::utils::time::now();
                    self.skipped_message_keys.insert(
                        (old_chain_key_bytes.clone(), self.receiving_chain_length),
                        msg_key,
                    );
                    self.skipped_key_timestamps.insert(
                        (old_chain_key_bytes.clone(), self.receiving_chain_length),
                        timestamp,
                    );
                    self.receiving_chain_key = next_chain;
                    self.receiving_chain_length = match self.receiving_chain_length.checked_add(1) {
                        Some(v) => v,
                        None => {
                            self.restore_snapshot(snapshot.clone());
                            return Err("receiving_chain_length overflow".to_string());
                        }
                    };
                }
            }
            debug!(target: "crypto::double_ratchet", "Performing DH ratchet");
            self.perform_dh_ratchet(&remote_dh_public)
                .inspect_err(|_e| {
                    self.restore_snapshot(snapshot.clone());
                })?;
        }

        // Try to find skipped message key (keyed by remote DH chain + message number)
        if let Some(key) = self
            .skipped_message_keys
            .remove(&(encrypted.dh_public_key.to_vec(), encrypted.message_number))
        {
            trace!(
                target: "crypto::double_ratchet",
                msg_num = %encrypted.message_number,
                "Found skipped message key"
            );
            return self.decrypt_with_key(&key, encrypted).inspect_err(|_e| {
                self.restore_snapshot(snapshot);
            });
        }

        // Derive keys until we reach the message number
        while self.receiving_chain_length <= encrypted.message_number {
            let (msg_key, next_chain) = P::kdf_ck(&self.receiving_chain_key).map_err(|e| {
                self.restore_snapshot(snapshot.clone());
                format!("KDF_CK failed: {}", e)
            })?;

            if self.receiving_chain_length == encrypted.message_number {
                self.receiving_chain_key = next_chain;
                self.receiving_chain_length = match self.receiving_chain_length.checked_add(1) {
                    Some(v) => v,
                    None => {
                        self.restore_snapshot(snapshot.clone());
                        return Err("receiving_chain_length overflow".to_string());
                    }
                };
                return self
                    .decrypt_with_key(&msg_key, encrypted)
                    .inspect_err(|_e| {
                        self.restore_snapshot(snapshot);
                    });
            } else {
                // Store skipped key keyed by (remote_dh_chain, msg_number)
                // so keys from different DH chains never collide.
                let timestamp = crate::utils::time::now();
                let chain_key = encrypted.dh_public_key.to_vec();

                self.skipped_message_keys
                    .insert((chain_key.clone(), self.receiving_chain_length), msg_key);
                self.skipped_key_timestamps
                    .insert((chain_key, self.receiving_chain_length), timestamp);
                self.receiving_chain_key = next_chain;
                self.receiving_chain_length = match self.receiving_chain_length.checked_add(1) {
                    Some(v) => v,
                    None => {
                        self.restore_snapshot(snapshot.clone());
                        return Err("receiving_chain_length overflow".to_string());
                    }
                };

                // DoS protection: reject if stored skipped key count reaches the configured max.
                if self.skipped_message_keys.len() >= Config::global().max_skipped_messages as usize
                {
                    self.restore_snapshot(snapshot);
                    return Err("Too many skipped messages".to_string());
                }
            }
        }

        self.restore_snapshot(snapshot);
        Err("Message key not found".to_string())
    }

    fn session_id(&self) -> &str {
        &self.session_id
    }

    fn contact_id(&self) -> &str {
        &self.contact_id
    }

    fn cleanup_old_skipped_keys(&mut self, max_age_seconds: i64) {
        use tracing::debug;

        let now = crate::utils::time::now();
        let initial_count = self.skipped_message_keys.len();

        // Collect keys to remove (avoids borrow conflict between two HashMaps)
        let keys_to_remove: Vec<_> = self
            .skipped_message_keys
            .keys()
            .filter(|key| match self.skipped_key_timestamps.get(*key) {
                Some(&ts) => (now as i64 - ts as i64) >= max_age_seconds,
                None => true, // no timestamp → remove
            })
            .cloned()
            .collect();

        for key in &keys_to_remove {
            self.skipped_message_keys.remove(key);
            self.skipped_key_timestamps.remove(key);
        }

        let removed_count = initial_count - self.skipped_message_keys.len();
        if removed_count > 0 {
            debug!(
                target: "crypto::double_ratchet",
                removed = %removed_count,
                remaining = %self.skipped_message_keys.len(),
                "Cleaned up old skipped message keys"
            );
        }
    }

    fn apply_pq_contribution(&mut self, kem_shared_secret: &[u8]) -> Result<(), String> {
        DoubleRatchetSession::apply_pq_contribution(self, kem_shared_secret)
    }

    fn health_snapshot(&self) -> DrHealthSnapshot {
        DoubleRatchetSession::health_snapshot(self)
    }
}

// Internal implementation details
