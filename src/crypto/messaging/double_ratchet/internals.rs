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
            is_pq_strengthened: self.pre_pq_root_key.is_none(),
            last_ratchet_at: self.last_ratchet_at,
            session_id: self.session_id.clone(),
        }
    }

    /// Mix a post-quantum KEM shared secret into the session root key (PQXDH contribution).
    ///
    /// Both sender and receiver call this after `init_session`/`init_receiving_session`
    /// with their respective KEM shared secret. The resulting root key is derived from
    /// BOTH the classical X3DH and ML-KEM-768, providing HNDL (Harvest Now Decrypt Later)
    /// protection: an attacker must break BOTH X25519 AND ML-KEM-768 to read messages.
    ///
    /// Derivation: `new_root_key = HKDF(salt=current_root_key, ikm=kem_ss, info="construct-pqxdh-v1")`
    pub fn apply_pq_contribution(&mut self, kem_shared_secret: &[u8]) -> Result<(), String> {
        match self.pre_pq_root_key.take() {
            Some(saved_rk1) => {
                // RESPONDER path: apply PQ to the saved RK1 (after 1st ratchet, before 2nd).
                // The INITIATOR also applies PQ to RK1, so both sides derive the same PQ root key.
                // After PQ-enhancing RK1, we must re-derive the second ratchet (sending chain)
                // so that our sending_chain_key matches what the INITIATOR will compute when
                // they perform a DH ratchet to receive our reply.
                let rk1_bytes = saved_rk1.as_ref().to_vec();
                let pq_rk1_bytes =
                    P::hkdf_derive_key(&rk1_bytes, kem_shared_secret, b"construct-pqxdh-v1", 32)
                        .map_err(|e| format!("PQ contribution HKDF failed: {:?}", e))?;
                let pq_rk1 = Self::bytes_to_aead_key(&pq_rk1_bytes)?;

                // Re-derive the second ratchet: KDF_RK(PQ_RK1, DH(our_priv, remote_pub))
                let dh_priv = self
                    .dh_ratchet_private
                    .as_ref()
                    .ok_or("Missing DH ratchet private key during PQ re-derive")?;
                let remote_pub = self
                    .remote_dh_public
                    .as_ref()
                    .ok_or("Missing remote DH public key during PQ re-derive")?;
                let dh_output = P::kem_decapsulate(dh_priv, remote_pub.as_ref())
                    .map_err(|e| format!("DH failed during PQ re-derive: {}", e))?;
                let (new_root_key, new_sending_chain) = P::kdf_rk(&pq_rk1, &dh_output)
                    .map_err(|e| format!("KDF_RK re-derive failed: {}", e))?;

                self.root_key = new_root_key;
                self.sending_chain_key = new_sending_chain;
            }
            _ => {
                // INITIATOR path: root_key is already RK1, apply PQ directly.
                let current_root = self.root_key.as_ref().to_vec();
                let new_root_bytes =
                    P::hkdf_derive_key(&current_root, kem_shared_secret, b"construct-pqxdh-v1", 32)
                        .map_err(|e| format!("PQ contribution HKDF failed: {:?}", e))?;
                self.root_key = Self::bytes_to_aead_key(&new_root_bytes)?;
            }
        }
        Ok(())
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
    pub(super) fn perform_dh_ratchet(
        &mut self,
        new_remote_dh: &P::KemPublicKey,
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

        debug!(
            target: "crypto::double_ratchet",
            "DH ratchet step completed"
        );

        Ok(())
    }

    /// Расшифровать с заданным message key
    pub(super) fn decrypt_with_key(
        &self,
        message_key: &P::AeadKey,
        encrypted: &EncryptedRatchetMessage,
    ) -> Result<Vec<u8>, String> {
        use tracing::{debug, trace};

        trace!(
            target: "crypto::double_ratchet",
            msg_num = %encrypted.message_number,
            nonce_len = %encrypted.nonce.len(),
            ciphertext_len = %encrypted.ciphertext.len(),
            "Decrypting with message key"
        );

        // Reconstruct Associated Data v2: must mirror encrypt() exactly.
        // Decrypt uses contact_id as sender (= local_user_id on encrypt side) and vice versa.
        let session_id_bytes: Vec<u8> = hex::decode(&self.session_id).map_err(|_| {
            format!(
                "AEAD decrypt: session_id '{}' is not valid hex — session may be corrupt; \
                 re-initialise the session",
                &self.session_id
            )
        })?;
        let mut associated_data =
            Vec::with_capacity(1 + self.contact_id.len() + self.local_user_id.len() + 16 + 32 + 4);
        associated_data.push(AD_VERSION); // AD version (see const AD_VERSION)
        associated_data.extend_from_slice(self.contact_id.as_bytes());
        associated_data.extend_from_slice(self.local_user_id.as_bytes());
        associated_data.extend_from_slice(&session_id_bytes);
        associated_data.extend_from_slice(&encrypted.dh_public_key);
        associated_data.extend_from_slice(&encrypted.message_number.to_be_bytes());

        tracing::info!(
            target: "crypto::double_ratchet",
            local_user_id = %self.local_user_id,
            contact_id = %self.contact_id,
            session_id = %self.session_id,
            msg_num = %encrypted.message_number,
            dh_pub_prefix = %hex::encode(&encrypted.dh_public_key[..4.min(encrypted.dh_public_key.len())]),
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
            // Privacy-safe diagnostic: log field lengths, not values.
            // A local_user_id/contact_id format mismatch (e.g. 32-char device-hash
            // vs 36-char server UUID) shows up immediately as an AD length difference.
            tracing::error!(
                target: "crypto::double_ratchet",
                local_user_id_len = %self.local_user_id.len(),
                contact_id_len = %self.contact_id.len(),
                ad_total_len = %associated_data.len(),
                msg_num = %encrypted.message_number,
                "AEAD decryption failed — check that local_user_id and contact_id \
                 are both server UUIDs (36 chars); a 32-char device-hash on either \
                 side will produce a permanent AD mismatch"
            );
            format!("Decryption failed: {}", e)
        })?;

        debug!(target: "crypto::double_ratchet", "Decryption successful");

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
