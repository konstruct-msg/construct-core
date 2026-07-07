// Управление ключами
// Хранение и ротация криптографических ключей

use crate::crypto::CryptoProvider;
use crate::crypto::SuiteID;
use crate::utils::error::{ConstructError, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use std::collections::HashMap;
use std::marker::PhantomData;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// Build prologue for X3DH signature (как в Noise Protocol)
/// Prologue включает протокол и suite ID для предотвращения key substitution attacks
pub fn build_prologue(suite_id: SuiteID) -> Vec<u8> {
    let protocol_name = b"KonstruktX3DH-v1";
    let suite_id_bytes = suite_id.as_u16().to_be_bytes();
    let mut prologue = Vec::with_capacity(protocol_name.len() + suite_id_bytes.len());
    prologue.extend_from_slice(protocol_name);
    prologue.extend_from_slice(&suite_id_bytes);
    prologue
}

/// Пара ключей X25519
#[derive(Clone, Zeroize)]
pub struct X25519KeyPair {
    pub private_key: Zeroizing<[u8; 32]>,
    pub public_key: [u8; 32],
}

impl X25519KeyPair {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let private_key = Zeroizing::new(bytes);
        let arr = *private_key;
        let secret = StaticSecret::from(arr);
        let public_key = PublicKey::from(&secret).to_bytes();
        Self {
            private_key,
            public_key,
        }
    }

    pub fn from_secret(secret: StaticSecret) -> Self {
        let public_key = PublicKey::from(&secret).to_bytes();
        let private_key = Zeroizing::new(secret.to_bytes());
        Self {
            private_key,
            public_key,
        }
    }

    pub fn get_secret(&self) -> StaticSecret {
        let arr = *self.private_key;
        StaticSecret::from(arr)
    }

    pub fn get_public(&self) -> PublicKey {
        PublicKey::from(self.public_key)
    }
}

/// Пара ключей Ed25519 для подписи
#[derive(Clone, Zeroize)]
pub struct Ed25519KeyPair {
    pub private_key: Zeroizing<[u8; 32]>,
    pub public_key: [u8; 32],
}

impl Ed25519KeyPair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        let private_key = Zeroizing::new(signing_key.to_bytes());
        let public_key = verifying_key.to_bytes();
        Self {
            private_key,
            public_key,
        }
    }

    pub fn get_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.private_key)
    }

    pub fn get_verifying_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&self.public_key).map_err(|e| {
            ConstructError::Crypto(crate::error::CryptoError::InvalidInputError(format!(
                "Corrupted Ed25519 public key in keystore: {e}"
            )))
        })
    }
}

/// Хранилище prekey с метаданными
#[derive(Clone)]
pub struct PrekeyStore<P: CryptoProvider> {
    pub key_pair: (P::KemPrivateKey, P::KemPublicKey),
    pub signature: Vec<u8>,
    pub created_at: i64,
    pub key_id: u32,
}

/// Менеджер криптографических ключей
pub struct KeyManager<P: CryptoProvider> {
    /// Identity ключ (долговременный)
    identity_key: Option<(P::KemPrivateKey, P::KemPublicKey)>,

    /// Signing ключ для подписей
    signing_key: Option<(P::SignaturePrivateKey, P::SignaturePublicKey)>,

    /// Текущий signed prekey
    current_signed_prekey: Option<PrekeyStore<P>>,

    /// История старых prekey для обратной совместимости
    old_prekeys: HashMap<u32, PrekeyStore<P>>,

    /// One-time prekeys (OTPKs) — burn-on-use, stored until consumed by incoming X3DH
    one_time_prekeys: HashMap<u32, (P::KemPrivateKey, P::KemPublicKey)>,

    /// Счетчик для key_id signed prekeys
    next_prekey_id: u32,

    /// Счетчик для OTPK key_id (separate range: starts at 1_000_000 to avoid collisions)
    next_otpk_id: u32,

    #[cfg(feature = "post-quantum")]
    /// Independent hybrid PQ signature private key (Ed25519+ML-DSA-65, 2016 bytes raw).
    /// Owned here for centralization: all long-term crypto keys live inside the core.
    /// Lazily initialized on first ensure_hybrid; not part of the main suite signing_key.
    hybrid_sig_priv: Option<Vec<u8>>,

    /// The ML-KEM-768 signed prekey as `(key_id, private, public)` raw bytes — the PQXDH
    /// KEM leg. Plain byte storage (decapsulation happens in the PQXDH layer), kept here
    /// so it persists atomically with the rest of the key-state instead of a separate
    /// platform store that can desync (Phase 2 of key-store consolidation). Not cfg-gated:
    /// no PQ primitives are needed to carry the bytes.
    kyber_spk: Option<(u32, Vec<u8>, Vec<u8>)>,

    _phantom: PhantomData<P>,
}

impl<P: CryptoProvider> KeyManager<P> {
    /// Создать новый KeyManager
    pub fn new() -> Self {
        Self {
            identity_key: None,
            signing_key: None,
            current_signed_prekey: None,
            old_prekeys: HashMap::new(),
            one_time_prekeys: HashMap::new(),
            next_prekey_id: 1,
            next_otpk_id: 1_000_000,
            #[cfg(feature = "post-quantum")]
            hybrid_sig_priv: None,
            kyber_spk: None,
            _phantom: PhantomData,
        }
    }

    /// Инициализировать с новыми ключами
    pub fn initialize(&mut self) -> Result<()> {
        self.identity_key = Some(P::generate_kem_keys().map_err(ConstructError::Crypto)?);
        self.signing_key = Some(P::generate_signature_keys().map_err(ConstructError::Crypto)?);
        self.rotate_signed_prekey()?;
        Ok(())
    }

    /// Инициализировать с существующими ключами (для восстановления из storage)
    pub fn initialize_from_keys(
        &mut self,
        identity_secret_bytes: Vec<u8>,
        signing_secret_bytes: Vec<u8>,
        prekey_secret_bytes: Vec<u8>,
        prekey_signature: Vec<u8>,
    ) -> Result<()> {
        // Создать ключи из байтов
        let identity_secret = P::kem_private_key_from_bytes(identity_secret_bytes);
        let identity_public =
            P::from_private_key_to_public_key(&identity_secret).map_err(ConstructError::Crypto)?;

        let signing_secret = P::signature_private_key_from_bytes(signing_secret_bytes);
        let signing_public =
            P::from_signature_private_to_public(&signing_secret).map_err(ConstructError::Crypto)?;

        let prekey_secret = P::kem_private_key_from_bytes(prekey_secret_bytes);
        let prekey_public =
            P::from_private_key_to_public_key(&prekey_secret).map_err(ConstructError::Crypto)?;

        // Сохранить ключи
        self.identity_key = Some((identity_secret, identity_public));
        self.signing_key = Some((signing_secret, signing_public));
        self.current_signed_prekey = Some(PrekeyStore {
            key_pair: (prekey_secret, prekey_public),
            signature: prekey_signature,
            created_at: 0, // Не важно для восстановленных ключей
            key_id: 1,
        });

        Ok(())
    }

    /// Variant of `initialize_from_keys` that also restores the persisted SPK key id.
    /// Called by `import_private_keys` so that `next_prekey_id` is consistent with
    /// the persisted rotation history.
    pub fn initialize_from_keys_with_id(
        &mut self,
        identity_secret_bytes: Vec<u8>,
        signing_secret_bytes: Vec<u8>,
        prekey_secret_bytes: Vec<u8>,
        prekey_signature: Vec<u8>,
        spk_id: u32,
    ) -> Result<()> {
        self.initialize_from_keys(
            identity_secret_bytes,
            signing_secret_bytes,
            prekey_secret_bytes,
            prekey_signature,
        )?;
        if let Some(ref mut store) = self.current_signed_prekey {
            store.key_id = spk_id;
        }
        // Ensure next_prekey_id is ahead of the current key id.
        if spk_id >= self.next_prekey_id {
            self.next_prekey_id = spk_id + 1;
        }
        Ok(())
    }

    /// Extended restore that also imports optional hybrid sig private key.
    pub fn initialize_from_keys_with_id_and_hybrid(
        &mut self,
        identity_secret_bytes: Vec<u8>,
        signing_secret_bytes: Vec<u8>,
        prekey_secret_bytes: Vec<u8>,
        prekey_signature: Vec<u8>,
        spk_id: u32,
        hybrid_sig_priv: Option<Vec<u8>>,
    ) -> Result<()> {
        self.initialize_from_keys_with_id(
            identity_secret_bytes,
            signing_secret_bytes,
            prekey_secret_bytes,
            prekey_signature,
            spk_id,
        )?;
        if let Some(h) = hybrid_sig_priv {
            self.set_hybrid_signature_private(h)?;
        }
        Ok(())
    }

    /// Получить identity public key
    pub fn identity_public_key(&self) -> Result<&P::KemPublicKey> {
        self.identity_key.as_ref().map(|k| &k.1).ok_or_else(|| {
            ConstructError::Crypto(crate::error::CryptoError::Other(
                "Identity key not initialized".to_string(),
            ))
        })
    }

    /// Получить identity secret key
    pub fn identity_secret_key(&self) -> Result<&P::KemPrivateKey> {
        self.identity_key.as_ref().map(|k| &k.0).ok_or_else(|| {
            ConstructError::Crypto(crate::error::CryptoError::Other(
                "Identity key not initialized".to_string(),
            ))
        })
    }

    /// Получить verifying key
    pub fn verifying_key(&self) -> Result<&P::SignaturePublicKey> {
        self.signing_key.as_ref().map(|k| &k.1).ok_or_else(|| {
            ConstructError::Crypto(crate::error::CryptoError::Other(
                "Signing key not initialized".to_string(),
            ))
        })
    }

    /// Получить текущий signed prekey
    pub fn current_signed_prekey(&self) -> Result<&PrekeyStore<P>> {
        self.current_signed_prekey.as_ref().ok_or_else(|| {
            ConstructError::Crypto(crate::error::CryptoError::Other(
                "No signed prekey available".to_string(),
            ))
        })
    }

    /// Return the current signed pre-key ID, or None if not initialized.
    pub fn current_signed_prekey_id(&self) -> Option<u32> {
        self.current_signed_prekey.as_ref().map(|s| s.key_id)
    }

    /// Ротация signed prekey
    pub fn rotate_signed_prekey(&mut self) -> Result<()> {
        let (signing_key, _) = self.signing_key.as_ref().ok_or_else(|| {
            ConstructError::Crypto(crate::error::CryptoError::Other(
                "Signing key not initialized".to_string(),
            ))
        })?;

        // Генерируем новый prekey
        let key_pair = P::generate_kem_keys().map_err(ConstructError::Crypto)?;

        // Подписываем signed prekey с prologue (как в Noise Protocol)
        // Prologue включает протокол и suite ID для предотвращения key substitution attacks
        let suite_id = SuiteID::from_u16_unchecked(P::suite_id()); // Provider гарантирует валидный suite_id
        let prologue = build_prologue(suite_id);
        let mut message_to_sign = Vec::with_capacity(prologue.len() + key_pair.1.as_ref().len());
        message_to_sign.extend_from_slice(&prologue);
        message_to_sign.extend_from_slice(key_pair.1.as_ref());
        let signature = P::sign(signing_key, &message_to_sign).map_err(ConstructError::Crypto)?;

        let key_id = self.next_prekey_id;
        self.next_prekey_id += 1;

        let prekey_store = PrekeyStore {
            key_pair,
            signature,
            created_at: crate::utils::time::current_timestamp(),
            key_id,
        };

        // Сохраняем старый prekey в историю
        if let Some(old_prekey) = self.current_signed_prekey.take() {
            self.old_prekeys.insert(old_prekey.key_id, old_prekey);
        }

        self.current_signed_prekey = Some(prekey_store);

        // Очищаем старые prekeys (используя конфигурируемый период)
        self.cleanup_old_prekeys(crate::config::Config::global().prekey_cleanup_period_secs);

        Ok(())
    }

    /// Получить prekey по ID
    pub fn get_prekey(&self, key_id: u32) -> Option<&PrekeyStore<P>> {
        if let Some(current) = &self.current_signed_prekey
            && current.key_id == key_id
        {
            return Some(current);
        }
        self.old_prekeys.get(&key_id)
    }

    /// Очистка старых prekeys
    fn cleanup_old_prekeys(&mut self, max_age_seconds: i64) {
        let now = crate::utils::time::current_timestamp();
        self.old_prekeys
            .retain(|_, prekey| now - prekey.created_at < max_age_seconds);
    }

    /// Экспорт регистрационного bundle
    ///
    /// TODO(ARCHITECTURE): Этот метод возвращает конкретный тип X3DHPublicKeyBundle
    /// См. полное описание: packages/core/ARCHITECTURE_TODOS.md
    ///
    /// ПРОБЛЕМА:
    /// - KeyManager<P> generic только по CryptoProvider
    /// - Не знает о handshake protocol (X3DH, PQ-X3DH, etc.)
    /// - Поэтому возвращает конкретный тип X3DHPublicKeyBundle
    /// - Это создаёт несоответствие с Client<P, H, M> где H - generic handshake protocol
    ///
    /// ПОСЛЕДСТВИЯ:
    /// - Client::get_registration_bundle() не может использовать этот метод
    /// - Потому что возвращаемые типы не совпадают:
    ///   - Этот метод: X3DHPublicKeyBundle (конкретный)
    ///   - Client метод: H::RegistrationBundle (generic)
    /// - Приходится обходить Client и вызывать этот метод напрямую
    ///
    /// ПРАВИЛЬНОЕ РЕШЕНИЕ:
    /// Сделать KeyManager generic по handshake protocol:
    /// ```rust,ignore
    /// pub struct KeyManager<P: CryptoProvider, H: KeyAgreement<P>> {
    ///     // ...
    /// }
    ///
    /// impl<P: CryptoProvider, H: KeyAgreement<P>> KeyManager<P, H> {
    ///     pub fn export_registration_bundle(&self) -> Result<H::RegistrationBundle> {
    ///         // Делегировать создание bundle протоколу handshake
    ///         H::export_from_key_manager(self)
    ///     }
    /// }
    /// ```
    ///
    /// Это потребует:
    /// 1. Добавить в trait KeyAgreement метод export_from_key_manager()
    /// 2. Обновить KeyManager<P> -> KeyManager<P, H>
    /// 3. Обновить все места использования KeyManager
    ///
    /// Смотрите также:
    /// - client_api.rs:137-161 - проблема в Client::get_registration_bundle()
    /// - uniffi_bindings.rs:93-118 - workaround и полное описание решений
    pub fn export_registration_bundle(
        &self,
    ) -> Result<crate::crypto::handshake::x3dh::X3DHPublicKeyBundle> {
        let identity_public = self.identity_public_key()?.as_ref().to_vec();
        let verifying_key = self.verifying_key()?.as_ref().to_vec();
        let prekey = self.current_signed_prekey()?;

        Ok(crate::crypto::handshake::x3dh::X3DHPublicKeyBundle {
            identity_public,
            signed_prekey_public: prekey.key_pair.1.as_ref().to_vec(),
            signature: prekey.signature.clone(),
            verifying_key,
            suite_id: SuiteID::from_u16_unchecked(P::suite_id()), // Provider гарантирует валидный suite_id
            one_time_prekey_public: None,
            one_time_prekey_id: None,
            spk_uploaded_at: 0,
            spk_rotation_epoch: 0,
            kyber_spk_uploaded_at: 0,
            kyber_spk_rotation_epoch: 0,
            supports_pq_ratchet: false,
        })
    }

    /// Экспорт публичного key bundle
    pub fn export_public_bundle(
        &self,
    ) -> Result<crate::crypto::handshake::x3dh::X3DHPublicKeyBundle> {
        let identity_public = self.identity_public_key()?.as_ref().to_vec();
        let verifying_key = self.verifying_key()?.as_ref().to_vec();
        let prekey = self.current_signed_prekey()?;

        Ok(crate::crypto::handshake::x3dh::X3DHPublicKeyBundle {
            identity_public,
            signed_prekey_public: prekey.key_pair.1.as_ref().to_vec(),
            signature: prekey.signature.clone(),
            verifying_key,
            suite_id: SuiteID::from_u16_unchecked(P::suite_id()), // Provider гарантирует валидный suite_id
            one_time_prekey_public: None,
            one_time_prekey_id: None,
            spk_uploaded_at: 0,
            spk_rotation_epoch: 0,
            kyber_spk_uploaded_at: 0,
            kyber_spk_rotation_epoch: 0,
            supports_pq_ratchet: false,
        })
    }

    /// Экспорт device registration bundle для device-based регистрации
    ///
    /// Возвращает X3DHRegistrationBundle, содержащий ТОЛЬКО публичные данные
    /// для безопасного обмена ключами между устройствами.
    ///
    /// # Безопасность
    ///
    /// Этот метод гарантирует, что:
    /// - Возвращаются только публичные ключи
    /// - Приватные ключи никогда не покидают KeyManager
    /// - Bundle можно безопасно отправлять по сети
    pub fn export_device_registration_bundle(
        &self,
    ) -> Result<crate::crypto::handshake::x3dh::X3DHRegistrationBundle> {
        let identity_public = self.identity_public_key()?.as_ref().to_vec();
        let verifying_key = self.verifying_key()?.as_ref().to_vec();
        let prekey = self.current_signed_prekey()?;

        Ok(crate::crypto::handshake::x3dh::X3DHRegistrationBundle {
            identity_public,
            signed_prekey_public: prekey.key_pair.1.as_ref().to_vec(),
            signature: prekey.signature.clone(),
            verifying_key,
            suite_id: SuiteID::from_u16_unchecked(P::suite_id()),
        })
    }

    /// Подписать данные
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let (signing_key, _) = self.signing_key.as_ref().ok_or_else(|| {
            ConstructError::Crypto(crate::error::CryptoError::Other(
                "Signing key not initialized".to_string(),
            ))
        })?;

        P::sign(signing_key, data).map_err(ConstructError::Crypto)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Hybrid PQ signature key (Ed25519 + ML-DSA-65) — centralized ownership
    // The key is independent of the main (classic) signing_key. It is lazily
    // created on first use and persisted as part of CFE private keys.
    // All hybrid signing now goes through the core (no external keychain blobs).
    // Gated behind post-quantum feature (same as the hybrid module).
    // ─────────────────────────────────────────────────────────────────────────

    /// Domain separation for X3DH pre-key signatures (both classic Ed25519 and hybrid).
    /// Must stay byte-identical to Swift `x3dhPrologue` and server.
    pub const X3DH_SIGN_PROLOGUE: &'static [u8] = b"KonstruktX3DH-v1";

    /// Domain separation for binding the hybrid identity key to the classic device Ed25519 identity.
    /// Must stay byte-identical to Swift `bindPrologue` / server `HYBRID_ID_BIND_PROLOGUE`.
    pub const HYBRID_ID_BIND_PROLOGUE: &'static [u8] = b"KonstruktHybridId-v1";

    /// Build the canonical message that is signed (classically or with hybrid key)
    /// over a pre-key (SPK or Kyber SPK).
    ///
    /// Format: PROLOGUE || [0x00, suite_id] || public_key_bytes
    pub fn build_x3dh_sign_message(suite_id: u8, public_key: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(Self::X3DH_SIGN_PROLOGUE.len() + 2 + public_key.len());
        msg.extend_from_slice(Self::X3DH_SIGN_PROLOGUE);
        msg.push(0x00);
        msg.push(suite_id);
        msg.extend_from_slice(public_key);
        msg
    }

    /// Build the message for the cross-signature that binds a freshly generated
    /// hybrid identity public key to the device's classic Ed25519 identity.
    ///
    /// Format: PROLOGUE || hybrid_public_key
    pub fn build_hybrid_identity_bind_message(hybrid_public: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(Self::HYBRID_ID_BIND_PROLOGUE.len() + hybrid_public.len());
        msg.extend_from_slice(Self::HYBRID_ID_BIND_PROLOGUE);
        msg.extend_from_slice(hybrid_public);
        msg
    }

    #[cfg(feature = "post-quantum")]
    /// Ensure a hybrid signature keypair exists. If absent, generate using the
    /// fixed hybrid suite (same as the free hybridSignatureKeygen primitive) and
    /// store. Returns the public key (1984 B).
    pub fn ensure_hybrid_signature_key(&mut self) -> Result<Vec<u8>> {
        if self.hybrid_sig_priv.is_none() {
            // Use the same generation as the stateless hybrid provider.
            let (priv_key, pub_key) =
                crate::crypto::suites::hybrid::HybridSuiteProvider::generate_signature_keys()
                    .map_err(ConstructError::Crypto)?;
            self.hybrid_sig_priv = Some(priv_key);
            return Ok(pub_key);
        }
        // Derive pub from stored priv (embedded pk or re-derive).
        let priv_key = self.hybrid_sig_priv.as_ref().unwrap();
        crate::crypto::suites::hybrid::HybridSuiteProvider::from_signature_private_to_public(
            priv_key,
        )
        .map_err(ConstructError::Crypto)
    }

    #[cfg(feature = "post-quantum")]
    /// Return the hybrid public key if one has been ensured/generated, else None.
    pub fn hybrid_signature_public_key(&self) -> Option<Vec<u8>> {
        self.hybrid_sig_priv.as_ref().and_then(|p| {
            crate::crypto::suites::hybrid::HybridSuiteProvider::from_signature_private_to_public(p).ok()
        })
    }

    #[cfg(feature = "post-quantum")]
    /// Sign with the hybrid key (if present). Returns 3373 B hybrid signature.
    /// The caller must have called ensure first (or this returns error).
    pub fn sign_hybrid(&self, message: &[u8]) -> Result<Vec<u8>> {
        let priv_key = self.hybrid_sig_priv.as_ref().ok_or_else(|| {
            ConstructError::Crypto(crate::error::CryptoError::Other(
                "Hybrid signature key not initialized (call ensure first)".to_string(),
            ))
        })?;
        crate::crypto::suites::hybrid::HybridSuiteProvider::sign(priv_key, message)
            .map_err(ConstructError::Crypto)
    }

    #[cfg(feature = "post-quantum")]
    /// Ensure the hybrid key (if needed) and return a hybrid signature over the
    /// standard X3DH prekey sign-message for the given suite and public key.
    ///
    /// This centralizes both key ownership and message construction.
    pub fn sign_hybrid_prekey(&mut self, suite_id: u8, public_key: &[u8]) -> Result<Vec<u8>> {
        let _ = self.ensure_hybrid_signature_key()?;
        let msg = Self::build_x3dh_sign_message(suite_id, public_key);
        self.sign_hybrid(&msg)
    }

    #[cfg(feature = "post-quantum")]
    /// Import a previously generated hybrid sig private key (from CFE restore).
    pub fn set_hybrid_signature_private(&mut self, priv_bytes: Vec<u8>) -> Result<()> {
        // Validate size early.
        if priv_bytes.len() != crate::crypto::suites::hybrid::HYBRID_SIG_SECRET_KEY_SIZE {
            return Err(ConstructError::Crypto(
                crate::error::CryptoError::InvalidInputError(format!(
                    "hybrid sig priv size {} != {}",
                    priv_bytes.len(),
                    crate::crypto::suites::hybrid::HYBRID_SIG_SECRET_KEY_SIZE
                )),
            ));
        }
        self.hybrid_sig_priv = Some(priv_bytes);
        Ok(())
    }

    #[cfg(feature = "post-quantum")]
    /// Export the hybrid sig private (if any) for CFE persistence.
    pub fn hybrid_signature_private_bytes(&self) -> Option<Vec<u8>> {
        self.hybrid_sig_priv.clone()
    }

    /// Store the ML-KEM-768 signed prekey `(key_id, private, public)` in the key-state.
    /// Commit-after-confirm is the caller's contract: only call once the server has
    /// confirmed the matching public key upload.
    pub fn set_kyber_spk(&mut self, key_id: u32, private_key: Vec<u8>, public_key: Vec<u8>) {
        self.kyber_spk = Some((key_id, private_key, public_key));
    }

    /// The stored ML-KEM-768 signed prekey as `(key_id, private, public)`, if any.
    pub fn kyber_spk_bytes(&self) -> Option<(u32, Vec<u8>, Vec<u8>)> {
        self.kyber_spk.clone()
    }

    // Non-pq stubs (no-op / None) so call sites in export/import don't need per-cfg.
    #[cfg(not(feature = "post-quantum"))]
    pub fn ensure_hybrid_signature_key(&mut self) -> Result<Vec<u8>> {
        Err(ConstructError::Crypto(crate::error::CryptoError::Other(
            "hybrid signatures require post-quantum feature".into(),
        )))
    }
    #[cfg(not(feature = "post-quantum"))]
    pub fn hybrid_signature_public_key(&self) -> Option<Vec<u8>> {
        None
    }
    #[cfg(not(feature = "post-quantum"))]
    pub fn sign_hybrid(&self, _message: &[u8]) -> Result<Vec<u8>> {
        Err(ConstructError::Crypto(crate::error::CryptoError::Other(
            "hybrid signatures require post-quantum feature".into(),
        )))
    }
    #[cfg(not(feature = "post-quantum"))]
    pub fn sign_hybrid_prekey(&mut self, _suite_id: u8, _public_key: &[u8]) -> Result<Vec<u8>> {
        Err(ConstructError::Crypto(crate::error::CryptoError::Other(
            "hybrid signatures require post-quantum feature".into(),
        )))
    }
    #[cfg(not(feature = "post-quantum"))]
    pub fn set_hybrid_signature_private(&mut self, _priv_bytes: Vec<u8>) -> Result<()> {
        Ok(())
    }
    #[cfg(not(feature = "post-quantum"))]
    pub fn hybrid_signature_private_bytes(&self) -> Option<Vec<u8>> {
        None
    }

    /// Количество сохраненных старых prekeys
    pub fn old_prekeys_count(&self) -> usize {
        self.old_prekeys.len()
    }

    /// Iterate over old prekeys for serialization.
    pub fn old_prekeys_iter(&self) -> impl Iterator<Item = &PrekeyStore<P>> {
        self.old_prekeys.values()
    }

    /// Restore a previously serialized old prekey (called during `import_private_keys`).
    ///
    /// Skips entries older than `max_age_seconds` to mirror the in-memory cleanup logic.
    pub fn add_old_prekey(
        &mut self,
        spk_priv_bytes: Vec<u8>,
        spk_sig: Vec<u8>,
        key_id: u32,
        created_at: i64,
    ) -> Result<()> {
        let max_age = crate::config::Config::global().prekey_cleanup_period_secs;
        let now = crate::utils::time::current_timestamp();
        if now - created_at >= max_age {
            return Ok(());
        }
        let secret = P::kem_private_key_from_bytes(spk_priv_bytes);
        let public = P::from_private_key_to_public_key(&secret).map_err(ConstructError::Crypto)?;
        self.old_prekeys.insert(
            key_id,
            PrekeyStore {
                key_pair: (secret, public),
                signature: spk_sig,
                created_at,
                key_id,
            },
        );
        // Advance next_prekey_id so future rotations don't reuse an old id.
        if key_id >= self.next_prekey_id {
            self.next_prekey_id = key_id + 1;
        }
        Ok(())
    }

    // ============================================================================
    // One-Time Prekeys (OTPKs)
    // ============================================================================

    /// Generate `count` new one-time prekeys, store private keys, return (key_id, public_key_bytes) pairs.
    /// Caller uploads the public keys to the server via UploadPreKeys.
    pub fn generate_one_time_prekeys(&mut self, count: u32) -> Result<Vec<(u32, Vec<u8>)>> {
        let mut result = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (private_key, public_key) =
                P::generate_kem_keys().map_err(ConstructError::Crypto)?;
            let key_id = self.next_otpk_id;
            self.next_otpk_id = self.next_otpk_id.wrapping_add(1);
            let public_bytes = public_key.as_ref().to_vec();
            self.one_time_prekeys
                .insert(key_id, (private_key, public_key));
            result.push((key_id, public_bytes));
        }
        Ok(result)
    }

    /// Consume (burn) a one-time prekey by key_id. Returns the private key if found.
    /// The key is removed from storage — it cannot be reused.
    pub fn consume_one_time_prekey(&mut self, key_id: u32) -> Option<P::KemPrivateKey> {
        self.one_time_prekeys
            .remove(&key_id)
            .map(|(private, _)| private)
    }

    /// How many OTPKs are currently stored locally (not yet consumed).
    pub fn one_time_prekey_count(&self) -> usize {
        self.one_time_prekeys.len()
    }

    pub fn next_otpk_id(&self) -> u32 {
        self.next_otpk_id
    }

    /// Restore/override the OTPK counter from persisted state.
    ///
    /// Never decreases the counter to avoid collisions.
    pub fn set_next_otpk_id(&mut self, next_id: u32) {
        if next_id > self.next_otpk_id {
            self.next_otpk_id = next_id;
        }
    }

    /// Export all stored OTPK (key_id, private_bytes, public_bytes) for persistence.
    pub fn export_one_time_prekeys(&self) -> Vec<(u32, Vec<u8>, Vec<u8>)> {
        self.one_time_prekeys
            .iter()
            .map(|(&id, (priv_key, pub_key))| {
                (id, priv_key.as_ref().to_vec(), pub_key.as_ref().to_vec())
            })
            .collect()
    }

    /// Import previously exported OTPKs back into the store (used after core restore).
    /// Also restores next_otpk_id to avoid collisions with persisted keys.
    /// Verifies each key pair: re-derives public from private and compares. Keys that
    /// fail the check are silently dropped to prevent permanently broken sessions.
    pub fn import_one_time_prekeys(&mut self, keys: Vec<(u32, Vec<u8>, Vec<u8>)>) {
        for (key_id, priv_bytes, pub_bytes) in keys {
            // Integrity check: re-derive pub from priv and compare.
            let priv_key = P::kem_private_key_from_bytes(priv_bytes.clone());
            match P::from_private_key_to_public_key(&priv_key) {
                Ok(derived_pub) if derived_pub.as_ref() == pub_bytes.as_slice() => {
                    let public_key = P::kem_public_key_from_bytes(pub_bytes);
                    self.one_time_prekeys.insert(key_id, (priv_key, public_key));
                    if key_id >= self.next_otpk_id {
                        self.next_otpk_id = key_id.wrapping_add(1);
                    }
                }
                Ok(_) => {
                    tracing::error!(
                        target: "crypto::keys",
                        key_id = %key_id,
                        "OTPK integrity check FAILED: derived public key does not match stored — dropping key"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        target: "crypto::keys",
                        key_id = %key_id,
                        error = %e,
                        "OTPK integrity check FAILED: cannot derive public key from private — dropping key"
                    );
                }
            }
        }
    }

    /// Remove all stored OTPKs with `key_id < min_keep_id`; returns how many were pruned.
    ///
    /// Convergence point after a replace-all upload: the server set is then exactly
    /// the batch just uploaded, so no *future* bundle fetch can reference an older key.
    /// The caller keeps a small ID window below the batch for first messages already
    /// in flight; everything older is dead weight that only grows the persisted blob.
    /// Never touches `next_otpk_id` — IDs stay monotonic.
    pub fn prune_one_time_prekeys_below(&mut self, min_keep_id: u32) -> usize {
        let before = self.one_time_prekeys.len();
        self.one_time_prekeys.retain(|&id, _| id >= min_keep_id);
        before - self.one_time_prekeys.len()
    }

    /// Iterate over all prekey private keys: current first, then old ones.
    ///
    /// Used by `init_receiving_session_with_ephemeral` to try all available
    /// prekeys when the current one fails (e.g. sender used a prekey from
    /// before a rotation).
    pub fn all_prekey_private_keys(&self) -> Vec<P::KemPrivateKey> {
        let mut keys = Vec::with_capacity(1 + self.old_prekeys.len());
        if let Some(current) = &self.current_signed_prekey {
            keys.push(current.key_pair.0.clone());
        }
        // Sort old prekeys newest-first (highest key_id = most recent rotation)
        let mut old: Vec<_> = self.old_prekeys.values().collect();
        old.sort_by_key(|p| std::cmp::Reverse(p.key_id));
        for prekey in old {
            keys.push(prekey.key_pair.0.clone());
        }
        keys
    }

    /// Получить signing key для экспорта
    pub fn signing_secret_key(&self) -> Result<&P::SignaturePrivateKey> {
        self.signing_key.as_ref().map(|k| &k.0).ok_or_else(|| {
            ConstructError::Crypto(crate::error::CryptoError::Other(
                "Signing key not initialized".to_string(),
            ))
        })
    }

    /// Raw bytes of the Ed25519 signing secret key.
    pub fn signing_secret_key_bytes(&self) -> Result<Vec<u8>> {
        let key = self.signing_secret_key()?;
        Ok(<_ as AsRef<[u8]>>::as_ref(key).to_vec())
    }

    /// Raw bytes of the X25519 identity secret key.
    pub fn identity_secret_key_bytes(&self) -> Result<Vec<u8>> {
        let key = self.identity_secret_key()?;
        Ok(<_ as AsRef<[u8]>>::as_ref(key).to_vec())
    }
}

impl<P: CryptoProvider> Default for KeyManager<P> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_keypair_zeroize() {
        let mut pair = X25519KeyPair::generate();
        let original_secret = *pair.private_key;
        pair.zeroize();
        let zeroed_secret = *pair.private_key;
        assert_ne!(original_secret, zeroed_secret);
        assert!(zeroed_secret.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_ed25519_keypair_zeroize() {
        let mut pair = Ed25519KeyPair::generate();
        let original_secret = *pair.private_key;
        pair.zeroize();
        let zeroed_secret = *pair.private_key;
        assert_ne!(original_secret, zeroed_secret);
        assert!(zeroed_secret.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_prune_one_time_prekeys_below() {
        use crate::crypto::suites::classic::ClassicSuiteProvider;
        let mut km: KeyManager<ClassicSuiteProvider> = KeyManager::new();
        let pairs = km.generate_one_time_prekeys(10).unwrap();
        assert_eq!(km.one_time_prekey_count(), 10);
        let cutoff = pairs[7].0; // keep the last 3

        let pruned = km.prune_one_time_prekeys_below(cutoff);
        assert_eq!(pruned, 7);
        assert_eq!(km.one_time_prekey_count(), 3);
        // Retained keys are exactly the ones at/above the cutoff, still consumable.
        for (id, _) in &pairs[7..] {
            assert!(km.consume_one_time_prekey(*id).is_some());
        }
        for (id, _) in &pairs[..7] {
            assert!(km.consume_one_time_prekey(*id).is_none());
        }
        // The ID counter is untouched — pruning must never enable ID reuse.
        let next = km.next_otpk_id();
        assert_eq!(next, pairs[9].0 + 1);

        // Pruning everything (cutoff above all IDs) empties the store.
        km.generate_one_time_prekeys(2).unwrap();
        assert_eq!(km.prune_one_time_prekeys_below(u32::MAX), 2);
        assert_eq!(km.one_time_prekey_count(), 0);
        assert_eq!(km.next_otpk_id(), next + 2);
    }
}
