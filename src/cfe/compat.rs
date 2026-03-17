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

// ============================================================================
// Legacy JSON → CFE migrations (v1 payload schemas)
// ============================================================================

pub fn migrate_private_keys_json_str(
    legacy_json: &str,
) -> Result<crate::cfe::CfePrivateKeysV1, CfeError> {
    use crate::crypto::provider::CryptoProvider;
    use crate::crypto::suites::classic::ClassicSuiteProvider;
    use base64::Engine as _;
    use serde::Deserialize;
    use serde_bytes::ByteBuf;

    #[derive(Debug, Deserialize)]
    struct LegacyPrivateKeysJson {
        identity_secret: String,
        signing_secret: String,
        signed_prekey_secret: String,
        prekey_signature: String,
        suite_id: String,
    }

    let legacy: LegacyPrivateKeysJson = serde_json::from_str(legacy_json)
        .map_err(|e| CfeError::LegacyJsonParseFailed(e.to_string()))?;

    let suite_id_u8: u8 = legacy
        .suite_id
        .parse::<u16>()
        .map_err(|e| CfeError::InvalidField(format!("suite_id parse failed: {e}")))?
        .try_into()
        .map_err(|_| CfeError::InvalidField("suite_id out of range".to_string()))?;

    let decode_b64 = |s: &str| -> Result<Vec<u8>, CfeError> {
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| CfeError::Base64DecodeFailed(e.to_string()))
    };

    let ik_priv = decode_b64(&legacy.identity_secret)?;
    let sk_priv = decode_b64(&legacy.signing_secret)?;
    let spk_priv = decode_b64(&legacy.signed_prekey_secret)?;
    let spk_sig = decode_b64(&legacy.prekey_signature)?;

    let ik_pub = ClassicSuiteProvider::from_private_key_to_public_key(&ik_priv)
        .map_err(|e| CfeError::KeyDerivationFailed(e.to_string()))?;
    let vk_pub = ClassicSuiteProvider::from_signature_private_to_public(&sk_priv)
        .map_err(|e| CfeError::KeyDerivationFailed(e.to_string()))?;
    let spk_pub = ClassicSuiteProvider::from_private_key_to_public_key(&spk_priv)
        .map_err(|e| CfeError::KeyDerivationFailed(e.to_string()))?;

    Ok(crate::cfe::CfePrivateKeysV1 {
        suite_id: suite_id_u8,
        ik_priv: ByteBuf::from(ik_priv),
        sk_priv: ByteBuf::from(sk_priv),
        spk_priv: ByteBuf::from(spk_priv),
        spk_sig: ByteBuf::from(spk_sig),
        spk_id: 0, // legacy JSON doesn't carry SPK id
        ik_pub: ByteBuf::from(ik_pub),
        vk_pub: ByteBuf::from(vk_pub),
        spk_pub: ByteBuf::from(spk_pub),
    })
}

pub fn migrate_session_json_str(
    legacy_json: &str,
) -> Result<crate::cfe::CfeSessionStateV1, CfeError> {
    use crate::crypto::messaging::double_ratchet::SerializableSession;

    let legacy: SerializableSession = serde_json::from_str(legacy_json)
        .map_err(|e| CfeError::LegacyJsonParseFailed(e.to_string()))?;
    legacy.to_cfe_v1().map_err(CfeError::InvalidField)
}

pub fn migrate_otpk_bundle_json_str(
    legacy_json: &str,
) -> Result<crate::cfe::CfeOtpkBundleV1, CfeError> {
    use serde::Deserialize;
    use serde_bytes::ByteBuf;

    #[derive(Debug, Deserialize)]
    struct LegacyOtpkRecord {
        key_id: u32,
        private_key: Vec<u8>,
        public_key: Vec<u8>,
    }

    let legacy_records: Vec<LegacyOtpkRecord> = serde_json::from_str(legacy_json)
        .map_err(|e| CfeError::LegacyJsonParseFailed(e.to_string()))?;

    let next_id = legacy_records
        .iter()
        .map(|r| r.key_id)
        .max()
        .map(|m| m.wrapping_add(1))
        .unwrap_or(1_000_000);

    let records = legacy_records
        .into_iter()
        .map(|r| crate::cfe::CfeOtpkRecordV1 {
            id: r.key_id,
            priv_key: ByteBuf::from(r.private_key),
            pub_key: ByteBuf::from(r.public_key),
        })
        .collect();

    Ok(crate::cfe::CfeOtpkBundleV1 { records, next_id })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::client_api::Client;
    use crate::crypto::handshake::x3dh::X3DHProtocol;
    use crate::crypto::messaging::double_ratchet::DoubleRatchetSession;
    use crate::crypto::provider::CryptoProvider;
    use crate::crypto::suites::classic::ClassicSuiteProvider;

    #[test]
    fn migrate_private_keys_json_derives_public_checks() {
        use base64::Engine as _;

        let (ik_priv, ik_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();
        let (spk_priv, spk_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();
        let (sk_priv, vk_pub) = ClassicSuiteProvider::generate_signature_keys().unwrap();
        let spk_sig = vec![7u8; 64];

        let legacy = serde_json::json!({
            "identity_secret": base64::engine::general_purpose::STANDARD.encode(&ik_priv),
            "signing_secret": base64::engine::general_purpose::STANDARD.encode(&sk_priv),
            "signed_prekey_secret": base64::engine::general_purpose::STANDARD.encode(&spk_priv),
            "prekey_signature": base64::engine::general_purpose::STANDARD.encode(&spk_sig),
            "suite_id": "1"
        })
        .to_string();

        let migrated = migrate_private_keys_json_str(&legacy).unwrap();
        assert_eq!(migrated.suite_id, 1);
        assert_eq!(migrated.ik_pub.as_ref(), ik_pub.as_slice());
        assert_eq!(migrated.spk_pub.as_ref(), spk_pub.as_slice());
        assert_eq!(migrated.vk_pub.as_ref(), vk_pub.as_slice());
        assert_eq!(migrated.spk_sig.as_ref(), spk_sig.as_slice());
    }

    #[test]
    fn migrate_otpk_bundle_json_sets_next_id() {
        let legacy = serde_json::json!([
            { "key_id": 1_000_000u32, "private_key": [1u8,2,3], "public_key": [9u8,8,7] },
            { "key_id": 1_000_010u32, "private_key": [4u8,5,6], "public_key": [6u8,5,4] }
        ])
        .to_string();

        let migrated = migrate_otpk_bundle_json_str(&legacy).unwrap();
        assert_eq!(migrated.records.len(), 2);
        assert_eq!(migrated.next_id, 1_000_011);
    }

    #[test]
    fn migrate_session_json_roundtrip_core_fields() {
        type TestClient = Client<
            ClassicSuiteProvider,
            X3DHProtocol<ClassicSuiteProvider>,
            DoubleRatchetSession<ClassicSuiteProvider>,
        >;

        let mut alice = TestClient::new().unwrap();
        let mut bob = TestClient::new().unwrap();
        alice.set_local_user_id("alice".to_string());
        bob.set_local_user_id("bob".to_string());

        let bob_bundle = bob.key_manager().export_registration_bundle().unwrap();
        let bob_identity_pub =
            ClassicSuiteProvider::kem_public_key_from_bytes(bob_bundle.identity_public.clone());

        alice
            .init_session("bob", &bob_bundle, &bob_identity_pub, 0)
            .unwrap();

        let session_json = {
            let session = alice.get_session("bob").unwrap();
            serde_json::to_string(&session.messaging_session().to_serializable()).unwrap()
        };

        let migrated = migrate_session_json_str(&session_json).unwrap();
        assert_eq!(migrated.ver, 1);
        assert_eq!(migrated.contact_id, "bob");
        assert_eq!(migrated.local_uid, "alice");
        assert_eq!(migrated.session_id.len(), 16);
        assert_eq!(migrated.rk.len(), 32);
    }
}
