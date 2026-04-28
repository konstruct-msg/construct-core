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
        old_spks: Vec::new(), // legacy JSON doesn't carry old SPKs
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

// ============================================================================
// Storage Migration: AppSettings (Этап 1)
// ============================================================================

use crate::cfe::CfeMessageType;
use crate::cfe::{decode, decode_as, encode};
use rmp_serde;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyBundleFormat {
    Json,
    Postcard,
    Cfe,
    Unknown,
}

pub fn detect_format(data: &[u8]) -> KeyBundleFormat {
    if data.len() >= 2 && data[0] == 0x43 && data[1] == 0x46 {
        return KeyBundleFormat::Cfe;
    }
    if looks_like_legacy_json(data) {
        return KeyBundleFormat::Json;
    }
    KeyBundleFormat::Postcard
}

pub fn migrate_app_settings_json_to_cfe(
    json_data: &[u8],
) -> Result<crate::cfe::CfeAppSettingsV1, CfeError> {
    #[derive(serde::Deserialize)]
    struct LegacyJsonSettings {
        #[serde(rename = "notificationsEnabled")]
        notifications_enabled: Option<bool>,
        #[serde(rename = "theme")]
        theme: Option<String>,
        #[serde(rename = "typingIndicator")]
        typing_indicator: Option<bool>,
        #[serde(rename = "readReceipts")]
        read_receipts: Option<bool>,
        #[serde(rename = "lastSync")]
        last_sync: Option<i64>,
    }

    let legacy: LegacyJsonSettings = serde_json::from_slice(json_data)
        .map_err(|e| CfeError::LegacyJsonParseFailed(e.to_string()))?;

    Ok(crate::cfe::CfeAppSettingsV1 {
        version: 1,
        notifications_enabled: legacy.notifications_enabled.unwrap_or(true),
        theme: legacy.theme.unwrap_or_else(|| "default".to_string()),
        typing_indicator: legacy.typing_indicator.unwrap_or(true),
        read_receipts: legacy.read_receipts.unwrap_or(true),
        last_sync: legacy.last_sync.unwrap_or(0),
    })
}

pub fn encode_app_settings_cfe(
    settings: &crate::cfe::CfeAppSettingsV1,
) -> Result<Vec<u8>, CfeError> {
    encode(CfeMessageType::AppSettings, settings)
}

pub fn decode_app_settings_cfe(data: &[u8]) -> Result<crate::cfe::CfeAppSettingsV1, CfeError> {
    decode_as(data, CfeMessageType::AppSettings)
}

pub fn migrate_contact_keys_to_cfe(
    legacy: &[u8],
    format: KeyBundleFormat,
) -> Result<Vec<u8>, CfeError> {
    let key_bundle_data = match format {
        KeyBundleFormat::Json => {
            return Err(CfeError::LegacyJson);
        }
        KeyBundleFormat::Postcard => legacy.to_vec(),
        KeyBundleFormat::Cfe => {
            let envelope = decode(legacy)?;
            envelope.payload
        }
        KeyBundleFormat::Unknown => {
            return Err(CfeError::InvalidFormat);
        }
    };

    let cfe_bundle = crate::cfe::CfeContactKeyBundleV1 {
        version: 1,
        key_bundle: key_bundle_data,
    };

    encode(CfeMessageType::ContactKeyBundle, &cfe_bundle)
}

pub fn decode_contact_keys_cfe(data: &[u8]) -> Result<Vec<u8>, CfeError> {
    let envelope = decode(data)?;
    if envelope.msg_type != CfeMessageType::ContactKeyBundle {
        return Err(CfeError::TypeMismatch {
            expected: CfeMessageType::ContactKeyBundle,
            got: envelope.msg_type,
        });
    }
    let bundle: crate::cfe::CfeContactKeyBundleV1 = rmp_serde::from_slice(&envelope.payload)
        .map_err(|e| CfeError::DeserializeFailed(e.to_string()))?;
    Ok(bundle.key_bundle)
}

pub fn load_settings_migration(data: &[u8]) -> Result<crate::cfe::CfeAppSettingsV1, CfeError> {
    if is_cfe_format(data) {
        decode_app_settings_cfe(data)
    } else if looks_like_legacy_json(data) {
        migrate_app_settings_json_to_cfe(data)
    } else {
        Err(CfeError::InvalidFormat)
    }
}

pub fn save_settings_cfe(settings: &crate::cfe::CfeAppSettingsV1) -> Result<Vec<u8>, CfeError> {
    encode_app_settings_cfe(settings)
}

// ============================================================================
// Storage Migration Tests
// ============================================================================

#[cfg(test)]
mod storage_tests {
    use super::*;
    use crate::cfe::CfeAppSettingsV1;
    use crate::cfe::CfeContactKeyBundleV1;
    use crate::cfe::CfeMessageType;
    use crate::cfe::{decode_as, encode};

    #[test]
    fn test_app_settings_cfe_roundtrip() {
        let settings = CfeAppSettingsV1 {
            version: 1,
            notifications_enabled: true,
            theme: "dark".to_string(),
            typing_indicator: false,
            read_receipts: true,
            last_sync: 1700000000,
        };

        let encoded = encode(CfeMessageType::AppSettings, &settings).expect("encode");
        let decoded: CfeAppSettingsV1 =
            decode_as(&encoded, CfeMessageType::AppSettings).expect("decode");

        assert_eq!(decoded.version, 1);
        assert!(decoded.notifications_enabled);
        assert_eq!(decoded.theme, "dark");
        assert!(decoded.typing_indicator);
        assert!(decoded.read_receipts);
        assert_eq!(decoded.last_sync, 1700000000);
    }

    #[test]
    fn test_app_settings_default() {
        let settings = CfeAppSettingsV1::default();

        assert_eq!(settings.version, 1);
        assert!(settings.notifications_enabled);
        assert_eq!(settings.theme, "default");
        assert!(settings.typing_indicator);
        assert!(settings.read_receipts);
        assert_eq!(settings.last_sync, 0);
    }

    #[test]
    fn test_app_settings_json_migration() {
        let json_data = br#"{"notificationsEnabled":false,"theme":"light","typingIndicator":true,"readReceipts":false,"lastSync":1700000000}"#;

        let migrated = migrate_app_settings_json_to_cfe(json_data).expect("migration");

        assert_eq!(migrated.version, 1);
        assert!(migrated.notifications_enabled);
        assert_eq!(migrated.theme, "light");
        assert!(migrated.typing_indicator);
        assert!(migrated.read_receipts);
        assert_eq!(migrated.last_sync, 1700000000);
    }

    #[test]
    fn test_app_settings_json_migration_defaults() {
        let json_data = br#"{}"#;

        let migrated = migrate_app_settings_json_to_cfe(json_data).expect("migration");

        assert!(migrated.notifications_enabled);
        assert_eq!(migrated.theme, "default");
        assert!(migrated.typing_indicator);
        assert!(migrated.read_receipts);
    }

    #[test]
    fn test_app_settings_json_migration_missing_fields() {
        let json_data = br#"{"notificationsEnabled":false,"theme":"dark"}"#;

        let migrated = migrate_app_settings_json_to_cfe(json_data).expect("migration");

        assert!(migrated.notifications_enabled);
        assert_eq!(migrated.theme, "dark");
        assert!(migrated.typing_indicator);
        assert!(migrated.read_receipts);
    }

    #[test]
    fn test_app_settings_json_migration_invalid() {
        let json_data = b"not json";

        let result = migrate_app_settings_json_to_cfe(json_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_settings_migration_cfe() {
        let settings = CfeAppSettingsV1 {
            version: 1,
            notifications_enabled: false,
            theme: "blue".to_string(),
            typing_indicator: true,
            read_receipts: false,
            last_sync: 1700000000,
        };

        let encoded = encode(CfeMessageType::AppSettings, &settings).expect("encode");
        let loaded = load_settings_migration(&encoded).expect("load");

        assert_eq!(loaded.theme, "blue");
    }

    #[test]
    fn test_load_settings_migration_json() {
        let json_data = br#"{"theme":"red","lastSync":1700000000}"#;

        let loaded = load_settings_migration(json_data).expect("load");

        assert_eq!(loaded.theme, "red");
        assert_eq!(loaded.last_sync, 1700000000);
    }

    #[test]
    fn test_load_settings_migration_invalid() {
        let data = b"binary data";

        let result = load_settings_migration(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_save_settings_cfe() {
        let settings = CfeAppSettingsV1 {
            version: 1,
            notifications_enabled: true,
            theme: "system".to_string(),
            typing_indicator: false,
            read_receipts: true,
            last_sync: 1700000000,
        };

        let saved = save_settings_cfe(&settings).expect("save");

        let decoded: CfeAppSettingsV1 =
            decode_as(&saved, CfeMessageType::AppSettings).expect("decode");
        assert_eq!(decoded.theme, "system");
    }

    #[test]
    fn test_contact_keys_cfe_roundtrip() {
        let key_data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let bundle = CfeContactKeyBundleV1 {
            version: 1,
            key_bundle: key_data.clone(),
        };

        let encoded = encode(CfeMessageType::ContactKeyBundle, &bundle).expect("encode");
        let decoded_keys = decode_contact_keys_cfe(&encoded).expect("decode");

        assert_eq!(decoded_keys, key_data);
    }

    #[test]
    fn test_contact_keys_postcard_migration() {
        let postcard_data = vec![0x00, 0x01, 0x02, 0x03];

        let migrated = migrate_contact_keys_to_cfe(&postcard_data, KeyBundleFormat::Postcard)
            .expect("migrate");

        assert!(!migrated.is_empty());
        assert!(is_cfe_format(&migrated));

        let extracted = decode_contact_keys_cfe(&migrated).expect("extract");
        assert_eq!(extracted, postcard_data);
    }

    #[test]
    fn test_detect_format_cfe() {
        let cfe_data = [0x43, 0x46, 0x01, 0x01];
        assert_eq!(detect_format(&cfe_data), KeyBundleFormat::Cfe);
    }

    #[test]
    fn test_detect_format_json_object() {
        let json_data = b"{\"key\":\"value\"}";
        assert_eq!(detect_format(json_data), KeyBundleFormat::Json);
    }

    #[test]
    fn test_detect_format_json_array() {
        let json_data = b"[1,2,3]";
        assert_eq!(detect_format(json_data), KeyBundleFormat::Json);
    }

    #[test]
    fn test_detect_format_postcard() {
        let postcard_data = vec![0x00, 0x01, 0x02];
        assert_eq!(detect_format(&postcard_data), KeyBundleFormat::Postcard);
    }

    #[test]
    fn test_is_cfe_format() {
        assert!(is_cfe_format(&[0x43, 0x46, 0x01]));
        assert!(!is_cfe_format(&[0x42, 0x46, 0x01]));
        assert!(!is_cfe_format(&[0x43, 0x47, 0x01]));
        assert!(!is_cfe_format(b"{\"key\":\"value\"}"));
    }

    #[test]
    fn test_looks_like_legacy_json() {
        assert!(looks_like_legacy_json(b"{\"key\":\"value\"}"));
        assert!(looks_like_legacy_json(b"[1,2,3]"));
        assert!(looks_like_legacy_json(b"   {\"key\":\"value\"}"));
        assert!(looks_like_legacy_json(b"\t{\"key\":\"value\"}"));
        assert!(looks_like_legacy_json(b"\n{\"key\":\"value\"}"));
        assert!(!looks_like_legacy_json(b"not json"));
        assert!(!looks_like_legacy_json(&[0x00, 0x01, 0x02]));
    }

    #[test]
    fn test_decode_contact_keys_wrong_type() {
        let settings = CfeAppSettingsV1::default();
        let encoded = encode(CfeMessageType::AppSettings, &settings).expect("encode");

        let result = decode_contact_keys_cfe(&encoded);
        assert!(result.is_err());
    }
}
