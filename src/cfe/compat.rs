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
// Note: migrate_private_keys_json_str, migrate_otpk_bundle_json_str, and
// migrate_session_json_str have been removed — legacy JSON is no longer
// supported. Only registration bundle and app settings migrations remain.
// ============================================================================

// DELETED — see note above:
// migrate_private_keys_json_str  (removed)
// migrate_session_json_str       (removed)
// migrate_otpk_bundle_json_str   (removed)

pub fn migrate_registration_bundle_json_str(
    legacy_json: &str,
) -> Result<crate::cfe::CfeRegistrationBundleV1, CfeError> {
    use base64::Engine as _;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct LegacyRegBundleJson {
        #[serde(rename = "identity_public")]
        identity_public: String,
        #[serde(rename = "signed_prekey_public")]
        signed_prekey_public: String,
        #[serde(rename = "signature")]
        signature: String,
        #[serde(rename = "verifying_key")]
        verifying_key: String,
        #[serde(rename = "suite_id")]
        suite_id: String,
    }

    let legacy: LegacyRegBundleJson = serde_json::from_str(legacy_json)
        .map_err(|e| CfeError::LegacyJsonParseFailed(e.to_string()))?;

    let decode_b64 = |s: &str| -> Result<Vec<u8>, CfeError> {
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|e| CfeError::Base64DecodeFailed(e.to_string()))
    };

    let suite_id_u8: u8 = legacy
        .suite_id
        .parse::<u16>()
        .map_err(|e| CfeError::InvalidField(format!("suite_id parse failed: {e}")))?
        .try_into()
        .map_err(|_| CfeError::InvalidField("suite_id out of range".to_string()))?;

    Ok(crate::cfe::CfeRegistrationBundleV1 {
        version: 1,
        identity_public: decode_b64(&legacy.identity_public)?,
        signed_prekey_public: decode_b64(&legacy.signed_prekey_public)?,
        signature: decode_b64(&legacy.signature)?,
        verifying_key: decode_b64(&legacy.verifying_key)?,
        suite_id: suite_id_u8,
    })
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

pub fn encode_registration_bundle_cfe(
    bundle: &crate::cfe::CfeRegistrationBundleV1,
) -> Result<Vec<u8>, CfeError> {
    encode(CfeMessageType::RegistrationBundle, bundle)
}

pub fn decode_registration_bundle_cfe(
    data: &[u8],
) -> Result<crate::cfe::CfeRegistrationBundleV1, CfeError> {
    decode_as(data, CfeMessageType::RegistrationBundle)
}

pub fn load_registration_bundle_migration(
    data: &[u8],
) -> Result<crate::cfe::CfeRegistrationBundleV1, CfeError> {
    if is_cfe_format(data) {
        decode_registration_bundle_cfe(data)
    } else if looks_like_legacy_json(data) {
        let json_str = std::str::from_utf8(data).map_err(|_| CfeError::InvalidFormat)?;
        migrate_registration_bundle_json_str(json_str)
    } else {
        Err(CfeError::InvalidFormat)
    }
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
    use crate::cfe::CfeRegistrationBundleV1;
    use crate::cfe::{decode_as, encode};
    use crate::crypto::provider::CryptoProvider;
    use crate::crypto::suites::classic::ClassicSuiteProvider;

    #[test]
    fn test_app_settings_cfe_roundtrip() {
        let settings = CfeAppSettingsV1 {
            version: 1,
            notifications_enabled: true,
            theme: "dark".to_string(),
            typing_indicator: true,
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
        assert!(!migrated.notifications_enabled);
        assert_eq!(migrated.theme, "light");
        assert!(migrated.typing_indicator);
        assert!(!migrated.read_receipts);
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

        assert!(!migrated.notifications_enabled);
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

    #[test]
    fn test_registration_bundle_json_migration() {
        use base64::Engine as _;

        let (_ik_priv, ik_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();
        let (_spk_priv, spk_pub) = ClassicSuiteProvider::generate_kem_keys().unwrap();
        let (_sk_priv, vk_pub) = ClassicSuiteProvider::generate_signature_keys().unwrap();
        let spk_sig = vec![7u8; 64];

        let legacy = serde_json::json!({
            "identity_public": base64::engine::general_purpose::STANDARD.encode(&ik_pub),
            "signed_prekey_public": base64::engine::general_purpose::STANDARD.encode(&spk_pub),
            "signature": base64::engine::general_purpose::STANDARD.encode(&spk_sig),
            "verifying_key": base64::engine::general_purpose::STANDARD.encode(&vk_pub),
            "suite_id": "1"
        })
        .to_string();

        let migrated = migrate_registration_bundle_json_str(&legacy).expect("migration");

        assert_eq!(migrated.version, 1);
        assert_eq!(migrated.suite_id, 1);
        assert_eq!(migrated.identity_public.as_slice(), ik_pub.as_slice());
        assert_eq!(migrated.signed_prekey_public.as_slice(), spk_pub.as_slice());
    }

    #[test]
    fn test_registration_bundle_cfe_roundtrip() {
        let bundle = CfeRegistrationBundleV1 {
            version: 1,
            identity_public: vec![1, 2, 3, 4],
            signed_prekey_public: vec![5, 6, 7, 8],
            signature: vec![9, 10, 11, 12],
            verifying_key: vec![13, 14, 15, 16],
            suite_id: 1,
        };

        let encoded = encode(CfeMessageType::RegistrationBundle, &bundle).expect("encode");
        let decoded: CfeRegistrationBundleV1 =
            decode_as(&encoded, CfeMessageType::RegistrationBundle).expect("decode");

        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.identity_public.as_slice(), &[1, 2, 3, 4]);
        assert_eq!(decoded.suite_id, 1);
    }

    #[test]
    fn test_load_registration_bundle_migration_cfe() {
        let bundle = CfeRegistrationBundleV1 {
            version: 1,
            identity_public: vec![1, 2, 3],
            signed_prekey_public: vec![4, 5, 6],
            signature: vec![7, 8, 9],
            verifying_key: vec![10, 11, 12],
            suite_id: 1,
        };

        let encoded = encode(CfeMessageType::RegistrationBundle, &bundle).expect("encode");
        let loaded = load_registration_bundle_migration(&encoded).expect("load");

        assert_eq!(loaded.identity_public.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn test_load_registration_bundle_migration_json() {
        let legacy = serde_json::json!({
            "identity_public": "AQID",
            "signed_prekey_public": "AQIE",
            "signature": "AQIF",
            "verifying_key": "AQYG",
            "suite_id": "1"
        })
        .to_string();

        let loaded = load_registration_bundle_migration(legacy.as_bytes()).expect("load");

        assert_eq!(loaded.identity_public.as_slice(), &[1, 2, 3]);
        assert_eq!(loaded.suite_id, 1);
    }
}
