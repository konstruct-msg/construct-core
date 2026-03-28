// Base64 утилиты

use base64::{Engine, engine::general_purpose};

pub fn encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

pub fn decode(data: &str) -> Result<Vec<u8>, String> {
    general_purpose::STANDARD
        .decode(data)
        .map_err(|e| format!("Base64 decode failed: {}", e))
}
