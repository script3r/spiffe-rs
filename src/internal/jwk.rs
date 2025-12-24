use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtKey {
    Ec { crv: String, x: Vec<u8>, y: Vec<u8> },
    Rsa { n: Vec<u8>, e: Vec<u8> },
}

#[derive(Debug, Deserialize)]
pub struct JwkDocument {
    pub keys: Option<Vec<JwkKeyEntry>>,
    #[serde(rename = "spiffe_sequence")]
    pub spiffe_sequence: Option<u64>,
    #[serde(rename = "spiffe_refresh_hint")]
    pub spiffe_refresh_hint: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct JwkKeyEntry {
    pub kty: String,
    pub kid: Option<String>,
    #[serde(rename = "use")]
    pub use_field: Option<String>,
    pub crv: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
    pub x5c: Option<Vec<String>>,
}

impl JwkKeyEntry {
    pub fn key_id(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    pub fn to_jwt_key(&self) -> Result<JwtKey, String> {
        match self.kty.as_str() {
            "EC" => {
                let crv = self.crv.as_ref().ok_or_else(|| "missing crv".to_string())?;
                let x = self
                    .x
                    .as_ref()
                    .ok_or_else(|| "missing x".to_string())
                    .and_then(|value| decode_base64(value))?;
                let y = self
                    .y
                    .as_ref()
                    .ok_or_else(|| "missing y".to_string())
                    .and_then(|value| decode_base64(value))?;
                Ok(JwtKey::Ec {
                    crv: crv.clone(),
                    x,
                    y,
                })
            }
            "RSA" => {
                let n = self
                    .n
                    .as_ref()
                    .ok_or_else(|| "missing n".to_string())
                    .and_then(|value| decode_base64(value))?;
                let e = self
                    .e
                    .as_ref()
                    .ok_or_else(|| "missing e".to_string())
                    .and_then(|value| decode_base64(value))?;
                Ok(JwtKey::Rsa { n, e })
            }
            _ => Err(format!("unsupported kty {}", self.kty)),
        }
    }

    pub fn x509_certificate_der(&self) -> Option<Vec<u8>> {
        let mut iter = self.x5c.as_ref()?.iter();
        let first = iter.next()?.clone();
        STANDARD.decode(first.as_bytes()).ok()
    }
}

pub fn decode_base64(value: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|err| err.to_string())
}
