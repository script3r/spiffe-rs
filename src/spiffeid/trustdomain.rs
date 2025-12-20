use crate::spiffeid::charset::is_backcompat_trust_domain_char;
use crate::spiffeid::id::make_id;
use crate::spiffeid::{Error, ID, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrustDomain {
    pub(crate) name: String,
}

pub fn trust_domain_from_string(id_or_name: &str) -> Result<TrustDomain> {
    if id_or_name.is_empty() {
        return Err(Error::MissingTrustDomain);
    }
    if id_or_name.contains(":/") {
        let id = ID::from_string(id_or_name)?;
        return Ok(id.trust_domain());
    }
    for &c in id_or_name.as_bytes() {
        if !is_valid_trust_domain_char(c) {
            return Err(Error::BadTrustDomainChar);
        }
    }
    Ok(TrustDomain {
        name: id_or_name.to_string(),
    })
}

pub fn trust_domain_from_uri(uri: &Url) -> Result<TrustDomain> {
    let id = ID::from_uri(uri)?;
    Ok(id.trust_domain())
}

impl TrustDomain {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn id(&self) -> ID {
        make_id(self, "").unwrap_or_else(|_| ID::zero())
    }

    pub fn id_string(&self) -> String {
        self.id().to_string()
    }

    pub fn is_zero(&self) -> bool {
        self.name.is_empty()
    }

    pub fn compare(&self, other: &TrustDomain) -> Ordering {
        self.name.cmp(&other.name)
    }

    pub fn marshal_text(&self) -> Option<Vec<u8>> {
        if self.is_zero() {
            None
        } else {
            Some(self.name.as_bytes().to_vec())
        }
    }

    pub fn unmarshal_text(&mut self, text: &[u8]) -> Result<()> {
        if text.is_empty() {
            *self = TrustDomain { name: String::new() };
            return Ok(());
        }
        let parsed = trust_domain_from_string(std::str::from_utf8(text).map_err(|e| {
            Error::Other(format!("invalid trust domain text: {}", e))
        })?)?;
        *self = parsed;
        Ok(())
    }
}

impl std::fmt::Display for TrustDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.name.fmt(f)
    }
}

impl Default for TrustDomain {
    fn default() -> Self {
        TrustDomain { name: String::new() }
    }
}

impl Serialize for TrustDomain {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.is_zero() {
            serializer.serialize_str("")
        } else {
            serializer.serialize_str(&self.name)
        }
    }
}

impl<'de> Deserialize<'de> for TrustDomain {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.is_empty() {
            Ok(TrustDomain { name: String::new() })
        } else {
            trust_domain_from_string(&s).map_err(serde::de::Error::custom)
        }
    }
}

fn is_valid_trust_domain_char(c: u8) -> bool {
    matches!(c, b'a'..=b'z')
        || matches!(c, b'0'..=b'9')
        || matches!(c, b'-' | b'.' | b'_')
        || is_backcompat_trust_domain_char(c)
}
