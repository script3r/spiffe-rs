use crate::spiffeid::charset::is_backcompat_trust_domain_char;
use crate::spiffeid::path::{format_path, join_path_segments, validate_path};
use crate::spiffeid::{Error, Result, TrustDomain};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use url::Url;

const SCHEME_PREFIX: &str = "spiffe://";

/// A SPIFFE ID is a structured URI that uniquely identifies a workload or other entity.
///
/// It follows the format: `spiffe://<trust-domain>/<path>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ID {
    id: String,
    path_idx: usize,
}

/// A parsed SPIFFE URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeUrl {
    scheme: String,
    host: String,
    path: String,
}

impl SpiffeUrl {
    /// Creates a new `SpiffeUrl`.
    pub fn new(scheme: &str, host: &str, path: &str) -> Self {
        Self {
            scheme: scheme.to_string(),
            host: host.to_string(),
            path: path.to_string(),
        }
    }

    /// Creates an empty `SpiffeUrl`.
    pub fn empty() -> Self {
        Self {
            scheme: String::new(),
            host: String::new(),
            path: String::new(),
        }
    }

    /// Returns the scheme of the URL.
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Returns the host of the URL (the trust domain).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the path of the URL.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns `true` if the URL is empty.
    pub fn is_empty(&self) -> bool {
        self.scheme.is_empty() && self.host.is_empty() && self.path.is_empty()
    }

    /// Converts the `SpiffeUrl` to a `url::Url`.
    pub fn as_url(&self) -> Option<Url> {
        if self.is_empty() {
            return None;
        }
        Url::parse(&self.to_string()).ok()
    }
}

impl std::fmt::Display for SpiffeUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_empty() {
            return Ok(());
        }
        write!(f, "{}://{}{}", self.scheme, self.host, self.path)
    }
}

impl ID {
    /// Creates a SPIFFE ID from a trust domain and a path.
    pub fn from_path(td: TrustDomain, path: &str) -> Result<ID> {
        validate_path(path)?;
        make_id(&td, path)
    }

    /// Creates a SPIFFE ID from a trust domain and a formatted path.
    pub fn from_pathf(td: TrustDomain, args: std::fmt::Arguments<'_>) -> Result<ID> {
        let path = format_path(args)?;
        make_id(&td, &path)
    }

    /// Creates a SPIFFE ID from a trust domain and path segments.
    pub fn from_segments(td: TrustDomain, segments: &[&str]) -> Result<ID> {
        let path = join_path_segments(segments)?;
        make_id(&td, &path)
    }

    /// Parses a SPIFFE ID from a string.
    pub fn from_string(id: &str) -> Result<ID> {
        if id.is_empty() {
            return Err(Error::Empty);
        }
        if !id.starts_with(SCHEME_PREFIX) {
            return Err(Error::WrongScheme);
        }

        let mut path_idx = SCHEME_PREFIX.len();
        let bytes = id.as_bytes();
        while path_idx < bytes.len() {
            let c = bytes[path_idx];
            if c == b'/' {
                break;
            }
            if !is_valid_trust_domain_char(c) {
                return Err(Error::BadTrustDomainChar);
            }
            path_idx += 1;
        }

        if path_idx == SCHEME_PREFIX.len() {
            return Err(Error::MissingTrustDomain);
        }

        validate_path(&id[path_idx..])?;

        Ok(ID {
            id: id.to_string(),
            path_idx,
        })
    }

    /// Parses a SPIFFE ID from formatted arguments.
    pub fn from_stringf(args: std::fmt::Arguments<'_>) -> Result<ID> {
        ID::from_string(&format!("{}", args))
    }

    /// Parses a SPIFFE ID from a `url::Url`.
    pub fn from_uri(uri: &Url) -> Result<ID> {
        ID::from_string(uri.as_str())
    }

    /// Returns the trust domain of the SPIFFE ID.
    pub fn trust_domain(&self) -> TrustDomain {
        if self.is_zero() {
            return TrustDomain {
                name: String::new(),
            };
        }
        TrustDomain {
            name: self.id[SCHEME_PREFIX.len()..self.path_idx].to_string(),
        }
    }

    /// Returns `true` if the SPIFFE ID is a member of the given trust domain.
    pub fn member_of(&self, td: &TrustDomain) -> bool {
        self.trust_domain() == *td
    }

    /// Returns the path component of the SPIFFE ID.
    pub fn path(&self) -> &str {
        &self.id[self.path_idx..]
    }

    /// Returns the SPIFFE ID as a `SpiffeUrl`.
    pub fn url(&self) -> SpiffeUrl {
        if self.is_zero() {
            return SpiffeUrl::empty();
        }
        SpiffeUrl::new("spiffe", self.trust_domain().name(), self.path())
    }

    /// Returns `true` if the SPIFFE ID is empty/zero.
    pub fn is_zero(&self) -> bool {
        self.id.is_empty()
    }

    /// Appends a path to the SPIFFE ID.
    pub fn append_path(&self, path: &str) -> Result<ID> {
        if self.is_zero() {
            return Err(Error::Other(
                "cannot append path on a zero ID value".to_string(),
            ));
        }
        validate_path(path)?;
        let mut id = self.clone();
        id.id.push_str(path);
        Ok(id)
    }

    /// Appends a formatted path to the SPIFFE ID.
    pub fn append_pathf(&self, args: std::fmt::Arguments<'_>) -> Result<ID> {
        if self.is_zero() {
            return Err(Error::Other(
                "cannot append path on a zero ID value".to_string(),
            ));
        }
        let path = format_path(args)?;
        let mut id = self.clone();
        id.id.push_str(&path);
        Ok(id)
    }

    /// Appends path segments to the SPIFFE ID.
    pub fn append_segments(&self, segments: &[&str]) -> Result<ID> {
        if self.is_zero() {
            return Err(Error::Other(
                "cannot append path segments on a zero ID value".to_string(),
            ));
        }
        let path = join_path_segments(segments)?;
        let mut id = self.clone();
        id.id.push_str(&path);
        Ok(id)
    }

    /// Replaces the path of the SPIFFE ID.
    pub fn replace_path(&self, path: &str) -> Result<ID> {
        if self.is_zero() {
            return Err(Error::Other(
                "cannot replace path on a zero ID value".to_string(),
            ));
        }
        ID::from_path(self.trust_domain(), path)
    }

    /// Replaces the path of the SPIFFE ID with a formatted string.
    pub fn replace_pathf(&self, args: std::fmt::Arguments<'_>) -> Result<ID> {
        if self.is_zero() {
            return Err(Error::Other(
                "cannot replace path on a zero ID value".to_string(),
            ));
        }
        let path = format_path(args)?;
        ID::from_path(self.trust_domain(), &path)
    }

    /// Replaces the path of the SPIFFE ID with path segments.
    pub fn replace_segments(&self, segments: &[&str]) -> Result<ID> {
        if self.is_zero() {
            return Err(Error::Other(
                "cannot replace path segments on a zero ID value".to_string(),
            ));
        }
        let path = join_path_segments(segments)?;
        ID::from_path(self.trust_domain(), &path)
    }

    /// Returns an empty/zero SPIFFE ID.
    pub fn zero() -> ID {
        ID {
            id: String::new(),
            path_idx: 0,
        }
    }
}

impl std::fmt::Display for ID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.id.fmt(f)
    }
}

impl Serialize for ID {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.is_zero() {
            serializer.serialize_str("")
        } else {
            serializer.serialize_str(&self.id)
        }
    }
}

impl Default for ID {
    fn default() -> Self {
        ID::zero()
    }
}

impl<'de> Deserialize<'de> for ID {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.is_empty() {
            Ok(ID::zero())
        } else {
            ID::from_string(&s).map_err(serde::de::Error::custom)
        }
    }
}

pub(crate) fn make_id(td: &TrustDomain, path: &str) -> Result<ID> {
    if td.is_zero() {
        return Err(Error::MissingTrustDomain);
    }
    let mut id = String::with_capacity(SCHEME_PREFIX.len() + td.name.len() + path.len());
    id.push_str(SCHEME_PREFIX);
    id.push_str(td.name());
    let path_idx = id.len();
    id.push_str(path);
    Ok(ID { id, path_idx })
}

fn is_valid_trust_domain_char(c: u8) -> bool {
    matches!(c, b'a'..=b'z')
        || matches!(c, b'0'..=b'9')
        || matches!(c, b'-' | b'.' | b'_')
        || is_backcompat_trust_domain_char(c)
}
