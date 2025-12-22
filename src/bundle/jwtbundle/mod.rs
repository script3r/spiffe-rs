use crate::internal::jwk::JwkDocument;
use crate::internal::jwtutil;
use crate::spiffeid::TrustDomain;
use base64::Engine;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::sync::RwLock;

#[derive(Debug, Clone)]
pub struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Error {}

impl Error {
    pub fn new(message: impl Into<String>) -> Error {
        Error(message.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub use crate::internal::jwk::JwtKey;

fn wrap_error(message: impl std::fmt::Display) -> Error {
    Error(format!("jwtbundle: {}", message))
}

fn strip_prefix(message: &str) -> &str {
    message.strip_prefix("jwtbundle: ").unwrap_or(message)
}

/// A JWT bundle contains the JWT authorities (public keys) for a trust domain.
#[derive(Debug)]
pub struct Bundle {
    trust_domain: TrustDomain,
    jwt_authorities: RwLock<HashMap<String, JwtKey>>,
}

impl Bundle {
    /// Creates a new empty `Bundle` for the given trust domain.
    pub fn new(trust_domain: TrustDomain) -> Bundle {
        Bundle {
            trust_domain,
            jwt_authorities: RwLock::new(HashMap::new()),
        }
    }

    /// Creates a new `Bundle` for the given trust domain and authorities.
    pub fn from_jwt_authorities(
        trust_domain: TrustDomain,
        jwt_authorities: &HashMap<String, JwtKey>,
    ) -> Bundle {
        Bundle {
            trust_domain,
            jwt_authorities: RwLock::new(jwtutil::copy_jwt_authorities(jwt_authorities)),
        }
    }

    /// Loads a JWT bundle from a JSON file (JWKS).
    pub fn load(trust_domain: TrustDomain, path: &str) -> Result<Bundle> {
        let bytes =
            fs::read(path).map_err(|err| wrap_error(format!("unable to read JWT bundle: {}", err)))?;
        Bundle::parse(trust_domain, &bytes)
    }

    /// Reads a JWT bundle from a reader.
    pub fn read(trust_domain: TrustDomain, reader: &mut dyn Read) -> Result<Bundle> {
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .map_err(|err| wrap_error(format!("unable to read: {}", err)))?;
        Bundle::parse(trust_domain, &bytes)
    }

    /// Parses a JWT bundle from JSON bytes (JWKS).
    pub fn parse(trust_domain: TrustDomain, bytes: &[u8]) -> Result<Bundle> {
        let jwks: JwkDocument =
            serde_json::from_slice(bytes).map_err(|err| wrap_error(format!("unable to parse JWKS: {}", err)))?;
        let bundle = Bundle::new(trust_domain);
        let keys = jwks.keys.unwrap_or_default();
        for (idx, key) in keys.iter().enumerate() {
            let key_id = key.key_id().unwrap_or_default();
            let jwt_key = key
                .to_jwt_key()
                .map_err(|err| wrap_error(format!("error adding authority {} of JWKS: {}", idx, err)))?;
            if let Err(err) = bundle.add_jwt_authority(key_id, jwt_key) {
                return Err(wrap_error(format!(
                    "error adding authority {} of JWKS: {}",
                    idx,
                    strip_prefix(&err.to_string())
                )));
            }
        }
        Ok(bundle)
    }

    /// Returns the trust domain of the bundle.
    pub fn trust_domain(&self) -> TrustDomain {
        self.trust_domain.clone()
    }

    /// Returns the JWT authorities in the bundle.
    pub fn jwt_authorities(&self) -> HashMap<String, JwtKey> {
        self.jwt_authorities
            .read()
            .map(|guard| jwtutil::copy_jwt_authorities(&guard))
            .unwrap_or_default()
    }

    /// Finds a JWT authority by its key ID.
    pub fn find_jwt_authority(&self, key_id: &str) -> Option<JwtKey> {
        self.jwt_authorities
            .read()
            .ok()
            .and_then(|guard| guard.get(key_id).cloned())
    }

    /// Returns `true` if the bundle has an authority with the given key ID.
    pub fn has_jwt_authority(&self, key_id: &str) -> bool {
        self.jwt_authorities
            .read()
            .map(|guard| guard.contains_key(key_id))
            .unwrap_or(false)
    }

    /// Adds a JWT authority to the bundle.
    pub fn add_jwt_authority(&self, key_id: &str, jwt_authority: JwtKey) -> Result<()> {
        if key_id.is_empty() {
            return Err(wrap_error("keyID cannot be empty"));
        }
        if let Ok(mut guard) = self.jwt_authorities.write() {
            guard.insert(key_id.to_string(), jwt_authority);
        }
        Ok(())
    }

    /// Removes a JWT authority from the bundle.
    pub fn remove_jwt_authority(&self, key_id: &str) {
        if let Ok(mut guard) = self.jwt_authorities.write() {
            guard.remove(key_id);
        }
    }

    /// Sets the JWT authorities in the bundle.
    pub fn set_jwt_authorities(&self, jwt_authorities: &HashMap<String, JwtKey>) {
        if let Ok(mut guard) = self.jwt_authorities.write() {
            *guard = jwtutil::copy_jwt_authorities(jwt_authorities);
        }
    }

    /// Returns `true` if the bundle is empty.
    pub fn empty(&self) -> bool {
        self.jwt_authorities
            .read()
            .map(|guard| guard.is_empty())
            .unwrap_or(true)
    }

    /// Marshals the bundle to JSON bytes (JWKS).
    pub fn marshal(&self) -> Result<Vec<u8>> {
        let mut keys = Vec::new();
        let authorities = self.jwt_authorities();
        for (key_id, jwt_key) in authorities {
            keys.push(JwksKey::from_jwt_key(&key_id, &jwt_key));
        }
        let jwks = Jwks { keys };
        serde_json::to_vec(&jwks).map_err(|err| wrap_error(err))
    }

    /// Clones the bundle.
    pub fn clone_bundle(&self) -> Bundle {
        Bundle::from_jwt_authorities(self.trust_domain(), &self.jwt_authorities())
    }

    /// Returns `true` if this bundle is equal to another bundle.
    pub fn equal(&self, other: &Bundle) -> bool {
        self.trust_domain == other.trust_domain
            && jwtutil::jwt_authorities_equal(&self.jwt_authorities(), &other.jwt_authorities())
    }

    /// Returns the bundle for the given trust domain if it matches.
    pub fn get_jwt_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> Result<Bundle> {
        if self.trust_domain != trust_domain {
            return Err(wrap_error(format!(
                "no JWT bundle for trust domain \"{}\"",
                trust_domain
            )));
        }
        Ok(self.clone_bundle())
    }
}

/// A source of JWT bundles.
pub trait Source {
    /// Returns the JWT bundle for the given trust domain.
    fn get_jwt_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> Result<Bundle>;
}

/// A set of JWT bundles for multiple trust domains.
#[derive(Debug)]
pub struct Set {
    bundles: RwLock<HashMap<TrustDomain, Bundle>>,
}

impl Set {
    /// Creates a new `Set` from the given bundles.
    pub fn new(bundles: &[Bundle]) -> Set {
        let mut map = HashMap::new();
        for bundle in bundles {
            map.insert(bundle.trust_domain(), bundle.clone_bundle());
        }
        Set {
            bundles: RwLock::new(map),
        }
    }

    /// Adds a bundle to the set.
    pub fn add(&self, bundle: &Bundle) {
        if let Ok(mut guard) = self.bundles.write() {
            guard.insert(bundle.trust_domain(), bundle.clone_bundle());
        }
    }

    /// Removes the bundle for the given trust domain from the set.
    pub fn remove(&self, trust_domain: TrustDomain) {
        if let Ok(mut guard) = self.bundles.write() {
            guard.remove(&trust_domain);
        }
    }

    /// Returns `true` if the set has a bundle for the given trust domain.
    pub fn has(&self, trust_domain: TrustDomain) -> bool {
        self.bundles
            .read()
            .map(|guard| guard.contains_key(&trust_domain))
            .unwrap_or(false)
    }

    /// Returns the bundle for the given trust domain from the set.
    pub fn get(&self, trust_domain: TrustDomain) -> Option<Bundle> {
        self.bundles
            .read()
            .ok()
            .and_then(|guard| guard.get(&trust_domain).map(|b| b.clone_bundle()))
    }

    /// Returns all bundles in the set.
    pub fn bundles(&self) -> Vec<Bundle> {
        let mut bundles = self
            .bundles
            .read()
            .map(|guard| guard.values().map(|b| b.clone_bundle()).collect::<Vec<_>>())
            .unwrap_or_default();
        bundles.sort_by(|a, b| a.trust_domain().compare(&b.trust_domain()));
        bundles
    }

    /// Returns the number of bundles in the set.
    pub fn len(&self) -> usize {
        self.bundles.read().map(|guard| guard.len()).unwrap_or(0)
    }

    /// Returns the JWT bundle for the given trust domain.
    pub fn get_jwt_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> Result<Bundle> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| wrap_error("bundle store poisoned"))?;
        let bundle = guard.get(&trust_domain).ok_or_else(|| {
            wrap_error(format!(
                "no JWT bundle for trust domain \"{}\"",
                trust_domain
            ))
        })?;
        Ok(bundle.clone_bundle())
    }
}

impl Source for Set {
    fn get_jwt_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> Result<Bundle> {
        self.get_jwt_bundle_for_trust_domain(trust_domain)
    }
}

impl Source for Bundle {
    fn get_jwt_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> Result<Bundle> {
        self.get_jwt_bundle_for_trust_domain(trust_domain)
    }
}

#[derive(Serialize)]
struct Jwks {
    keys: Vec<JwksKey>,
}

#[derive(Serialize)]
struct JwksKey {
    kty: String,
    kid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    e: Option<String>,
}

impl JwksKey {
    fn from_jwt_key(key_id: &str, key: &JwtKey) -> JwksKey {
        match key {
            JwtKey::Ec { crv, x, y } => JwksKey {
                kty: "EC".to_string(),
                kid: key_id.to_string(),
                crv: Some(crv.clone()),
                x: Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x)),
                y: Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y)),
                n: None,
                e: None,
            },
            JwtKey::Rsa { n, e } => JwksKey {
                kty: "RSA".to_string(),
                kid: key_id.to_string(),
                crv: None,
                x: None,
                y: None,
                n: Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(n)),
                e: Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(e)),
            },
        }
    }
}
