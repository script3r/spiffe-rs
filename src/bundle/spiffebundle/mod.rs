use crate::bundle::jwtbundle;
use crate::bundle::x509bundle;
use crate::internal::jwk::JwkDocument;
use crate::internal::jwtutil;
use crate::internal::x509util;
use crate::spiffeid::TrustDomain;
use base64::Engine;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::sync::RwLock;
use std::time::Duration;
use oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_NIST_EC_P384, OID_NIST_EC_P521};
use x509_parser::prelude::X509Certificate;

const X509_SVID_USE: &str = "x509-svid";
const JWT_SVID_USE: &str = "jwt-svid";

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
    Error(format!("spiffebundle: {}", message))
}

fn strip_prefix(message: &str) -> &str {
    message.strip_prefix("spiffebundle: ").unwrap_or(message)
}

/// A SPIFFE bundle contains both X.509 and JWT authorities for a trust domain.
#[derive(Debug)]
pub struct Bundle {
    trust_domain: TrustDomain,
    refresh_hint: RwLock<Option<Duration>>,
    sequence_number: RwLock<Option<u64>>,
    jwt_authorities: RwLock<HashMap<String, JwtKey>>,
    x509_authorities: RwLock<Vec<Vec<u8>>>,
}

impl Bundle {
    /// Creates a new empty `Bundle` for the given trust domain.
    pub fn new(trust_domain: TrustDomain) -> Bundle {
        Bundle {
            trust_domain,
            refresh_hint: RwLock::new(None),
            sequence_number: RwLock::new(None),
            jwt_authorities: RwLock::new(HashMap::new()),
            x509_authorities: RwLock::new(Vec::new()),
        }
    }

    /// Loads a SPIFFE bundle from a JSON file (JWKS).
    pub fn load(trust_domain: TrustDomain, path: &str) -> Result<Bundle> {
        let bytes =
            fs::read(path).map_err(|err| wrap_error(format!("unable to read SPIFFE bundle: {}", err)))?;
        Bundle::parse(trust_domain, &bytes)
    }

    /// Reads a SPIFFE bundle from a reader.
    pub fn read(trust_domain: TrustDomain, reader: &mut dyn Read) -> Result<Bundle> {
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .map_err(|err| wrap_error(format!("unable to read: {}", err)))?;
        Bundle::parse(trust_domain, &bytes)
    }

    /// Parses a SPIFFE bundle from JSON bytes (JWKS).
    pub fn parse(trust_domain: TrustDomain, bytes: &[u8]) -> Result<Bundle> {
        let jwks: JwkDocument =
            serde_json::from_slice(bytes).map_err(|err| wrap_error(format!("unable to parse JWKS: {}", err)))?;
        let bundle = Bundle::new(trust_domain);
        if let Some(hint) = jwks.spiffe_refresh_hint {
            bundle.set_refresh_hint(Duration::from_secs(hint as u64));
        }
        if let Some(seq) = jwks.spiffe_sequence {
            bundle.set_sequence_number(seq);
        }

        let keys = jwks.keys.ok_or_else(|| wrap_error("no authorities found"))?;
        for (idx, key) in keys.iter().enumerate() {
            match key.use_field.as_deref() {
                Some(X509_SVID_USE) => {
                    let cert = key
                        .x509_certificate_der()
                        .ok_or_else(|| {
                            wrap_error(format!(
                                "expected a single certificate in {} entry {}; got 0",
                                X509_SVID_USE, idx
                            ))
                        })?;
                    if let Some(count) = key.x5c.as_ref().map(|x| x.len()) {
                        if count != 1 {
                            return Err(wrap_error(format!(
                                "expected a single certificate in {} entry {}; got {}",
                                X509_SVID_USE, idx, count
                            )));
                        }
                    }
                    bundle.add_x509_authority(&cert);
                }
                Some(JWT_SVID_USE) => {
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
                _ => {}
            }
        }
        Ok(bundle)
    }

    /// Creates a SPIFFE bundle from an X.509 bundle.
    pub fn from_x509_bundle(x509_bundle: &x509bundle::Bundle) -> Bundle {
        let bundle = Bundle::new(x509_bundle.trust_domain());
        bundle.set_x509_authorities(&x509_bundle.x509_authorities());
        bundle
    }

    /// Creates a SPIFFE bundle from a JWT bundle.
    pub fn from_jwt_bundle(jwt_bundle: &jwtbundle::Bundle) -> Bundle {
        let bundle = Bundle::new(jwt_bundle.trust_domain());
        bundle.set_jwt_authorities(&jwt_bundle.jwt_authorities());
        bundle
    }

    /// Creates a SPIFFE bundle from X.509 authorities.
    pub fn from_x509_authorities(trust_domain: TrustDomain, authorities: &[Vec<u8>]) -> Bundle {
        let bundle = Bundle::new(trust_domain);
        bundle.set_x509_authorities(authorities);
        bundle
    }

    /// Creates a SPIFFE bundle from JWT authorities.
    pub fn from_jwt_authorities(
        trust_domain: TrustDomain,
        jwt_authorities: &HashMap<String, JwtKey>,
    ) -> Bundle {
        let bundle = Bundle::new(trust_domain);
        bundle.set_jwt_authorities(jwt_authorities);
        bundle
    }

    /// Returns the trust domain of the bundle.
    pub fn trust_domain(&self) -> TrustDomain {
        self.trust_domain.clone()
    }

    /// Returns the X.509 authorities in the bundle, DER encoded.
    pub fn x509_authorities(&self) -> Vec<Vec<u8>> {
        self.x509_authorities
            .read()
            .map(|guard| x509util::copy_x509_authorities(&guard))
            .unwrap_or_default()
    }

    /// Adds an X.509 authority to the bundle.
    pub fn add_x509_authority(&self, authority: &[u8]) {
        if let Ok(mut guard) = self.x509_authorities.write() {
            if guard.iter().any(|cert| cert == authority) {
                return;
            }
            guard.push(authority.to_vec());
        }
    }

    /// Removes an X.509 authority from the bundle.
    pub fn remove_x509_authority(&self, authority: &[u8]) {
        if let Ok(mut guard) = self.x509_authorities.write() {
            if let Some(index) = guard.iter().position(|cert| cert == authority) {
                guard.remove(index);
            }
        }
    }

    /// Returns `true` if the bundle has the given X.509 authority.
    pub fn has_x509_authority(&self, authority: &[u8]) -> bool {
        self.x509_authorities
            .read()
            .map(|guard| guard.iter().any(|cert| cert == authority))
            .unwrap_or(false)
    }

    /// Sets the X.509 authorities in the bundle.
    pub fn set_x509_authorities(&self, authorities: &[Vec<u8>]) {
        if let Ok(mut guard) = self.x509_authorities.write() {
            *guard = x509util::copy_x509_authorities(authorities);
        }
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
        let x509_empty = self
            .x509_authorities
            .read()
            .map(|guard| guard.is_empty())
            .unwrap_or(true);
        let jwt_empty = self
            .jwt_authorities
            .read()
            .map(|guard| guard.is_empty())
            .unwrap_or(true);
        x509_empty && jwt_empty
    }

    /// Returns the refresh hint for the bundle.
    pub fn refresh_hint(&self) -> Option<Duration> {
        self.refresh_hint.read().ok().and_then(|guard| *guard)
    }

    /// Sets the refresh hint for the bundle.
    pub fn set_refresh_hint(&self, refresh_hint: Duration) {
        if let Ok(mut guard) = self.refresh_hint.write() {
            *guard = Some(refresh_hint);
        }
    }

    /// Clears the refresh hint for the bundle.
    pub fn clear_refresh_hint(&self) {
        if let Ok(mut guard) = self.refresh_hint.write() {
            *guard = None;
        }
    }

    /// Returns the sequence number of the bundle.
    pub fn sequence_number(&self) -> Option<u64> {
        self.sequence_number.read().ok().and_then(|guard| *guard)
    }

    /// Sets the sequence number of the bundle.
    pub fn set_sequence_number(&self, sequence_number: u64) {
        if let Ok(mut guard) = self.sequence_number.write() {
            *guard = Some(sequence_number);
        }
    }

    /// Clears the sequence number of the bundle.
    pub fn clear_sequence_number(&self) {
        if let Ok(mut guard) = self.sequence_number.write() {
            *guard = None;
        }
    }

    /// Marshals the bundle to JSON bytes (JWKS).
    pub fn marshal(&self) -> Result<Vec<u8>> {
        let mut keys = Vec::new();
        let refresh_hint = self.refresh_hint();
        let sequence_number = self.sequence_number();

        for cert in self.x509_authorities() {
            let jwk = JwksKey::from_x509_authority(&cert)?;
            keys.push(jwk);
        }
        for (key_id, jwt_key) in self.jwt_authorities() {
            keys.push(JwksKey::from_jwt_key(&key_id, &jwt_key));
        }

        let doc = SpiffeJwks {
            keys,
            spiffe_sequence: sequence_number,
            spiffe_refresh_hint: refresh_hint.map(|hint| {
                let nanos = hint.as_nanos();
                let secs = (nanos + 1_000_000_000 - 1) / 1_000_000_000;
                secs as i64
            }),
        };
        serde_json::to_vec(&doc).map_err(|err| wrap_error(err))
    }

    /// Clones the bundle.
    pub fn clone_bundle(&self) -> Bundle {
        let bundle = Bundle::new(self.trust_domain());
        if let Some(refresh_hint) = self.refresh_hint() {
            bundle.set_refresh_hint(refresh_hint);
        }
        if let Some(sequence_number) = self.sequence_number() {
            bundle.set_sequence_number(sequence_number);
        }
        bundle.set_x509_authorities(&self.x509_authorities());
        bundle.set_jwt_authorities(&self.jwt_authorities());
        bundle
    }

    /// Returns the X.509 bundle view of this bundle.
    pub fn x509_bundle(&self) -> x509bundle::Bundle {
        x509bundle::Bundle::from_x509_authorities(self.trust_domain(), &self.x509_authorities())
    }

    /// Returns the JWT bundle view of this bundle.
    pub fn jwt_bundle(&self) -> jwtbundle::Bundle {
        jwtbundle::Bundle::from_jwt_authorities(self.trust_domain(), &self.jwt_authorities())
    }

    /// Returns the bundle for the given trust domain if it matches.
    pub fn get_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> Result<Bundle> {
        if self.trust_domain != trust_domain {
            return Err(wrap_error(format!(
                "no SPIFFE bundle for trust domain \"{}\"",
                trust_domain
            )));
        }
        Ok(self.clone_bundle())
    }

    /// Returns the X.509 bundle for the given trust domain if it matches.
    pub fn get_x509_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> Result<x509bundle::Bundle> {
        if self.trust_domain != trust_domain {
            return Err(wrap_error(format!(
                "no X.509 bundle for trust domain \"{}\"",
                trust_domain
            )));
        }
        Ok(self.x509_bundle())
    }

    /// Returns the JWT bundle for the given trust domain if it matches.
    pub fn get_jwt_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> Result<jwtbundle::Bundle> {
        if self.trust_domain != trust_domain {
            return Err(wrap_error(format!(
                "no JWT bundle for trust domain \"{}\"",
                trust_domain
            )));
        }
        Ok(self.jwt_bundle())
    }

    /// Returns `true` if this bundle is equal to another bundle.
    pub fn equal(&self, other: &Bundle) -> bool {
        self.trust_domain == other.trust_domain
            && self.refresh_hint() == other.refresh_hint()
            && self.sequence_number() == other.sequence_number()
            && jwtutil::jwt_authorities_equal(&self.jwt_authorities(), &other.jwt_authorities())
            && x509util::certs_equal(&self.x509_authorities(), &other.x509_authorities())
    }
}

/// A source of SPIFFE bundles.
pub trait Source {
    /// Returns the SPIFFE bundle for the given trust domain.
    fn get_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> Result<Bundle>;
}

/// A set of SPIFFE bundles for multiple trust domains.
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

    /// Returns the SPIFFE bundle for the given trust domain.
    pub fn get_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> Result<Bundle> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| wrap_error("bundle store poisoned"))?;
        let bundle = guard.get(&trust_domain).ok_or_else(|| {
            wrap_error(format!(
                "no SPIFFE bundle for trust domain \"{}\"",
                trust_domain
            ))
        })?;
        Ok(bundle.clone_bundle())
    }

    /// Returns the X.509 bundle for the given trust domain.
    pub fn get_x509_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> Result<x509bundle::Bundle> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| wrap_error("bundle store poisoned"))?;
        let bundle = guard.get(&trust_domain).ok_or_else(|| {
            wrap_error(format!(
                "no X.509 bundle for trust domain \"{}\"",
                trust_domain
            ))
        })?;
        Ok(bundle.x509_bundle())
    }

    /// Returns the JWT bundle for the given trust domain.
    pub fn get_jwt_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> Result<jwtbundle::Bundle> {
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
        Ok(bundle.jwt_bundle())
    }
}

impl Source for Set {
    fn get_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> Result<Bundle> {
        self.get_bundle_for_trust_domain(trust_domain)
    }
}

#[derive(Serialize)]
struct SpiffeJwks {
    keys: Vec<JwksKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    spiffe_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    spiffe_refresh_hint: Option<i64>,
}

#[derive(Serialize)]
struct JwksKey {
    #[serde(rename = "use")]
    use_field: String,
    kty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    x5c: Option<Vec<String>>,
}

impl JwksKey {
    fn from_jwt_key(key_id: &str, key: &JwtKey) -> JwksKey {
        match key {
            JwtKey::Ec { crv, x, y } => JwksKey {
                use_field: JWT_SVID_USE.to_string(),
                kty: "EC".to_string(),
                kid: Some(key_id.to_string()),
                crv: Some(crv.clone()),
                x: Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x)),
                y: Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y)),
                n: None,
                e: None,
                x5c: None,
            },
            JwtKey::Rsa { n, e } => JwksKey {
                use_field: JWT_SVID_USE.to_string(),
                kty: "RSA".to_string(),
                kid: Some(key_id.to_string()),
                crv: None,
                x: None,
                y: None,
                n: Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(n)),
                e: Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(e)),
                x5c: None,
            },
        }
    }

    fn from_x509_authority(cert: &[u8]) -> Result<JwksKey> {
        let cert_bytes = cert;
        let (_rest, parsed) =
            x509_parser::parse_x509_certificate(cert_bytes).map_err(|err| wrap_error(err))?;
        let (crv, x, y) = ec_public_key_parameters(&parsed)?;
        let x5c = vec![base64::engine::general_purpose::STANDARD.encode(cert_bytes)];
        Ok(JwksKey {
            use_field: X509_SVID_USE.to_string(),
            kty: "EC".to_string(),
            kid: None,
            crv: Some(crv),
            x: Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x)),
            y: Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y)),
            n: None,
            e: None,
            x5c: Some(x5c),
        })
    }
}

fn ec_public_key_parameters(cert: &X509Certificate<'_>) -> Result<(String, Vec<u8>, Vec<u8>)> {
    let alg = &cert.tbs_certificate.subject_pki.algorithm.algorithm;
    let crv = if alg == &OID_KEY_TYPE_EC_PUBLIC_KEY {
        let params = cert
            .tbs_certificate
            .subject_pki
            .algorithm
            .parameters
            .as_ref()
            .ok_or_else(|| wrap_error("missing EC parameters"))?;
        let oid = params.as_oid().map_err(|_| wrap_error("invalid EC parameters"))?;
        if oid == OID_EC_P256 {
            "P-256".to_string()
        } else if oid == OID_NIST_EC_P384 {
            "P-384".to_string()
        } else if oid == OID_NIST_EC_P521 {
            "P-521".to_string()
        } else {
            return Err(wrap_error("unsupported EC curve"));
        }
    } else {
        return Err(wrap_error("unsupported public key algorithm"));
    };

    let spk = cert
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .as_ref();
    if spk.is_empty() || spk[0] != 0x04 {
        return Err(wrap_error("unsupported EC public key encoding"));
    }
    let coord_len = (spk.len() - 1) / 2;
    let x = spk[1..1 + coord_len].to_vec();
    let y = spk[1 + coord_len..].to_vec();
    Ok((crv, x, y))
}
