use crate::bundle::jwtbundle;
use crate::bundle::jwtbundle::JwtKey;
use crate::spiffeid::ID;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::{
    signature::Verifier, Signature as P256Signature, VerifyingKey as P256VerifyingKey,
};
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
use p521::ecdsa::{Signature as P521Signature, VerifyingKey as P521VerifyingKey};
use pkcs8::AssociatedOid;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
use rsa::pss::{Signature as RsaPssSignature, VerifyingKey as RsaPssVerifyingKey};
use rsa::signature::digest::FixedOutputReset;
use rsa::RsaPublicKey;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone)]
pub struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

fn wrap_error(message: impl std::fmt::Display) -> Error {
    Error(format!("jwtsvid: {}", message))
}

/// A JWT SVID (SPIFFE Verifiable Identity Document).
///
/// It consists of a JWT token and its parsed claims.
#[derive(Debug, Clone)]
pub struct SVID {
    /// The SPIFFE ID of the SVID.
    pub id: ID,
    /// The audience the SVID is intended for.
    pub audience: Vec<String>,
    /// The expiry time of the SVID.
    pub expiry: SystemTime,
    /// The claims contained in the JWT SVID.
    pub claims: HashMap<String, Value>,
    /// An optional hint for the SVID.
    pub hint: String,
    token: String,
}

/// Parameters for issuing a JWT SVID.
#[derive(Debug, Clone)]
pub struct Params {
    /// The subject SPIFFE ID.
    pub subject: ID,
    /// The primary audience.
    pub audience: String,
    /// Additional audiences.
    pub extra_audiences: Vec<String>,
}

impl Params {
    /// Creates a new `Params` with a subject and primary audience.
    pub fn new(subject: ID, audience: impl Into<String>) -> Self {
        Self {
            subject,
            audience: audience.into(),
            extra_audiences: Vec::new(),
        }
    }

    /// Adds an extra audience to the parameters.
    pub fn with_extra_audience(mut self, audience: impl Into<String>) -> Self {
        self.extra_audiences.push(audience.into());
        self
    }

    /// Returns the full list of audiences.
    pub fn audience_list(&self) -> Vec<String> {
        let mut audiences = Vec::with_capacity(1 + self.extra_audiences.len());
        audiences.push(self.audience.clone());
        audiences.extend(self.extra_audiences.clone());
        audiences
    }
}

impl SVID {
    /// Returns the JWT token string.
    pub fn marshal(&self) -> String {
        self.token.clone()
    }
}

/// Parses and validates a JWT SVID token.
///
/// It uses the provided bundle source to verify the token signature and checks
/// the audience claim.
pub fn parse_and_validate(
    token: &str,
    bundles: &dyn jwtbundle::Source,
    audience: &[String],
) -> Result<SVID> {
    parse(
        token,
        audience,
        |header, signing_input, signature, trust_domain| {
            let key_id = header
                .kid
                .as_deref()
                .ok_or_else(|| wrap_error("token header missing key id"))?;
            let bundle = bundles
                .get_jwt_bundle_for_trust_domain(trust_domain.clone())
                .map_err(|_| {
                    wrap_error(format!(
                        "no bundle found for trust domain \"{}\"",
                        trust_domain
                    ))
                })?;
            let authority = bundle.find_jwt_authority(key_id).ok_or_else(|| {
                wrap_error(format!(
                    "no JWT authority \"{}\" found for trust domain \"{}\"",
                    key_id, trust_domain
                ))
            })?;
            verify_signature(&header.alg, &authority, signing_input, signature).map_err(|_| {
            wrap_error("unable to get claims from token: go-jose/go-jose: error in cryptographic primitive")
        })?;
            Ok(())
        },
    )
}

/// Parses a JWT SVID token without validating its signature.
///
/// **WARNING**: This should only be used if the token has already been validated
/// by other means.
pub fn parse_insecure(token: &str, audience: &[String]) -> Result<SVID> {
    parse(
        token,
        audience,
        |_header, _signing_input, _signature, _td| Ok(()),
    )
}

fn parse<F>(token: &str, audience: &[String], verify: F) -> Result<SVID>
where
    F: Fn(&Header, &str, &[u8], &crate::spiffeid::TrustDomain) -> Result<()>,
{
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(wrap_error("unable to parse JWT token"));
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0].as_bytes())
        .map_err(|_| wrap_error("unable to parse JWT token"))?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1].as_bytes())
        .map_err(|_| wrap_error("unable to parse JWT token"))?;
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2].as_bytes())
        .map_err(|_| wrap_error("unable to parse JWT token"))?;

    let header: Header = serde_json::from_slice(&header_bytes)
        .map_err(|_| wrap_error("unable to parse JWT token"))?;

    if !is_allowed_alg(&header.alg) {
        return Err(wrap_error("unable to parse JWT token"));
    }
    if let Some(typ) = header.typ.as_deref() {
        if typ != "JWT" && typ != "JOSE" {
            return Err(wrap_error(
                "token header type not equal to either JWT or JOSE",
            ));
        }
    }

    let claims: Map<String, Value> = serde_json::from_slice(&payload_bytes)
        .map_err(|_| wrap_error("unable to parse JWT token"))?;
    let subject = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| wrap_error("token missing subject claim"))?;
    let expiry = claims
        .get("exp")
        .and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|v| v as i64)))
        .ok_or_else(|| wrap_error("token missing exp claim"))?;
    let aud = extract_audience(&claims);

    let id = ID::from_string(subject)
        .map_err(|err| wrap_error(format!("token has an invalid subject claim: {}", err)))?;

    let trust_domain = id.trust_domain();
    verify(
        &header,
        &format!("{}.{}", parts[0], parts[1]),
        &signature,
        &trust_domain,
    )?;

    validate_claims(expiry, &aud, audience)?;

    Ok(SVID {
        id,
        audience: aud,
        expiry: SystemTime::UNIX_EPOCH + Duration::from_secs(expiry as u64),
        claims: claims.into_iter().collect::<HashMap<_, _>>(),
        hint: String::new(),
        token: token.to_string(),
    })
}

fn validate_claims(expiry: i64, audience: &[String], expected: &[String]) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| wrap_error("token has expired"))?
        .as_secs() as i64;
    if expiry <= now {
        return Err(wrap_error("token has expired"));
    }
    if !expected.is_empty() && !expected.iter().any(|a| audience.contains(a)) {
        return Err(wrap_error(format!(
            "expected audience in {:?} (audience={:?})",
            expected, audience
        )));
    }
    Ok(())
}

fn extract_audience(claims: &Map<String, Value>) -> Vec<String> {
    match claims.get("aud") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

fn is_allowed_alg(alg: &str) -> bool {
    matches!(
        alg,
        "RS256" | "RS384" | "RS512" | "ES256" | "ES384" | "ES512" | "PS256" | "PS384" | "PS512"
    )
}

fn verify_signature(alg: &str, key: &JwtKey, signing_input: &str, signature: &[u8]) -> Result<()> {
    match (alg, key) {
        ("RS256", JwtKey::Rsa { n, e }) => {
            verify_rsa_pkcs1::<Sha256>(n, e, signing_input, signature)
        }
        ("RS384", JwtKey::Rsa { n, e }) => {
            verify_rsa_pkcs1::<Sha384>(n, e, signing_input, signature)
        }
        ("RS512", JwtKey::Rsa { n, e }) => {
            verify_rsa_pkcs1::<Sha512>(n, e, signing_input, signature)
        }
        ("PS256", JwtKey::Rsa { n, e }) => verify_rsa_pss::<Sha256>(n, e, signing_input, signature),
        ("PS384", JwtKey::Rsa { n, e }) => verify_rsa_pss::<Sha384>(n, e, signing_input, signature),
        ("PS512", JwtKey::Rsa { n, e }) => verify_rsa_pss::<Sha512>(n, e, signing_input, signature),
        ("ES256", JwtKey::Ec { x, y, .. }) => verify_ecdsa_p256(x, y, signing_input, signature),
        ("ES384", JwtKey::Ec { x, y, .. }) => verify_ecdsa_p384(x, y, signing_input, signature),
        ("ES512", JwtKey::Ec { x, y, .. }) => verify_ecdsa_p521(x, y, signing_input, signature),
        _ => Err(wrap_error("unable to parse JWT token")),
    }
}

fn verify_rsa_pkcs1<D>(n: &[u8], e: &[u8], signing_input: &str, signature: &[u8]) -> Result<()>
where
    D: Digest + AssociatedOid,
{
    let public_key = rsa_public_key(n, e)?;
    let verifying_key = RsaVerifyingKey::<D>::new(public_key);
    let sig = RsaSignature::try_from(signature).map_err(|_| wrap_error("invalid signature"))?;
    verifying_key
        .verify(signing_input.as_bytes(), &sig)
        .map_err(|_| wrap_error("invalid signature"))?;
    Ok(())
}

fn verify_rsa_pss<D>(n: &[u8], e: &[u8], signing_input: &str, signature: &[u8]) -> Result<()>
where
    D: Digest + FixedOutputReset,
{
    let public_key = rsa_public_key(n, e)?;
    let verifying_key = RsaPssVerifyingKey::<D>::new(public_key);
    let sig = RsaPssSignature::try_from(signature).map_err(|_| wrap_error("invalid signature"))?;
    verifying_key
        .verify(signing_input.as_bytes(), &sig)
        .map_err(|_| wrap_error("invalid signature"))?;
    Ok(())
}

fn rsa_public_key(n: &[u8], e: &[u8]) -> Result<RsaPublicKey> {
    let n = rsa::BigUint::from_bytes_be(n);
    let e = rsa::BigUint::from_bytes_be(e);
    RsaPublicKey::new(n, e).map_err(|_| wrap_error("invalid RSA key"))
}

fn verify_ecdsa_p256(x: &[u8], y: &[u8], signing_input: &str, signature: &[u8]) -> Result<()> {
    let public_key = ecdsa_public_key(x, y)?;
    let key =
        P256VerifyingKey::from_sec1_bytes(&public_key).map_err(|_| wrap_error("invalid EC key"))?;
    let sig = P256Signature::from_slice(signature).map_err(|_| wrap_error("invalid signature"))?;
    key.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| wrap_error("invalid signature"))?;
    Ok(())
}

fn verify_ecdsa_p384(x: &[u8], y: &[u8], signing_input: &str, signature: &[u8]) -> Result<()> {
    let public_key = ecdsa_public_key(x, y)?;
    let key =
        P384VerifyingKey::from_sec1_bytes(&public_key).map_err(|_| wrap_error("invalid EC key"))?;
    let sig = P384Signature::from_slice(signature).map_err(|_| wrap_error("invalid signature"))?;
    key.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| wrap_error("invalid signature"))?;
    Ok(())
}

fn verify_ecdsa_p521(x: &[u8], y: &[u8], signing_input: &str, signature: &[u8]) -> Result<()> {
    let public_key = ecdsa_public_key(x, y)?;
    let key =
        P521VerifyingKey::from_sec1_bytes(&public_key).map_err(|_| wrap_error("invalid EC key"))?;
    let sig = P521Signature::from_slice(signature).map_err(|_| wrap_error("invalid signature"))?;
    key.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| wrap_error("invalid signature"))?;
    Ok(())
}

fn ecdsa_public_key(x: &[u8], y: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + x.len() + y.len());
    out.push(0x04);
    out.extend_from_slice(x);
    out.extend_from_slice(y);
    Ok(out)
}

#[derive(Debug, serde::Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(rename = "typ")]
    #[serde(default)]
    typ: Option<String>,
}
