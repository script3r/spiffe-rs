use crate::bundle::x509bundle;
use crate::internal::pemutil;
use crate::spiffeid::ID;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use std::fs;
use std::time::SystemTime;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::X509Certificate;
use x509_parser::time::ASN1Time;

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

fn wrap_error(message: impl std::fmt::Display) -> Error {
    Error(format!("x509svid: {}", message))
}

/// An X.509 SVID (SPIFFE Verifiable Identity Document).
///
/// It consists of an X.509 certificate chain and a private key.
#[derive(Debug, Clone)]
pub struct SVID {
    /// The SPIFFE ID of the SVID.
    pub id: ID,
    /// The X.509 certificate chain, DER encoded.
    pub certificates: Vec<Vec<u8>>,
    /// The private key, DER encoded.
    pub private_key: Vec<u8>,
    /// An optional hint for the SVID.
    pub hint: String,
}

impl SVID {
    /// Loads an X.509 SVID from PEM encoded files.
    pub fn load(cert_file: &str, key_file: &str) -> Result<SVID> {
        let cert_bytes = fs::read(cert_file)
            .map_err(|err| wrap_error(format!("cannot read certificate file: {}", err)))?;
        let key_bytes =
            fs::read(key_file).map_err(|err| wrap_error(format!("cannot read key file: {}", err)))?;
        SVID::parse(&cert_bytes, &key_bytes)
    }

    /// Parses an X.509 SVID from PEM encoded bytes.
    pub fn parse(cert_bytes: &[u8], key_bytes: &[u8]) -> Result<SVID> {
        let certs =
            pemutil::parse_certificates(cert_bytes).map_err(|err| {
                wrap_error(format!("cannot parse PEM encoded certificate: {}", err))
            })?;
        let key = parse_private_key_pem(key_bytes)
            .map_err(|err| wrap_error(format!("cannot parse PEM encoded private key: {}", err)))?;
        new_svid(certs, key)
    }

    /// Parses an X.509 SVID from DER encoded bytes.
    pub fn parse_raw(cert_bytes: &[u8], key_bytes: &[u8]) -> Result<SVID> {
        let certs = parse_raw_certificates(cert_bytes)
            .map_err(|err| wrap_error(format!("cannot parse DER encoded certificate: {}", err)))?;
        let key = parse_private_key_der(key_bytes)
            .map_err(|err| wrap_error(format!("cannot parse DER encoded private key: {}", err)))?;
        new_svid(certs, key)
    }

    /// Marshals the SVID to PEM encoded bytes.
    pub fn marshal(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        if self.certificates.is_empty() {
            return Err(wrap_error("no certificates to marshal"));
        }
        if self.private_key.is_empty() {
            return Err(wrap_error("cannot encode private key: missing private key"));
        }
        let cert_bytes = pemutil::encode_certificates(&self.certificates);
        let key_bytes = pem::encode(&pem::Pem::new("PRIVATE KEY", self.private_key.clone()))
            .as_bytes()
            .to_vec();
        Ok((cert_bytes, key_bytes))
    }

    /// Marshals the SVID to DER encoded bytes.
    pub fn marshal_raw(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        if self.certificates.is_empty() {
            return Err(wrap_error("no certificates to marshal"));
        }
        if self.private_key.is_empty() {
            return Err(wrap_error("cannot marshal private key: missing private key"));
        }
        let mut certs = Vec::new();
        for cert in &self.certificates {
            certs.extend_from_slice(cert);
        }
        Ok((certs, self.private_key.clone()))
    }

    /// Returns the SVID itself (satisfies `Source` trait).
    pub fn get_x509_svid(&self) -> Result<SVID> {
        Ok(self.clone())
    }
}

/// A source of X.509 SVIDs.
pub trait Source {
    /// Returns an X.509 SVID.
    fn get_x509_svid(&self) -> Result<SVID>;
}

pub trait VerifyOption {
    fn apply(&self, config: &mut VerifyConfig);
}

pub struct VerifyConfig {
    now: Option<SystemTime>,
}

pub struct WithTime(SystemTime);

impl WithTime {
    pub fn new(now: SystemTime) -> Self {
        Self(now)
    }
}

impl VerifyOption for WithTime {
    fn apply(&self, config: &mut VerifyConfig) {
        config.now = Some(self.0);
    }
}

pub fn verify(
    certs: &[Vec<u8>],
    bundle_source: &dyn x509bundle::Source,
    opts: &[Box<dyn VerifyOption>],
) -> Result<(ID, Vec<Vec<Vec<u8>>>)> {
    let mut config = VerifyConfig { now: None };
    for opt in opts {
        opt.apply(&mut config);
    }
    if certs.is_empty() {
        return Err(wrap_error("empty certificates chain"));
    }

    let leaf = parse_certificate(&certs[0])?;
    let id = id_from_cert(&leaf)
        .map_err(|err| wrap_error(format!("could not get leaf SPIFFE ID: {}", err)))?;

    if leaf.is_ca() {
        return Err(wrap_error("leaf certificate with CA flag set to true"));
    }
    validate_leaf_key_usage(&leaf)?;

    let bundle = bundle_source
        .get_x509_bundle_for_trust_domain(id.trust_domain())
        .map_err(|err| wrap_error(format!("could not get X509 bundle: {}", err)))?;

    verify_chain(certs, &bundle, config.now)
        .map_err(|err| wrap_error(format!("could not verify leaf certificate: {}", err)))?;

    Ok((id, vec![certs.to_vec()]))
}

pub fn parse_and_verify(
    raw_certs: &[Vec<u8>],
    bundle_source: &dyn x509bundle::Source,
    opts: &[Box<dyn VerifyOption>],
) -> Result<(ID, Vec<Vec<Vec<u8>>>)> {
    let mut certs = Vec::new();
    for raw in raw_certs {
        parse_certificate(raw)
            .map_err(|err| wrap_error(format!("unable to parse certificate: {}", err)))?;
        certs.push(raw.clone());
    }
    verify(&certs, bundle_source, opts)
}

fn new_svid(certs: Vec<Vec<u8>>, key_der: Vec<u8>) -> Result<SVID> {
    let id = validate_certificates(&certs)
        .map_err(|err| wrap_error(format!("certificate validation failed: {}", err)))?;
    validate_private_key(&key_der, &certs[0])
        .map_err(|err| wrap_error(format!("private key validation failed: {}", err)))?;
    Ok(SVID {
        id,
        certificates: certs,
        private_key: key_der,
        hint: String::new(),
    })
}

fn validate_certificates(certs: &[Vec<u8>]) -> Result<ID> {
    if certs.is_empty() {
        return Err(Error("no certificates found".to_string()));
    }
    let leaf = parse_certificate(&certs[0])?;
    let leaf_id = id_from_cert(&leaf)
        .map_err(|err| Error(format!("cannot get leaf certificate SPIFFE ID: {}", err)))?;

    if leaf.is_ca() {
        return Err(Error(
            "leaf certificate must not have CA flag set to true".to_string(),
        ));
    }
    validate_leaf_key_usage(&leaf)
        .map_err(|err| Error(err.to_string()))?;

    for cert_bytes in certs.iter().skip(1) {
        let cert = parse_certificate(cert_bytes)?;
        if !cert.is_ca() {
            return Err(Error(
                "signing certificate must have CA flag set to true".to_string(),
            ));
        }
        let key_usage = cert
            .key_usage()
            .map_err(|_| Error("signing certificate invalid key usage".to_string()))?;
        let flags = key_usage.map(|ext| ext.value).map(|ku| ku.key_cert_sign());
        if flags != Some(true) {
            return Err(Error(
                "signing certificate must have 'keyCertSign' set as key usage".to_string(),
            ));
        }
    }

    Ok(leaf_id)
}

fn validate_leaf_key_usage(cert: &X509Certificate<'_>) -> Result<()> {
    let key_usage = cert
        .key_usage()
        .map_err(|_| Error("certificate has invalid key usage".to_string()))?;
    let flags = key_usage.map(|ext| ext.value);
    let digital = flags.map(|ku| ku.digital_signature()).unwrap_or(false);
    let cert_sign = flags.map(|ku| ku.key_cert_sign()).unwrap_or(false);
    let crl_sign = flags.map(|ku| ku.crl_sign()).unwrap_or(false);
    if !digital {
        return Err(Error(
            "leaf certificate must have 'digitalSignature' set as key usage".to_string(),
        ));
    }
    if cert_sign {
        return Err(Error(
            "leaf certificate must not have 'keyCertSign' set as key usage".to_string(),
        ));
    }
    if crl_sign {
        return Err(Error(
            "leaf certificate must not have 'cRLSign' set as key usage".to_string(),
        ));
    }
    Ok(())
}

fn id_from_cert(cert: &X509Certificate<'_>) -> Result<ID> {
    let san = cert
        .subject_alternative_name()
        .map_err(|_| Error("certificate contains invalid URI SAN".to_string()))?
        .ok_or_else(|| Error("certificate contains no URI SAN".to_string()))?;
    let mut uris = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::URI(uri) => Some(*uri),
            _ => None,
        })
        .collect::<Vec<_>>();
    if uris.is_empty() {
        return Err(Error("certificate contains no URI SAN".to_string()));
    }
    if uris.len() > 1 {
        return Err(Error("certificate contains more than one URI SAN".to_string()));
    }
    ID::from_string(uris.remove(0)).map_err(|err| Error(err.to_string()))
}

fn parse_certificate(cert_bytes: &[u8]) -> Result<X509Certificate<'_>> {
    let (_rest, cert) =
        x509_parser::parse_x509_certificate(cert_bytes).map_err(|err| Error(err.to_string()))?;
    Ok(cert)
}

fn parse_raw_certificates(bytes: &[u8]) -> std::result::Result<Vec<Vec<u8>>, String> {
    let mut remaining = bytes;
    let mut certs = Vec::new();
    while !remaining.is_empty() {
        let (rest, _cert) = x509_parser::parse_x509_certificate(remaining)
            .map_err(|err| err.to_string())?;
        let consumed = remaining
            .len()
            .checked_sub(rest.len())
            .ok_or_else(|| "invalid certificate length".to_string())?;
        certs.push(remaining[..consumed].to_vec());
        remaining = rest;
    }
    Ok(certs)
}

fn parse_private_key_pem(key_bytes: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let pems = pem::parse_many(key_bytes).map_err(|_| "no PEM blocks found".to_string())?;
    for pem in pems {
        if pem.tag() == "PRIVATE KEY" {
            return Ok(pem.contents().to_vec());
        }
    }
    Err("no PEM blocks found".to_string())
}

fn parse_private_key_der(key_bytes: &[u8]) -> std::result::Result<Vec<u8>, String> {
    if key_bytes.is_empty() {
        return Err("no private key found".to_string());
    }
    Ok(key_bytes.to_vec())
}

fn validate_private_key(key_bytes: &[u8], cert_bytes: &[u8]) -> Result<()> {
    if key_bytes.is_empty() {
        return Err(Error("no private key found".to_string()));
    }
    let cert = parse_certificate(cert_bytes)?;
    let public_key = cert
        .public_key()
        .parsed()
        .map_err(|_| Error("unsupported public key type".to_string()))?;

    if let Ok(private_key) = RsaPrivateKey::from_pkcs8_der(key_bytes) {
        let pub_key = private_key.to_public_key();
        let modulus = pub_key.n().to_bytes_be();
        let exponent = pub_key.e().to_bytes_be();
        if let x509_parser::public_key::PublicKey::RSA(rsa) = public_key {
            let n = normalize_bigint(rsa.modulus);
            let e = normalize_bigint(rsa.exponent);
            if n == modulus && e == exponent {
                return Ok(());
            }
            return Err(Error("leaf certificate does not match private key".to_string()));
        }
    }

    if let Ok(secret) = p256::SecretKey::from_pkcs8_der(key_bytes) {
        let pub_key = secret.public_key();
        let bytes = pub_key.to_encoded_point(false).as_bytes().to_vec();
        if let x509_parser::public_key::PublicKey::EC(ec) = public_key {
            if bytes == ec.data() {
                return Ok(());
            }
            return Err(Error("leaf certificate does not match private key".to_string()));
        }
    }

    if let Ok(secret) = p384::SecretKey::from_pkcs8_der(key_bytes) {
        let pub_key = secret.public_key();
        let bytes = pub_key.to_encoded_point(false).as_bytes().to_vec();
        if let x509_parser::public_key::PublicKey::EC(ec) = public_key {
            if bytes == ec.data() {
                return Ok(());
            }
            return Err(Error("leaf certificate does not match private key".to_string()));
        }
    }

    if let Ok(secret) = p521::SecretKey::from_pkcs8_der(key_bytes) {
        let pub_key = secret.public_key();
        let bytes = pub_key.to_encoded_point(false).as_bytes().to_vec();
        if let x509_parser::public_key::PublicKey::EC(ec) = public_key {
            if bytes == ec.data() {
                return Ok(());
            }
            return Err(Error("leaf certificate does not match private key".to_string()));
        }
    }

    Err(Error("unsupported private key type".to_string()))
}

fn normalize_bigint(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    while out.first() == Some(&0u8) && out.len() > 1 {
        out.remove(0);
    }
    out
}

fn verify_chain(
    certs: &[Vec<u8>],
    bundle: &x509bundle::Bundle,
    now: Option<SystemTime>,
) -> std::result::Result<(), String> {
    let now = now.unwrap_or_else(SystemTime::now);
    let now = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| "invalid time".to_string())?;
    let now = ASN1Time::from_timestamp(now.as_secs() as i64).map_err(|_| "invalid time".to_string())?;

    let parsed = certs
        .iter()
        .map(|cert| parse_certificate(cert).map_err(|err| err.to_string()))
        .collect::<std::result::Result<Vec<_>, _>>()?;

    for cert in &parsed {
        if !cert.validity().is_valid_at(now) {
            return Err("certificate has expired".to_string());
        }
    }

    let roots = bundle.x509_authorities();
    if roots.is_empty() {
        return Err("certificate signed by unknown authority".to_string());
    }

    if certs.len() == 1 {
        for root in roots {
            let root_cert = parse_certificate(&root).map_err(|err| err.to_string())?;
            if parsed[0]
                .verify_signature(Some(&root_cert.tbs_certificate.subject_pki))
                .is_ok()
            {
                return Ok(());
            }
        }
        return Err("certificate signed by unknown authority".to_string());
    }

    for idx in 0..parsed.len() - 1 {
        let issuer = &parsed[idx + 1];
        parsed[idx]
            .verify_signature(Some(&issuer.tbs_certificate.subject_pki))
            .map_err(|_| "certificate signed by unknown authority".to_string())?;
    }

    let last = parsed.last().ok_or_else(|| "empty chain".to_string())?;
    for root in roots {
        let root_cert = parse_certificate(&root).map_err(|err| err.to_string())?;
        if last
            .verify_signature(Some(&root_cert.tbs_certificate.subject_pki))
            .is_ok()
        {
            return Ok(());
        }
    }

    Err("certificate signed by unknown authority".to_string())
}
