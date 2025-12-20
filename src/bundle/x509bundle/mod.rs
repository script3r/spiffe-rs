use crate::internal::pemutil;
use crate::internal::x509util;
use crate::spiffeid::TrustDomain;
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

fn wrap_error(message: impl std::fmt::Display) -> Error {
    Error(format!("x509bundle: {}", message))
}

#[derive(Debug)]
pub struct Bundle {
    trust_domain: TrustDomain,
    x509_authorities: RwLock<Vec<Vec<u8>>>,
}

impl Bundle {
    pub fn new(trust_domain: TrustDomain) -> Bundle {
        Bundle {
            trust_domain,
            x509_authorities: RwLock::new(Vec::new()),
        }
    }

    pub fn from_x509_authorities(trust_domain: TrustDomain, authorities: &[Vec<u8>]) -> Bundle {
        Bundle {
            trust_domain,
            x509_authorities: RwLock::new(x509util::copy_x509_authorities(authorities)),
        }
    }

    pub fn load(trust_domain: TrustDomain, path: &str) -> Result<Bundle> {
        let bytes = fs::read(path)
            .map_err(|err| wrap_error(format!("unable to load X.509 bundle file: {}", err)))?;
        Bundle::parse(trust_domain, &bytes)
    }

    pub fn read(trust_domain: TrustDomain, reader: &mut dyn Read) -> Result<Bundle> {
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .map_err(|err| wrap_error(format!("unable to read X.509 bundle: {}", err)))?;
        Bundle::parse(trust_domain, &bytes)
    }

    pub fn parse(trust_domain: TrustDomain, bytes: &[u8]) -> Result<Bundle> {
        let bundle = Bundle::new(trust_domain);
        if bytes.is_empty() {
            return Ok(bundle);
        }
        let certs = pemutil::parse_certificates(bytes)
            .map_err(|err| wrap_error(format!("cannot parse certificate: {}", err)))?;
        for cert in certs {
            bundle.add_x509_authority(&cert);
        }
        Ok(bundle)
    }

    pub fn parse_raw(trust_domain: TrustDomain, bytes: &[u8]) -> Result<Bundle> {
        let bundle = Bundle::new(trust_domain);
        if bytes.is_empty() {
            return Ok(bundle);
        }
        let certs = parse_raw_certificates(bytes)
            .map_err(|err| wrap_error(format!("cannot parse certificate: {}", err)))?;
        for cert in certs {
            bundle.add_x509_authority(&cert);
        }
        Ok(bundle)
    }

    pub fn trust_domain(&self) -> TrustDomain {
        self.trust_domain.clone()
    }

    pub fn x509_authorities(&self) -> Vec<Vec<u8>> {
        self.x509_authorities
            .read()
            .map(|guard| x509util::copy_x509_authorities(&guard))
            .unwrap_or_default()
    }

    pub fn add_x509_authority(&self, authority: &[u8]) {
        if let Ok(mut guard) = self.x509_authorities.write() {
            if guard.iter().any(|cert| cert == authority) {
                return;
            }
            guard.push(authority.to_vec());
        }
    }

    pub fn remove_x509_authority(&self, authority: &[u8]) {
        if let Ok(mut guard) = self.x509_authorities.write() {
            if let Some(index) = guard.iter().position(|cert| cert == authority) {
                guard.remove(index);
            }
        }
    }

    pub fn has_x509_authority(&self, authority: &[u8]) -> bool {
        self.x509_authorities
            .read()
            .map(|guard| guard.iter().any(|cert| cert == authority))
            .unwrap_or(false)
    }

    pub fn set_x509_authorities(&self, authorities: &[Vec<u8>]) {
        if let Ok(mut guard) = self.x509_authorities.write() {
            *guard = x509util::copy_x509_authorities(authorities);
        }
    }

    pub fn empty(&self) -> bool {
        self.x509_authorities
            .read()
            .map(|guard| guard.is_empty())
            .unwrap_or(true)
    }

    pub fn marshal(&self) -> Result<Vec<u8>> {
        let certs = self.x509_authorities();
        Ok(pemutil::encode_certificates(&certs))
    }

    pub fn equal(&self, other: &Bundle) -> bool {
        self.trust_domain == other.trust_domain
            && x509util::certs_equal(&self.x509_authorities(), &other.x509_authorities())
    }

    pub fn clone_bundle(&self) -> Bundle {
        Bundle::from_x509_authorities(self.trust_domain(), &self.x509_authorities())
    }

    pub fn get_x509_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> Result<Bundle> {
        if self.trust_domain != trust_domain {
            return Err(wrap_error(format!(
                "no X.509 bundle found for trust domain: \"{}\"",
                trust_domain
            )));
        }
        Ok(self.clone_bundle())
    }
}

pub trait Source {
    fn get_x509_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> Result<Bundle>;
}

#[derive(Debug)]
pub struct Set {
    bundles: RwLock<HashMap<TrustDomain, Bundle>>,
}

impl Set {
    pub fn new(bundles: &[Bundle]) -> Set {
        let mut map = HashMap::new();
        for bundle in bundles {
            map.insert(bundle.trust_domain(), bundle.clone_bundle());
        }
        Set {
            bundles: RwLock::new(map),
        }
    }

    pub fn add(&self, bundle: &Bundle) {
        if let Ok(mut guard) = self.bundles.write() {
            guard.insert(bundle.trust_domain(), bundle.clone_bundle());
        }
    }

    pub fn remove(&self, trust_domain: TrustDomain) {
        if let Ok(mut guard) = self.bundles.write() {
            guard.remove(&trust_domain);
        }
    }

    pub fn has(&self, trust_domain: TrustDomain) -> bool {
        self.bundles
            .read()
            .map(|guard| guard.contains_key(&trust_domain))
            .unwrap_or(false)
    }

    pub fn get(&self, trust_domain: TrustDomain) -> Option<Bundle> {
        self.bundles
            .read()
            .ok()
            .and_then(|guard| guard.get(&trust_domain).map(|b| b.clone_bundle()))
    }

    pub fn bundles(&self) -> Vec<Bundle> {
        let mut bundles = self
            .bundles
            .read()
            .map(|guard| guard.values().map(|b| b.clone_bundle()).collect::<Vec<_>>())
            .unwrap_or_default();
        bundles.sort_by(|a, b| a.trust_domain().compare(&b.trust_domain()));
        bundles
    }

    pub fn len(&self) -> usize {
        self.bundles.read().map(|guard| guard.len()).unwrap_or(0)
    }

    pub fn get_x509_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> Result<Bundle> {
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
        Ok(bundle.clone_bundle())
    }
}

impl Source for Set {
    fn get_x509_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> Result<Bundle> {
        self.get_x509_bundle_for_trust_domain(trust_domain)
    }
}

impl Source for Bundle {
    fn get_x509_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> Result<Bundle> {
        self.get_x509_bundle_for_trust_domain(trust_domain)
    }
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
