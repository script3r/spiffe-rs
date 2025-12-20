use crate::bundle::x509bundle;
use crate::spiffeid;
use crate::spiffeid::ID;
use crate::svid::x509svid;
use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::server::{ClientCertVerified, ClientCertVerifier};
use rustls::{Certificate, ClientConfig, Error as RustlsError, PrivateKey, RootCertStore, ServerConfig};
use std::sync::Arc;

pub type Authorizer =
    Arc<dyn Fn(&ID, &[Vec<Vec<u8>>]) -> std::result::Result<(), super::Error> + Send + Sync>;

#[derive(Clone, Default)]
pub struct Trace;

#[derive(Clone)]
pub struct TlsOption {
    _trace: std::option::Option<Trace>,
}

impl TlsOption {
    pub fn with_trace(trace: Trace) -> Self {
        Self { _trace: std::option::Option::Some(trace) }
    }
}

#[derive(Clone)]
pub struct WebCert {
    pub certs: Vec<Certificate>,
    pub key: PrivateKey,
}

pub fn authorize_any() -> Authorizer {
    adapt_matcher(spiffeid::match_any())
}

pub fn authorize_id(allowed: ID) -> Authorizer {
    adapt_matcher(spiffeid::match_id(allowed))
}

pub fn authorize_one_of(allowed: &[ID]) -> Authorizer {
    adapt_matcher(spiffeid::match_one_of(allowed))
}

pub fn authorize_member_of(allowed: spiffeid::TrustDomain) -> Authorizer {
    adapt_matcher(spiffeid::match_member_of(allowed))
}

pub fn adapt_matcher(matcher: spiffeid::Matcher) -> Authorizer {
    Arc::new(move |actual, _chains| {
        matcher(actual).map_err(|err| super::wrap_error(err))
    })
}

pub fn tls_client_config(
    bundle_source: Arc<dyn x509bundle::Source + Send + Sync>,
    authorizer: Authorizer,
) -> super::Result<ClientConfig> {
    let verifier = Arc::new(SpiffeServerVerifier::new(bundle_source, authorizer));
    Ok(ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

pub fn mtls_client_config(
    svid_source: &dyn x509svid::Source,
    bundle_source: Arc<dyn x509bundle::Source + Send + Sync>,
    authorizer: Authorizer,
) -> super::Result<ClientConfig> {
    let (certs, key) = svid_to_rustls(svid_source)?;
    let verifier = Arc::new(SpiffeServerVerifier::new(bundle_source, authorizer));
    ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(certs, key)
        .map_err(|err| super::wrap_error(format!("unable to set client auth cert: {}", err)))
}

pub fn mtls_server_config(
    svid_source: &dyn x509svid::Source,
    bundle_source: Arc<dyn x509bundle::Source + Send + Sync>,
    authorizer: Authorizer,
) -> super::Result<ServerConfig> {
    let (certs, key) = svid_to_rustls(svid_source)?;
    let verifier = Arc::new(SpiffeClientVerifier::new(bundle_source, authorizer));
    ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|err| super::wrap_error(format!("unable to set server cert: {}", err)))
}

pub fn tls_server_config(svid_source: &dyn x509svid::Source) -> super::Result<ServerConfig> {
    let (certs, key) = svid_to_rustls(svid_source)?;
    ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| super::wrap_error(format!("unable to set server cert: {}", err)))
}

pub fn mtls_web_client_config(
    svid_source: &dyn x509svid::Source,
    roots: std::option::Option<RootCertStore>,
) -> super::Result<ClientConfig> {
    let (certs, key) = svid_to_rustls(svid_source)?;
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots.unwrap_or_else(system_roots))
        .with_client_auth_cert(certs, key)
        .map_err(|err| super::wrap_error(format!("unable to set client auth cert: {}", err)))?;
    config.alpn_protocols.clear();
    Ok(config)
}

pub fn mtls_web_server_config(
    cert: WebCert,
    bundle_source: Arc<dyn x509bundle::Source + Send + Sync>,
    authorizer: Authorizer,
) -> super::Result<ServerConfig> {
    let verifier = Arc::new(SpiffeClientVerifier::new(bundle_source, authorizer));
    ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert.certs, cert.key)
        .map_err(|err| super::wrap_error(format!("unable to set server cert: {}", err)))
}

pub fn webpki_client_config(roots: std::option::Option<RootCertStore>) -> super::Result<ClientConfig> {
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots.unwrap_or_else(system_roots))
        .with_no_client_auth();
    config.alpn_protocols.clear();
    Ok(config)
}

fn svid_to_rustls(svid_source: &dyn x509svid::Source) -> super::Result<(Vec<Certificate>, PrivateKey)> {
    let svid = svid_source
        .get_x509_svid()
        .map_err(|err| super::wrap_error(err))?;
    if svid.certificates.is_empty() {
        return Err(super::wrap_error("empty X509-SVID"));
    }
    let certs = svid
        .certificates
        .iter()
        .map(|cert| Certificate(cert.clone()))
        .collect::<Vec<_>>();
    Ok((certs, PrivateKey(svid.private_key.clone())))
}

fn system_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    if let Ok(store) = rustls_native_certs::load_native_certs() {
        for cert in store {
            let _ = roots.add(&Certificate(cert.as_ref().to_vec()));
        }
    }
    roots
}

struct SpiffeServerVerifier {
    bundle_source: Arc<dyn x509bundle::Source + Send + Sync>,
    authorizer: Authorizer,
}

impl SpiffeServerVerifier {
    fn new(
        bundle_source: Arc<dyn x509bundle::Source + Send + Sync>,
        authorizer: Authorizer,
    ) -> Self {
        Self {
            bundle_source,
            authorizer,
        }
    }

    fn verify_peer(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
    ) -> Result<ServerCertVerified, RustlsError> {
        let raw = raw_chain(end_entity, intermediates);
        let (id, chains) = x509svid::parse_and_verify(&raw, self.bundle_source.as_ref(), &[])
            .map_err(|err| RustlsError::General(format!("spiffe verification failed: {}", err)))?;
        (self.authorizer)(&id, &chains)
            .map_err(|err| RustlsError::General(err.to_string()))?;
        Ok(ServerCertVerified::assertion())
    }
}

impl ServerCertVerifier for SpiffeServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        self.verify_peer(end_entity, intermediates)
    }
}

struct SpiffeClientVerifier {
    bundle_source: Arc<dyn x509bundle::Source + Send + Sync>,
    authorizer: Authorizer,
}

impl SpiffeClientVerifier {
    fn new(
        bundle_source: Arc<dyn x509bundle::Source + Send + Sync>,
        authorizer: Authorizer,
    ) -> Self {
        Self {
            bundle_source,
            authorizer,
        }
    }

    fn verify_peer(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
    ) -> Result<ClientCertVerified, RustlsError> {
        let raw = raw_chain(end_entity, intermediates);
        let (id, chains) = x509svid::parse_and_verify(&raw, self.bundle_source.as_ref(), &[])
            .map_err(|err| RustlsError::General(format!("spiffe verification failed: {}", err)))?;
        (self.authorizer)(&id, &chains)
            .map_err(|err| RustlsError::General(err.to_string()))?;
        Ok(ClientCertVerified::assertion())
    }
}

impl ClientCertVerifier for SpiffeClientVerifier {
    fn client_auth_root_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        _now: std::time::SystemTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        self.verify_peer(end_entity, intermediates)
    }
}

fn raw_chain(end_entity: &Certificate, intermediates: &[Certificate]) -> Vec<Vec<u8>> {
    let mut raw = Vec::with_capacity(1 + intermediates.len());
    raw.push(end_entity.0.clone());
    for cert in intermediates {
        raw.push(cert.0.clone());
    }
    raw
}
