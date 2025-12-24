//! Helpers for building `rustls` configurations that enforce SPIFFE identities.
//!
//! This module wires together three steps that are easy to conflate:
//!
//! - **Chain verification**: verify the peer certificate chain against an X.509
//!   bundle source (trust domain authorities).
//! - **SPIFFE ID extraction**: parse the peer SPIFFE ID from the leaf SVID.
//! - **Authorization**: decide whether the extracted ID is acceptable for the
//!   connection.
//!
//! The [`Authorizer`] type represents the final authorization step.

use crate::bundle::x509bundle;
use crate::spiffeid;
use crate::spiffeid::ID;
use crate::svid::x509svid;
use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::server::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    Certificate, ClientConfig, Error as RustlsError, PrivateKey, RootCertStore, ServerConfig,
};
use std::sync::Arc;

/// Authorization callback used by SPIFFE-TLS verification.
///
/// The callback receives:
/// - **`id`**: the SPIFFE ID extracted from the peer X.509-SVID leaf.
/// - **`chains`**: the verified chain(s), where each chain is a list of DER
///   certificates (leaf first). Some verifiers may provide multiple candidate
///   chains; most callers can ignore this parameter.
///
/// Return `Ok(())` to authorize the peer, otherwise return an error to fail the
/// TLS handshake.
pub type Authorizer =
    Arc<dyn Fn(&ID, &[Vec<Vec<u8>>]) -> std::result::Result<(), super::Error> + Send + Sync>;

/// Optional tracing hooks invoked when fetching an SVID for a TLS config.
///
/// This is intended for diagnostics (e.g. logging), not for modifying the
/// handshake.
#[derive(Clone, Default)]
pub struct Trace {
    pub get_certificate: Option<Arc<dyn Fn(GetCertificateInfo) + Send + Sync>>,
    pub got_certificate: Option<Arc<dyn Fn(GotCertificateInfo) + Send + Sync>>,
}

/// Input to [`Trace::get_certificate`].
#[derive(Clone, Default)]
pub struct GetCertificateInfo;

/// Input to [`Trace::got_certificate`].
#[derive(Clone, Default)]
pub struct GotCertificateInfo {
    /// The leaf certificate that will be used (if any).
    pub cert: Option<Certificate>,
    /// An error string if fetching the SVID failed.
    pub err: Option<String>,
}

/// Optional configuration applied when constructing `rustls` configs.
#[derive(Clone, Default)]
pub struct TlsOption {
    trace: std::option::Option<Trace>,
}

impl TlsOption {
    /// Enables [`Trace`] hooks for SVID retrieval.
    pub fn with_trace(trace: Trace) -> Self {
        Self {
            trace: std::option::Option::Some(trace),
        }
    }
}

#[derive(Clone)]
pub struct WebCert {
    /// Certificate chain to present (leaf first).
    pub certs: Vec<Certificate>,
    /// Private key corresponding to the leaf certificate.
    pub key: PrivateKey,
}

/// Authorizes any valid SPIFFE ID.
pub fn authorize_any() -> Authorizer {
    adapt_matcher(spiffeid::match_any())
}

/// Authorizes only the given SPIFFE ID.
pub fn authorize_id(allowed: ID) -> Authorizer {
    adapt_matcher(spiffeid::match_id(allowed))
}

/// Authorizes if the peer matches any ID in `allowed`.
pub fn authorize_one_of(allowed: &[ID]) -> Authorizer {
    adapt_matcher(spiffeid::match_one_of(allowed))
}

/// Authorizes if the peer ID is a member of the given trust domain.
pub fn authorize_member_of(allowed: spiffeid::TrustDomain) -> Authorizer {
    adapt_matcher(spiffeid::match_member_of(allowed))
}

/// Adapts a [`spiffeid::Matcher`] into an [`Authorizer`].
///
/// The resulting authorizer ignores verified chains and only evaluates the
/// matcher against the extracted SPIFFE ID.
pub fn adapt_matcher(matcher: spiffeid::Matcher) -> Authorizer {
    Arc::new(move |actual, _chains| matcher(actual).map_err(|err| super::wrap_error(err)))
}

/// Builds a `rustls` client config that authenticates the server via SPIFFE-TLS.
///
/// This configuration **does not** present a client certificate. Use
/// [`mtls_client_config`] for mutual authentication.
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

/// Builds a `rustls` client config for SPIFFE mTLS (client presents an X.509-SVID).
pub fn mtls_client_config(
    svid_source: &dyn x509svid::Source,
    bundle_source: Arc<dyn x509bundle::Source + Send + Sync>,
    authorizer: Authorizer,
) -> super::Result<ClientConfig> {
    mtls_client_config_with_options(svid_source, bundle_source, authorizer, &[])
}

/// Like [`mtls_client_config`], but allows passing [`TlsOption`] (e.g. tracing).
pub fn mtls_client_config_with_options(
    svid_source: &dyn x509svid::Source,
    bundle_source: Arc<dyn x509bundle::Source + Send + Sync>,
    authorizer: Authorizer,
    opts: &[TlsOption],
) -> super::Result<ClientConfig> {
    let (certs, key) = svid_to_rustls(svid_source, trace_from_options(opts))?;
    let verifier = Arc::new(SpiffeServerVerifier::new(bundle_source, authorizer));
    ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(certs, key)
        .map_err(|err| super::wrap_error(format!("unable to set client auth cert: {}", err)))
}

/// Builds a `rustls` server config for SPIFFE mTLS (server requires client certs).
pub fn mtls_server_config(
    svid_source: &dyn x509svid::Source,
    bundle_source: Arc<dyn x509bundle::Source + Send + Sync>,
    authorizer: Authorizer,
) -> super::Result<ServerConfig> {
    mtls_server_config_with_options(svid_source, bundle_source, authorizer, &[])
}

/// Like [`mtls_server_config`], but allows passing [`TlsOption`] (e.g. tracing).
pub fn mtls_server_config_with_options(
    svid_source: &dyn x509svid::Source,
    bundle_source: Arc<dyn x509bundle::Source + Send + Sync>,
    authorizer: Authorizer,
    opts: &[TlsOption],
) -> super::Result<ServerConfig> {
    let (certs, key) = svid_to_rustls(svid_source, trace_from_options(opts))?;
    let verifier = Arc::new(SpiffeClientVerifier::new(bundle_source, authorizer));
    ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|err| super::wrap_error(format!("unable to set server cert: {}", err)))
}

/// Builds a `rustls` server config that presents an X.509-SVID but does not
/// authenticate clients.
pub fn tls_server_config(svid_source: &dyn x509svid::Source) -> super::Result<ServerConfig> {
    tls_server_config_with_options(svid_source, &[])
}

/// Like [`tls_server_config`], but allows passing [`TlsOption`] (e.g. tracing).
pub fn tls_server_config_with_options(
    svid_source: &dyn x509svid::Source,
    opts: &[TlsOption],
) -> super::Result<ServerConfig> {
    let (certs, key) = svid_to_rustls(svid_source, trace_from_options(opts))?;
    ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| super::wrap_error(format!("unable to set server cert: {}", err)))
}

/// Builds a `rustls` client config that presents an X.509-SVID and verifies the
/// server using Web PKI roots.
///
/// This is intended for talking to conventional HTTPS servers that use Web PKI
/// identities, while still authenticating the client with an X.509-SVID.
pub fn mtls_web_client_config(
    svid_source: &dyn x509svid::Source,
    roots: std::option::Option<RootCertStore>,
) -> super::Result<ClientConfig> {
    mtls_web_client_config_with_options(svid_source, roots, &[])
}

/// Like [`mtls_web_client_config`], but allows passing [`TlsOption`] (e.g. tracing).
pub fn mtls_web_client_config_with_options(
    svid_source: &dyn x509svid::Source,
    roots: std::option::Option<RootCertStore>,
    opts: &[TlsOption],
) -> super::Result<ClientConfig> {
    let (certs, key) = svid_to_rustls(svid_source, trace_from_options(opts))?;
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots.unwrap_or_else(system_roots))
        .with_client_auth_cert(certs, key)
        .map_err(|err| super::wrap_error(format!("unable to set client auth cert: {}", err)))?;
    config.alpn_protocols.clear();
    Ok(config)
}

/// Builds a `rustls` server config for “web mTLS”:
///
/// - The server presents a Web PKI-style certificate chain (`cert`).
/// - The server requires a client certificate and enforces a SPIFFE ID policy
///   using `bundle_source` + `authorizer`.
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

/// Builds a Web PKI `rustls` client config (no client certificate).
///
/// This is *not* SPIFFE-aware; it exists to support federation bundle fetching
/// over HTTPS when SPIFFE authentication is not configured.
pub fn webpki_client_config(
    roots: std::option::Option<RootCertStore>,
) -> super::Result<ClientConfig> {
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots.unwrap_or_else(system_roots))
        .with_no_client_auth();
    config.alpn_protocols.clear();
    Ok(config)
}

fn svid_to_rustls(
    svid_source: &dyn x509svid::Source,
    trace: std::option::Option<&Trace>,
) -> super::Result<(Vec<Certificate>, PrivateKey)> {
    if let Some(trace) = trace {
        if let Some(get) = &trace.get_certificate {
            get(GetCertificateInfo);
        }
    }
    let svid = match svid_source.get_x509_svid() {
        Ok(svid) => svid,
        Err(err) => {
            if let Some(trace) = trace {
                if let Some(got) = &trace.got_certificate {
                    got(GotCertificateInfo {
                        cert: None,
                        err: Some(err.to_string()),
                    });
                }
            }
            return Err(super::wrap_error(err));
        }
    };
    if svid.certificates.is_empty() {
        return Err(super::wrap_error("empty X509-SVID"));
    }
    let certs = svid
        .certificates
        .iter()
        .map(|cert| Certificate(cert.clone()))
        .collect::<Vec<_>>();
    let key = PrivateKey(svid.private_key.clone());
    if let Some(trace) = trace {
        if let Some(got) = &trace.got_certificate {
            got(GotCertificateInfo {
                cert: certs.first().cloned(),
                err: None,
            });
        }
    }
    Ok((certs, key))
}

fn trace_from_options(opts: &[TlsOption]) -> std::option::Option<&Trace> {
    opts.iter().rev().find_map(|opt| opt.trace.as_ref())
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
        (self.authorizer)(&id, &chains).map_err(|err| RustlsError::General(err.to_string()))?;
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
        (self.authorizer)(&id, &chains).map_err(|err| RustlsError::General(err.to_string()))?;
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
