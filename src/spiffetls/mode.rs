//! Dial/listen “modes” for `spiffetls` helpers.
//!
//! A mode is a small builder object that tells [`crate::spiffetls::dial`] /
//! [`crate::spiffetls::listen`] how to construct `rustls` configs:
//!
//! - Whether to do **TLS**, **SPIFFE mTLS**, or **web mTLS**
//! - Where to get the X.509-SVID and bundle information (from a Workload API
//!   [`workloadapi::X509Source`], or from "raw" provided sources)
//! - Which SPIFFE IDs are allowed (via a [`tlsconfig::Authorizer`])

use crate::bundle::x509bundle;
use crate::spiffetls::tlsconfig;
use crate::svid::x509svid;
use crate::workloadapi;
use rustls::RootCertStore;
use std::sync::Arc;

#[derive(Clone)]
pub struct DialMode {
    pub(crate) mode: ClientMode,
    pub(crate) source_unneeded: bool,
    pub(crate) authorizer: tlsconfig::Authorizer,
    pub(crate) source: Option<Arc<workloadapi::X509Source>>,
    pub(crate) options: Vec<Arc<dyn workloadapi::X509SourceOption>>,
    pub(crate) bundle: Option<Arc<dyn x509bundle::Source + Send + Sync>>,
    pub(crate) svid: Option<Arc<dyn x509svid::Source + Send + Sync>>,
    pub(crate) roots: Option<RootCertStore>,
}

#[derive(Clone)]
pub struct ListenMode {
    pub(crate) mode: ServerMode,
    pub(crate) source_unneeded: bool,
    pub(crate) authorizer: tlsconfig::Authorizer,
    pub(crate) source: Option<Arc<workloadapi::X509Source>>,
    pub(crate) options: Vec<Arc<dyn workloadapi::X509SourceOption>>,
    pub(crate) bundle: Option<Arc<dyn x509bundle::Source + Send + Sync>>,
    pub(crate) svid: Option<Arc<dyn x509svid::Source + Send + Sync>>,
    pub(crate) web_cert: Option<tlsconfig::WebCert>,
}

#[derive(Clone, Copy)]
pub(crate) enum ClientMode {
    Tls,
    Mtls,
    MtlsWeb,
}

#[derive(Clone, Copy)]
pub(crate) enum ServerMode {
    Tls,
    Mtls,
    MtlsWeb,
}

/// Dial a server using SPIFFE-TLS (server authenticated by SPIFFE ID).
///
/// The client does not present an X.509-SVID.
pub fn tls_client(authorizer: tlsconfig::Authorizer) -> DialMode {
    DialMode {
        mode: ClientMode::Tls,
        source_unneeded: false,
        authorizer,
        source: None,
        options: Vec::new(),
        bundle: None,
        svid: None,
        roots: None,
    }
}

/// Like [`tls_client`], but uses an existing [`workloadapi::X509Source`].
pub fn tls_client_with_source(
    authorizer: tlsconfig::Authorizer,
    source: Arc<workloadapi::X509Source>,
) -> DialMode {
    DialMode {
        mode: ClientMode::Tls,
        source_unneeded: false,
        authorizer,
        source: Some(source),
        options: Vec::new(),
        bundle: None,
        svid: None,
        roots: None,
    }
}

/// Like [`tls_client`], but configures the internal [`workloadapi::X509Source`]
/// via source options.
///
/// This is useful if you want `spiffetls` to create and own the source, but you
/// need to configure the Workload API client used by the source.
pub fn tls_client_with_source_options(
    authorizer: tlsconfig::Authorizer,
    options: Vec<Arc<dyn workloadapi::X509SourceOption>>,
) -> DialMode {
    DialMode {
        mode: ClientMode::Tls,
        source_unneeded: false,
        authorizer,
        source: None,
        options,
        bundle: None,
        svid: None,
        roots: None,
    }
}

/// Like [`tls_client`], but bypasses the Workload API entirely.
///
/// The provided `bundle` is used to verify the server certificate chain.
pub fn tls_client_with_raw_config(
    authorizer: tlsconfig::Authorizer,
    bundle: Arc<dyn x509bundle::Source + Send + Sync>,
) -> DialMode {
    DialMode {
        mode: ClientMode::Tls,
        source_unneeded: true,
        authorizer,
        source: None,
        options: Vec::new(),
        bundle: Some(bundle),
        svid: None,
        roots: None,
    }
}

/// Dial a server using SPIFFE mTLS (both sides authenticate via SPIFFE IDs).
pub fn mtls_client(authorizer: tlsconfig::Authorizer) -> DialMode {
    DialMode {
        mode: ClientMode::Mtls,
        source_unneeded: false,
        authorizer,
        source: None,
        options: Vec::new(),
        bundle: None,
        svid: None,
        roots: None,
    }
}

/// Like [`mtls_client`], but uses an existing [`workloadapi::X509Source`].
pub fn mtls_client_with_source(
    authorizer: tlsconfig::Authorizer,
    source: Arc<workloadapi::X509Source>,
) -> DialMode {
    DialMode {
        mode: ClientMode::Mtls,
        source_unneeded: false,
        authorizer,
        source: Some(source),
        options: Vec::new(),
        bundle: None,
        svid: None,
        roots: None,
    }
}

/// Like [`mtls_client`], but configures the internal [`workloadapi::X509Source`]
/// via source options.
pub fn mtls_client_with_source_options(
    authorizer: tlsconfig::Authorizer,
    options: Vec<Arc<dyn workloadapi::X509SourceOption>>,
) -> DialMode {
    DialMode {
        mode: ClientMode::Mtls,
        source_unneeded: false,
        authorizer,
        source: None,
        options,
        bundle: None,
        svid: None,
        roots: None,
    }
}

/// Like [`mtls_client`], but bypasses the Workload API entirely.
///
/// The provided `svid` is presented as the client certificate chain, and the
/// provided `bundle` is used to verify the server certificate chain.
pub fn mtls_client_with_raw_config(
    authorizer: tlsconfig::Authorizer,
    svid: Arc<dyn x509svid::Source + Send + Sync>,
    bundle: Arc<dyn x509bundle::Source + Send + Sync>,
) -> DialMode {
    DialMode {
        mode: ClientMode::Mtls,
        source_unneeded: true,
        authorizer,
        source: None,
        options: Vec::new(),
        svid: Some(svid),
        bundle: Some(bundle),
        roots: None,
    }
}

/// Dial a “web” server using Web PKI verification, while presenting an X.509-SVID.
///
/// - The server is verified using `roots` (or system roots if `None`).
/// - No SPIFFE ID authorization is performed for the server identity.
pub fn mtls_web_client(roots: Option<RootCertStore>) -> DialMode {
    DialMode {
        mode: ClientMode::MtlsWeb,
        source_unneeded: false,
        authorizer: tlsconfig::authorize_any(),
        source: None,
        options: Vec::new(),
        bundle: None,
        svid: None,
        roots,
    }
}

/// Like [`mtls_web_client`], but uses an existing [`workloadapi::X509Source`].
pub fn mtls_web_client_with_source(
    roots: Option<RootCertStore>,
    source: Arc<workloadapi::X509Source>,
) -> DialMode {
    DialMode {
        mode: ClientMode::MtlsWeb,
        source_unneeded: false,
        authorizer: tlsconfig::authorize_any(),
        source: Some(source),
        options: Vec::new(),
        bundle: None,
        svid: None,
        roots,
    }
}

/// Like [`mtls_web_client`], but configures the internal [`workloadapi::X509Source`]
/// via source options.
pub fn mtls_web_client_with_source_options(
    roots: Option<RootCertStore>,
    options: Vec<Arc<dyn workloadapi::X509SourceOption>>,
) -> DialMode {
    DialMode {
        mode: ClientMode::MtlsWeb,
        source_unneeded: false,
        authorizer: tlsconfig::authorize_any(),
        source: None,
        options,
        bundle: None,
        svid: None,
        roots,
    }
}

/// Like [`mtls_web_client`], but bypasses the Workload API entirely.
///
/// The provided `svid` is presented as the client certificate chain.
pub fn mtls_web_client_with_raw_config(
    roots: Option<RootCertStore>,
    svid: Arc<dyn x509svid::Source + Send + Sync>,
) -> DialMode {
    DialMode {
        mode: ClientMode::MtlsWeb,
        source_unneeded: true,
        authorizer: tlsconfig::authorize_any(),
        source: None,
        options: Vec::new(),
        bundle: None,
        svid: Some(svid),
        roots,
    }
}

/// Listen using TLS (present an X.509-SVID, do not authenticate clients).
pub fn tls_server() -> ListenMode {
    ListenMode {
        mode: ServerMode::Tls,
        source_unneeded: false,
        authorizer: tlsconfig::authorize_any(),
        source: None,
        options: Vec::new(),
        bundle: None,
        svid: None,
        web_cert: None,
    }
}

/// Like [`tls_server`], but uses an existing [`workloadapi::X509Source`].
pub fn tls_server_with_source(source: Arc<workloadapi::X509Source>) -> ListenMode {
    ListenMode {
        mode: ServerMode::Tls,
        source_unneeded: false,
        authorizer: tlsconfig::authorize_any(),
        source: Some(source),
        options: Vec::new(),
        bundle: None,
        svid: None,
        web_cert: None,
    }
}

/// Like [`tls_server`], but configures the internal [`workloadapi::X509Source`]
/// via source options.
pub fn tls_server_with_source_options(
    options: Vec<Arc<dyn workloadapi::X509SourceOption>>,
) -> ListenMode {
    ListenMode {
        mode: ServerMode::Tls,
        source_unneeded: false,
        authorizer: tlsconfig::authorize_any(),
        source: None,
        options,
        bundle: None,
        svid: None,
        web_cert: None,
    }
}

/// Like [`tls_server`], but bypasses the Workload API entirely.
///
/// The provided `svid` is presented as the server certificate chain.
pub fn tls_server_with_raw_config(svid: Arc<dyn x509svid::Source + Send + Sync>) -> ListenMode {
    ListenMode {
        mode: ServerMode::Tls,
        source_unneeded: true,
        authorizer: tlsconfig::authorize_any(),
        source: None,
        options: Vec::new(),
        bundle: None,
        svid: Some(svid),
        web_cert: None,
    }
}

/// Listen using SPIFFE mTLS (require and authorize client certificates).
pub fn mtls_server(authorizer: tlsconfig::Authorizer) -> ListenMode {
    ListenMode {
        mode: ServerMode::Mtls,
        source_unneeded: false,
        authorizer,
        source: None,
        options: Vec::new(),
        bundle: None,
        svid: None,
        web_cert: None,
    }
}

/// Like [`mtls_server`], but uses an existing [`workloadapi::X509Source`].
pub fn mtls_server_with_source(
    authorizer: tlsconfig::Authorizer,
    source: Arc<workloadapi::X509Source>,
) -> ListenMode {
    ListenMode {
        mode: ServerMode::Mtls,
        source_unneeded: false,
        authorizer,
        source: Some(source),
        options: Vec::new(),
        bundle: None,
        svid: None,
        web_cert: None,
    }
}

/// Like [`mtls_server`], but configures the internal [`workloadapi::X509Source`]
/// via source options.
pub fn mtls_server_with_source_options(
    authorizer: tlsconfig::Authorizer,
    options: Vec<Arc<dyn workloadapi::X509SourceOption>>,
) -> ListenMode {
    ListenMode {
        mode: ServerMode::Mtls,
        source_unneeded: false,
        authorizer,
        source: None,
        options,
        bundle: None,
        svid: None,
        web_cert: None,
    }
}

/// Like [`mtls_server`], but bypasses the Workload API entirely.
///
/// The provided `svid` is presented as the server certificate chain and
/// `bundle` is used to verify/authorize client certificates.
pub fn mtls_server_with_raw_config(
    authorizer: tlsconfig::Authorizer,
    svid: Arc<dyn x509svid::Source + Send + Sync>,
    bundle: Arc<dyn x509bundle::Source + Send + Sync>,
) -> ListenMode {
    ListenMode {
        mode: ServerMode::Mtls,
        source_unneeded: true,
        authorizer,
        source: None,
        options: Vec::new(),
        bundle: Some(bundle),
        svid: Some(svid),
        web_cert: None,
    }
}

/// Listen using Web PKI identity, while requiring and authorizing SPIFFE clients.
///
/// The server presents `cert` (typically a public TLS certificate chain) but
/// authenticates clients via SPIFFE mTLS using `authorizer`.
pub fn mtls_web_server(authorizer: tlsconfig::Authorizer, cert: tlsconfig::WebCert) -> ListenMode {
    ListenMode {
        mode: ServerMode::MtlsWeb,
        source_unneeded: false,
        authorizer,
        source: None,
        options: Vec::new(),
        bundle: None,
        svid: None,
        web_cert: Some(cert),
    }
}

/// Like [`mtls_web_server`], but uses an existing [`workloadapi::X509Source`].
pub fn mtls_web_server_with_source(
    authorizer: tlsconfig::Authorizer,
    cert: tlsconfig::WebCert,
    source: Arc<workloadapi::X509Source>,
) -> ListenMode {
    ListenMode {
        mode: ServerMode::MtlsWeb,
        source_unneeded: false,
        authorizer,
        source: Some(source),
        options: Vec::new(),
        bundle: None,
        svid: None,
        web_cert: Some(cert),
    }
}

/// Like [`mtls_web_server`], but configures the internal [`workloadapi::X509Source`]
/// via source options.
pub fn mtls_web_server_with_source_options(
    authorizer: tlsconfig::Authorizer,
    cert: tlsconfig::WebCert,
    options: Vec<Arc<dyn workloadapi::X509SourceOption>>,
) -> ListenMode {
    ListenMode {
        mode: ServerMode::MtlsWeb,
        source_unneeded: false,
        authorizer,
        source: None,
        options,
        bundle: None,
        svid: None,
        web_cert: Some(cert),
    }
}

/// Like [`mtls_web_server`], but bypasses the Workload API entirely.
///
/// The provided `bundle` is used to verify/authorize client certificates.
pub fn mtls_web_server_with_raw_config(
    authorizer: tlsconfig::Authorizer,
    cert: tlsconfig::WebCert,
    bundle: Arc<dyn x509bundle::Source + Send + Sync>,
) -> ListenMode {
    ListenMode {
        mode: ServerMode::MtlsWeb,
        source_unneeded: true,
        authorizer,
        source: None,
        options: Vec::new(),
        bundle: Some(bundle),
        svid: None,
        web_cert: Some(cert),
    }
}
