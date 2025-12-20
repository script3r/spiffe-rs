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

pub fn tls_client_with_source(authorizer: tlsconfig::Authorizer, source: Arc<workloadapi::X509Source>) -> DialMode {
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

pub fn mtls_client_with_source(authorizer: tlsconfig::Authorizer, source: Arc<workloadapi::X509Source>) -> DialMode {
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

pub fn tls_server_with_source_options(options: Vec<Arc<dyn workloadapi::X509SourceOption>>) -> ListenMode {
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

pub fn mtls_server_with_source(authorizer: tlsconfig::Authorizer, source: Arc<workloadapi::X509Source>) -> ListenMode {
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
