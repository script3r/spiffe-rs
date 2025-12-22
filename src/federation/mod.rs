use crate::bundle::spiffebundle;
use crate::bundle::x509bundle;
use crate::spiffeid::{self, TrustDomain};
use crate::spiffetls::tlsconfig;
use crate::workloadapi::Context;
use hyper::body::Body;
use hyper::service::Service;
use hyper::{Request, Response, StatusCode};
use rustls::{Certificate, ClientConfig, RootCertStore, ServerName};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use url::Url;

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
    Error(format!("federation: {}", message))
}

/// An option for fetching a SPIFFE bundle from a remote URL.
pub trait FetchOption {
    fn apply(&self, options: &mut FetchOptions) -> Result<()>;
}

/// Sets the authentication method to SPIFFE-TLS.
pub fn with_spiffe_auth(
    bundle_source: Arc<dyn x509bundle::Source + Send + Sync>,
    endpoint_id: spiffeid::ID,
) -> impl FetchOption {
    FetchOptionFn(move |options: &mut FetchOptions| {
        if !matches!(options.auth_method, AuthMethod::Default) {
            return Err(wrap_error(
                "cannot use both SPIFFE and Web PKI authentication",
            ));
        }
        options.auth_method = AuthMethod::Spiffe {
            bundle_source: bundle_source.clone(),
            endpoint_id: endpoint_id.clone(),
        };
        Ok(())
    })
}

/// Sets the authentication method to Web PKI with the given roots.
pub fn with_web_pki_roots(roots: RootCertStore) -> impl FetchOption {
    FetchOptionFn(move |options: &mut FetchOptions| {
        if !matches!(options.auth_method, AuthMethod::Default) {
            return Err(wrap_error(
                "cannot use both SPIFFE and Web PKI authentication",
            ));
        }
        options.auth_method = AuthMethod::WebPki { roots: roots.clone() };
        Ok(())
    })
}

/// Fetches a SPIFFE bundle from the given URL.
pub fn fetch_bundle(
    trust_domain: TrustDomain,
    url: &str,
    options: &[Box<dyn FetchOption>],
) -> Result<spiffebundle::Bundle> {
    let mut opts = FetchOptions::default();
    for option in options {
        option.apply(&mut opts)?;
    }

    let parsed = Url::parse(url).map_err(|err| wrap_error(format!("invalid URL: {}", err)))?;
    let body = fetch_url(&parsed, &opts)?;
    spiffebundle::Bundle::parse(trust_domain, &body).map_err(|err| wrap_error(err))
}

/// A watcher for SPIFFE bundle updates.
pub trait BundleWatcher: Send + Sync {
    /// Returns the duration to wait before the next refresh.
    fn next_refresh(&self, refresh_hint: Duration) -> Duration;
    /// Called when the bundle is updated.
    fn on_update(&self, bundle: spiffebundle::Bundle);
    /// Called when an error occurs during fetching.
    fn on_error(&self, err: Error);
}

/// Watches a SPIFFE bundle at the given URL for updates.
pub async fn watch_bundle(
    ctx: &Context,
    trust_domain: TrustDomain,
    url: &str,
    watcher: Arc<dyn BundleWatcher>,
    options: Vec<Box<dyn FetchOption>>,
) -> Result<()> {
    let mut latest: Option<spiffebundle::Bundle> = None;
    loop {
        match fetch_bundle(trust_domain.clone(), url, &options) {
            Ok(bundle) => {
                let changed = latest.as_ref().map(|b| !b.equal(&bundle)).unwrap_or(true);
                if changed {
                    watcher.on_update(bundle.clone_bundle());
                    latest = Some(bundle);
                }
            }
            Err(err) => watcher.on_error(err),
        }

        let refresh_hint = latest
            .as_ref()
            .and_then(|b| b.refresh_hint())
            .unwrap_or_default();
        let next = watcher.next_refresh(refresh_hint);

        tokio::select! {
            _ = tokio::time::sleep(next) => {},
            _ = ctx.cancelled() => return Err(wrap_error("context canceled")),
        }
    }
}

#[derive(Clone)]
enum AuthMethod {
    Default,
    Spiffe {
        bundle_source: Arc<dyn x509bundle::Source + Send + Sync>,
        endpoint_id: spiffeid::ID,
    },
    WebPki {
        roots: RootCertStore,
    },
}

#[doc(hidden)]
pub struct FetchOptions {
    auth_method: AuthMethod,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            auth_method: AuthMethod::Default,
        }
    }
}

struct FetchOptionFn<F>(F);

impl<F> FetchOption for FetchOptionFn<F>
where
    F: Fn(&mut FetchOptions) -> Result<()> + Send + Sync,
{
    fn apply(&self, options: &mut FetchOptions) -> Result<()> {
        (self.0)(options)
    }
}

/// An option for configuring a `BundleHandler`.
pub trait HandlerOption {
    fn apply(&self, config: &mut HandlerConfig) -> Result<()>;
}

/// Sets the logger for the handler.
pub fn with_handler_logger(log: crate::workloadapi::LoggerRef) -> Box<dyn HandlerOption> {
    Box::new(HandlerOptionFn(move |config: &mut HandlerConfig| {
        config.log = log.clone();
        Ok(())
    }))
}

/// Creates a new `BundleHandler` that serves a SPIFFE bundle for the given trust domain.
pub fn new_handler(
    trust_domain: TrustDomain,
    source: Arc<dyn spiffebundle::Source + Send + Sync>,
    options: Vec<Box<dyn HandlerOption>>,
) -> Result<BundleHandler> {
    let mut config = HandlerConfig {
        log: Arc::new(crate::logger::null_logger()),
    };
    for opt in options {
        opt.apply(&mut config)?;
    }
    Ok(BundleHandler {
        trust_domain,
        source,
        log: config.log,
    })
}

/// A handler that serves a SPIFFE bundle over HTTP.
pub struct BundleHandler {
    trust_domain: TrustDomain,
    source: Arc<dyn spiffebundle::Source + Send + Sync>,
    log: crate::workloadapi::LoggerRef,
}

impl Service<Request<Body>> for BundleHandler {
    type Response = Response<Body>;
    type Error = hyper::Error;
    type Future = std::future::Ready<std::result::Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut TaskContext<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let response = if req.method() != hyper::Method::GET {
            Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::from("method is not allowed"))
                .unwrap()
        } else {
            match self.source.get_bundle_for_trust_domain(self.trust_domain.clone()) {
                Ok(bundle) => match bundle.marshal() {
                    Ok(body) => Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                    Err(err) => {
                        self.log.errorf(format_args!(
                            "unable to marshal bundle for trust domain {:?}: {}",
                            self.trust_domain, err
                        ));
                        Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Body::from(format!(
                                "unable to serve bundle for {:?}",
                                self.trust_domain
                            )))
                            .unwrap()
                    }
                },
                Err(err) => {
                    self.log.errorf(format_args!(
                        "unable to get bundle for trust domain {:?}: {}",
                        self.trust_domain, err
                    ));
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from(format!(
                            "unable to serve bundle for {:?}",
                            self.trust_domain
                        )))
                        .unwrap()
                }
            }
        };
        std::future::ready(Ok(response))
    }
}

#[doc(hidden)]
pub struct HandlerConfig {
    log: crate::workloadapi::LoggerRef,
}

struct HandlerOptionFn<F>(F);

impl<F> HandlerOption for HandlerOptionFn<F>
where
    F: Fn(&mut HandlerConfig) -> Result<()> + Send + Sync,
{
    fn apply(&self, config: &mut HandlerConfig) -> Result<()> {
        (self.0)(config)
    }
}

fn fetch_url(url: &Url, options: &FetchOptions) -> Result<Vec<u8>> {
    let host = url
        .host_str()
        .ok_or_else(|| wrap_error("URL missing host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| wrap_error("URL missing port"))?;
    let addr = format!("{}:{}", host, port);

    let mut stream = match url.scheme() {
        "https" => {
            let server_name = server_name_for_host(host)?;
            let tls_config = tls_config_for_auth(options)?;
            let tcp = TcpStream::connect(&addr).map_err(|err| wrap_error(err))?;
            let conn = rustls::ClientConnection::new(Arc::new(tls_config), server_name)
                .map_err(|err| wrap_error(format!("unable to create TLS connection: {}", err)))?;
            HttpStream::Tls(rustls::StreamOwned::new(conn, tcp))
        }
        "http" => HttpStream::Plain(
            TcpStream::connect(&addr).map_err(|err| wrap_error(err))?,
        ),
        scheme => {
            return Err(wrap_error(format!("unsupported URL scheme: {}", scheme)));
        }
    };

    let path = match (url.path(), url.query()) {
        ("", None) => "/".to_string(),
        (path, None) => path.to_string(),
        (path, Some(query)) => format!("{}?{}", path, query),
    };
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: */*\r\n\r\n",
        path, host
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|err| wrap_error(err))?;
    stream.flush().map_err(|err| wrap_error(err))?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).map_err(|err| wrap_error(err))?;
    parse_http_body(&response)
}

fn tls_config_for_auth(options: &FetchOptions) -> Result<ClientConfig> {
    match &options.auth_method {
        AuthMethod::Default => tlsconfig::webpki_client_config(Some(system_roots()?)),
        AuthMethod::WebPki { roots } => tlsconfig::webpki_client_config(Some(roots.clone())),
        AuthMethod::Spiffe {
            bundle_source,
            endpoint_id,
        } => tlsconfig::tls_client_config(
            bundle_source.clone(),
            tlsconfig::authorize_id(endpoint_id.clone()),
        ),
    }
    .map_err(|err| wrap_error(err))
}

fn system_roots() -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs()
        .map_err(|err| wrap_error(format!("unable to load native certs: {}", err)))?
    {
        roots
            .add(&Certificate(cert.as_ref().to_vec()))
            .map_err(|err| wrap_error(format!("unable to add root cert: {}", err)))?;
    }
    Ok(roots)
}

fn parse_http_body(response: &[u8]) -> Result<Vec<u8>> {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| wrap_error("invalid HTTP response"))?;
    let header = &response[..split];
    let body = response[split + 4..].to_vec();
    let status_line = header
        .split(|byte| *byte == b'\n')
        .next()
        .ok_or_else(|| wrap_error("invalid HTTP response"))?;
    let status_line = String::from_utf8_lossy(status_line).trim().to_string();
    let mut parts = status_line.split_whitespace();
    let _proto = parts.next().ok_or_else(|| wrap_error("invalid HTTP response"))?;
    let status = parts.next().ok_or_else(|| wrap_error("invalid HTTP response"))?;
    if status != "200" {
        return Err(wrap_error(format!("unexpected HTTP status {}", status)));
    }
    Ok(body)
}

fn server_name_for_host(host: &str) -> Result<ServerName> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip));
    }
    ServerName::try_from(host).map_err(|err| wrap_error(format!("invalid server name: {}", err)))
}

enum HttpStream {
    Plain(TcpStream),
    Tls(rustls::StreamOwned<rustls::ClientConnection, TcpStream>),
}

impl Read for HttpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            HttpStream::Plain(stream) => stream.read(buf),
            HttpStream::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for HttpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            HttpStream::Plain(stream) => stream.write(buf),
            HttpStream::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            HttpStream::Plain(stream) => stream.flush(),
            HttpStream::Tls(stream) => stream.flush(),
        }
    }
}
