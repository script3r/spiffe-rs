use crate::spiffetls::{tlsconfig, ListenMode, ListenOption, Result};
use crate::workloadapi::{Context, X509Source};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

/// A SPIFFE-TLS listener.
pub struct Listener {
    inner: TcpListener,
    config: Arc<rustls::ServerConfig>,
    source: Option<Arc<X509Source>>,
}

impl Listener {
    /// Accepts a new connection and performs the TLS handshake.
    pub fn accept(&self) -> Result<ServerStream> {
        let (sock, _addr) = self
            .inner
            .accept()
            .map_err(|err| crate::spiffetls::wrap_error(err))?;
        let conn = rustls::ServerConnection::new(self.config.clone()).map_err(|err| {
            crate::spiffetls::wrap_error(format!("unable to create server connection: {}", err))
        })?;
        Ok(ServerStream {
            inner: rustls::StreamOwned::new(conn, sock),
        })
    }

    /// Returns the local address the listener is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.inner
            .local_addr()
            .map_err(|err| crate::spiffetls::wrap_error(err))
    }

    /// Closes the listener and its underlying source if it was created by the listener.
    pub async fn close(self) -> Result<()> {
        if let Some(source) = self.source {
            source
                .close()
                .await
                .map_err(|err| crate::spiffetls::Error(err.to_string()))?;
        }
        Ok(())
    }
}

/// A SPIFFE-TLS server stream.
pub struct ServerStream {
    inner: rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
}

impl ServerStream {
    /// Returns the SPIFFE ID of the peer.
    pub fn peer_id(&self) -> Result<crate::spiffeid::ID> {
        crate::spiffetls::peer_id_from_stream(self.inner.conn.peer_certificates())
    }
}

impl Read for ServerStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for ServerStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Listens for SPIFFE-TLS connections using mutual TLS.
pub async fn listen(
    ctx: &Context,
    addr: &str,
    authorizer: tlsconfig::Authorizer,
    options: Vec<Box<dyn ListenOption>>,
) -> Result<Listener> {
    listen_with_mode(
        ctx,
        addr,
        crate::spiffetls::mtls_server(authorizer),
        options,
    )
    .await
}

/// Listens for SPIFFE-TLS connections with the given mode.
pub async fn listen_with_mode(
    ctx: &Context,
    addr: &str,
    mode: ListenMode,
    options: Vec<Box<dyn ListenOption>>,
) -> Result<Listener> {
    let mut m = mode.clone();
    let mut source = None;

    if !m.source_unneeded {
        let resolved = if let Some(source) = m.source.clone() {
            source
        } else {
            let source = Arc::new(X509Source::new(ctx, m.options.clone()).await?);
            source
        };
        source = Some(resolved.clone());
        m.bundle = Some(resolved.clone());
        m.svid = Some(resolved.clone());
    }

    let mut config = crate::spiffetls::option::ListenConfig::default();
    for opt in options {
        opt.apply(&mut config);
    }

    let tls_config = match m.mode {
        crate::spiffetls::mode::ServerMode::Tls => {
            let svid = m
                .svid
                .ok_or_else(|| crate::spiffetls::wrap_error("missing svid source"))?;
            tlsconfig::tls_server_config_with_options(svid.as_ref(), &config.tls_options)?
        }
        crate::spiffetls::mode::ServerMode::Mtls => {
            let svid = m
                .svid
                .ok_or_else(|| crate::spiffetls::wrap_error("missing svid source"))?;
            let bundle = m
                .bundle
                .ok_or_else(|| crate::spiffetls::wrap_error("missing bundle source"))?;
            tlsconfig::mtls_server_config_with_options(
                svid.as_ref(),
                bundle,
                m.authorizer.clone(),
                &config.tls_options,
            )?
        }
        crate::spiffetls::mode::ServerMode::MtlsWeb => {
            let bundle = m
                .bundle
                .ok_or_else(|| crate::spiffetls::wrap_error("missing bundle source"))?;
            let cert = m
                .web_cert
                .ok_or_else(|| crate::spiffetls::wrap_error("missing web cert"))?;
            tlsconfig::mtls_web_server_config(cert, bundle, m.authorizer.clone())?
        }
    };

    let listener = TcpListener::bind(addr).map_err(|err| crate::spiffetls::wrap_error(err))?;
    let tls_config = apply_base_server_config(tls_config, config.base_server_config);
    Ok(Listener {
        inner: listener,
        config: Arc::new(tls_config),
        source,
    })
}

fn apply_base_server_config(
    mut computed: rustls::ServerConfig,
    base: Option<rustls::ServerConfig>,
) -> rustls::ServerConfig {
    let Some(base) = base else {
        return computed;
    };
    computed.ignore_client_order = base.ignore_client_order;
    computed.max_fragment_size = base.max_fragment_size;
    computed.session_storage = base.session_storage;
    computed.ticketer = base.ticketer;
    computed.alpn_protocols = base.alpn_protocols;
    computed.key_log = base.key_log;
    computed.max_early_data_size = base.max_early_data_size;
    computed.send_half_rtt_data = base.send_half_rtt_data;
    computed.send_tls13_tickets = base.send_tls13_tickets;
    computed
}
