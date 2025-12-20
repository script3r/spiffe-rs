use crate::spiffeid::ID;
use crate::spiffetls::{tlsconfig, Error, Result};
use crate::spiffetls::{DialMode, DialOption};
use crate::workloadapi::{Context, X509Source};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use x509_parser::extensions::GeneralName;

pub struct ClientStream {
    inner: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    source: Option<Arc<X509Source>>,
}

impl ClientStream {
    pub fn peer_id(&self) -> Result<ID> {
        peer_id_from_certs(self.inner.conn.peer_certificates())
    }

    pub async fn close(self) -> Result<()> {
        if let Some(source) = self.source {
            source.close().await.map_err(|err| Error(err.to_string()))?;
        }
        Ok(())
    }
}

impl Read for ClientStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for ClientStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

pub async fn dial(
    ctx: &Context,
    addr: &str,
    server_name: rustls::ServerName,
    authorizer: tlsconfig::Authorizer,
    options: Vec<Box<dyn DialOption>>,
) -> Result<ClientStream> {
    dial_with_mode(ctx, addr, server_name, crate::spiffetls::mtls_client(authorizer), options).await
}

pub async fn dial_with_mode(
    ctx: &Context,
    addr: &str,
    server_name: rustls::ServerName,
    mode: DialMode,
    options: Vec<Box<dyn DialOption>>,
) -> Result<ClientStream> {
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

    let mut config = crate::spiffetls::option::DialConfig::default();
    for opt in options {
        opt.apply(&mut config);
    }

    let tls_config = match m.mode {
        crate::spiffetls::mode::ClientMode::Tls => {
            let bundle = m.bundle.ok_or_else(|| crate::spiffetls::wrap_error("missing bundle source"))?;
            tlsconfig::tls_client_config(bundle, m.authorizer.clone())?
        }
        crate::spiffetls::mode::ClientMode::Mtls => {
            let svid = m.svid.ok_or_else(|| crate::spiffetls::wrap_error("missing svid source"))?;
            let bundle = m.bundle.ok_or_else(|| crate::spiffetls::wrap_error("missing bundle source"))?;
            tlsconfig::mtls_client_config_with_options(
                svid.as_ref(),
                bundle,
                m.authorizer.clone(),
                &config.tls_options,
            )?
        }
        crate::spiffetls::mode::ClientMode::MtlsWeb => {
            let svid = m.svid.ok_or_else(|| crate::spiffetls::wrap_error("missing svid source"))?;
            tlsconfig::mtls_web_client_config_with_options(
                svid.as_ref(),
                m.roots,
                &config.tls_options,
            )?
        }
    };

    let tcp = TcpStream::connect(addr).map_err(|err| crate::spiffetls::wrap_error(err))?;
    let tls_config = apply_base_client_config(tls_config, config.base_client_config);
    let conn = rustls::ClientConnection::new(Arc::new(tls_config), server_name)
        .map_err(|err| crate::spiffetls::wrap_error(format!("unable to create client connection: {}", err)))?;
    Ok(ClientStream {
        inner: rustls::StreamOwned::new(conn, tcp),
        source,
    })
}

fn apply_base_client_config(
    mut computed: rustls::ClientConfig,
    base: Option<rustls::ClientConfig>,
) -> rustls::ClientConfig {
    let Some(base) = base else {
        return computed;
    };
    computed.alpn_protocols = base.alpn_protocols;
    computed.resumption = base.resumption;
    computed.max_fragment_size = base.max_fragment_size;
    computed.enable_sni = base.enable_sni;
    computed.key_log = base.key_log;
    computed.enable_early_data = base.enable_early_data;
    computed
}

fn peer_id_from_certs(certs: Option<&[rustls::Certificate]>) -> Result<ID> {
    let certs = certs.ok_or_else(|| crate::spiffetls::wrap_error("no peer certificates"))?;
    let cert = certs
        .first()
        .ok_or_else(|| crate::spiffetls::wrap_error("no peer certificates"))?;
    let (_rest, parsed) = x509_parser::parse_x509_certificate(&cert.0)
        .map_err(|err| crate::spiffetls::wrap_error(format!("invalid peer certificate: {}", err)))?;
    let san = parsed
        .subject_alternative_name()
        .map_err(|_| crate::spiffetls::wrap_error("invalid peer certificate: invalid URI SAN"))?
        .ok_or_else(|| crate::spiffetls::wrap_error("invalid peer certificate: no URI SAN"))?;
    let mut uris = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::URI(uri) => Some(*uri),
            _ => None,
        })
        .collect::<Vec<_>>();
    if uris.len() != 1 {
        return Err(crate::spiffetls::wrap_error(
            "invalid peer certificate: expected single URI SAN",
        ));
    }
    ID::from_string(uris.remove(0))
        .map_err(|err| crate::spiffetls::wrap_error(format!("invalid peer certificate: {}", err)))
}
