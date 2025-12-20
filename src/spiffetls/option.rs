use crate::spiffetls::tlsconfig;
use rustls::{ClientConfig, ServerConfig};

pub trait DialOption: Send + Sync {
    fn apply(&self, config: &mut DialConfig);
}

pub trait ListenOption: Send + Sync {
    fn apply(&self, config: &mut ListenConfig);
}

pub struct DialConfig {
    pub base_client_config: Option<ClientConfig>,
    pub tls_options: Vec<tlsconfig::TlsOption>,
}

impl Default for DialConfig {
    fn default() -> Self {
        Self {
            base_client_config: None,
            tls_options: Vec::new(),
        }
    }
}

pub struct ListenConfig {
    pub base_server_config: Option<ServerConfig>,
    pub tls_options: Vec<tlsconfig::TlsOption>,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            base_server_config: None,
            tls_options: Vec::new(),
        }
    }
}

pub fn with_dial_tls_config_base(config: ClientConfig) -> Box<dyn DialOption> {
    Box::new(DialOptionFn(move |opts: &mut DialConfig| {
        opts.base_client_config = Some(config.clone());
    }))
}

pub fn with_dial_tls_options(options: Vec<tlsconfig::TlsOption>) -> Box<dyn DialOption> {
    Box::new(DialOptionFn(move |opts: &mut DialConfig| {
        opts.tls_options = options.clone();
    }))
}

pub fn with_listen_tls_config_base(config: ServerConfig) -> Box<dyn ListenOption> {
    Box::new(ListenOptionFn(move |opts: &mut ListenConfig| {
        opts.base_server_config = Some(config.clone());
    }))
}

pub fn with_listen_tls_options(options: Vec<tlsconfig::TlsOption>) -> Box<dyn ListenOption> {
    Box::new(ListenOptionFn(move |opts: &mut ListenConfig| {
        opts.tls_options = options.clone();
    }))
}

struct DialOptionFn<F>(F);

impl<F> DialOption for DialOptionFn<F>
where
    F: Fn(&mut DialConfig) + Send + Sync,
{
    fn apply(&self, config: &mut DialConfig) {
        (self.0)(config)
    }
}

struct ListenOptionFn<F>(F);

impl<F> ListenOption for ListenOptionFn<F>
where
    F: Fn(&mut ListenConfig) + Send + Sync,
{
    fn apply(&self, config: &mut ListenConfig) {
        (self.0)(config)
    }
}
