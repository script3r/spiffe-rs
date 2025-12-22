use crate::logger;
use crate::workloadapi::{backoff, client::Client, LoggerRef};
use std::sync::Arc;

/// An option for configuring a Workload API client.
pub trait ClientOption: Send + Sync {
    fn configure_client(&self, config: &mut ClientConfig);
}

/// An option for configuring a source (X.509, JWT, or bundle).
pub trait SourceOption: Send + Sync {
    fn configure_x509_source(&self, config: &mut X509SourceConfig);
    fn configure_jwt_source(&self, config: &mut JWTSourceConfig);
    fn configure_bundle_source(&self, config: &mut BundleSourceConfig);
}

/// An option for configuring an X.509 source.
pub trait X509SourceOption: Send + Sync {
    fn configure_x509_source(&self, config: &mut X509SourceConfig);
}

/// An option for configuring a JWT source.
pub trait JWTSourceOption: Send + Sync {
    fn configure_jwt_source(&self, config: &mut JWTSourceConfig);
}

/// An option for configuring a bundle source.
pub trait BundleSourceOption: Send + Sync {
    fn configure_bundle_source(&self, config: &mut BundleSourceConfig);
}

/// An option for configuring the gRPC channel.
pub trait DialOption: Send + Sync {
    fn apply(&self, endpoint: tonic::transport::Endpoint) -> tonic::transport::Endpoint;
}

/// Sets the address of the Workload API endpoint.
pub fn with_addr(addr: impl Into<String>) -> Arc<dyn ClientOption> {
    Arc::new(WithAddr {
        addr: addr.into(),
    })
}

/// Sets the gRPC dial options.
pub fn with_dial_options(options: Vec<Arc<dyn DialOption>>) -> Arc<dyn ClientOption> {
    Arc::new(WithDialOptions { options })
}

/// Sets the logger for the client.
pub fn with_logger(log: LoggerRef) -> Arc<dyn ClientOption> {
    Arc::new(WithLogger { log })
}

/// Sets the backoff strategy for retrying failed connections.
pub fn with_backoff_strategy(strategy: Arc<dyn backoff::BackoffStrategy>) -> Arc<dyn ClientOption> {
    Arc::new(WithBackoffStrategy { strategy })
}

/// Sets an existing Workload API client to be used by the source.
pub fn with_client(client: Arc<Client>) -> Arc<dyn SourceOption> {
    Arc::new(WithClient { client })
}

/// Sets the options for the Workload API client created by the source.
pub fn with_client_options(options: Vec<Arc<dyn ClientOption>>) -> Arc<dyn SourceOption> {
    Arc::new(WithClientOptions { options })
}

/// Sets a custom picker for X.509 SVIDs.
pub fn with_default_x509_svid_picker(
    picker: Arc<dyn Fn(&[crate::svid::x509svid::SVID]) -> crate::svid::x509svid::SVID + Send + Sync>,
) -> Arc<dyn X509SourceOption> {
    Arc::new(WithDefaultX509SVIDPicker { picker })
}

/// Sets a custom picker for JWT SVIDs.
pub fn with_default_jwt_svid_picker(
    picker: Arc<dyn Fn(&[crate::svid::jwtsvid::SVID]) -> crate::svid::jwtsvid::SVID + Send + Sync>,
) -> Arc<dyn JWTSourceOption> {
    Arc::new(WithDefaultJWTSVIDPicker { picker })
}

#[derive(Clone)]
pub struct ClientConfig {
    pub address: Option<String>,
    pub dial_options: Vec<Arc<dyn DialOption>>,
    pub log: LoggerRef,
    pub backoff_strategy: Arc<dyn backoff::BackoffStrategy>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            address: None,
            dial_options: Vec::new(),
            log: Arc::new(logger::null_logger()),
            backoff_strategy: Arc::new(backoff::LinearBackoffStrategy::default()),
        }
    }
}

pub struct WatcherConfig {
    pub client: Option<Arc<Client>>,
    pub client_options: Vec<Arc<dyn ClientOption>>,
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self {
            client: None,
            client_options: Vec::new(),
        }
    }
}

pub struct X509SourceConfig {
    pub watcher: WatcherConfig,
    pub picker: Option<
        Arc<dyn Fn(&[crate::svid::x509svid::SVID]) -> crate::svid::x509svid::SVID + Send + Sync>,
    >,
}

impl Default for X509SourceConfig {
    fn default() -> Self {
        Self {
            watcher: WatcherConfig::default(),
            picker: None,
        }
    }
}

pub struct JWTSourceConfig {
    pub watcher: WatcherConfig,
    pub picker:
        Option<Arc<dyn Fn(&[crate::svid::jwtsvid::SVID]) -> crate::svid::jwtsvid::SVID + Send + Sync>>,
}

impl Default for JWTSourceConfig {
    fn default() -> Self {
        Self {
            watcher: WatcherConfig::default(),
            picker: None,
        }
    }
}

pub struct BundleSourceConfig {
    pub watcher: WatcherConfig,
}

impl Default for BundleSourceConfig {
    fn default() -> Self {
        Self {
            watcher: WatcherConfig::default(),
        }
    }
}

struct WithAddr {
    addr: String,
}

impl ClientOption for WithAddr {
    fn configure_client(&self, config: &mut ClientConfig) {
        config.address = Some(self.addr.clone());
    }
}

struct WithDialOptions {
    options: Vec<Arc<dyn DialOption>>,
}

impl ClientOption for WithDialOptions {
    fn configure_client(&self, config: &mut ClientConfig) {
        config.dial_options.extend(self.options.iter().cloned());
    }
}

struct WithLogger {
    log: LoggerRef,
}

impl ClientOption for WithLogger {
    fn configure_client(&self, config: &mut ClientConfig) {
        config.log = self.log.clone();
    }
}

struct WithBackoffStrategy {
    strategy: Arc<dyn backoff::BackoffStrategy>,
}

impl ClientOption for WithBackoffStrategy {
    fn configure_client(&self, config: &mut ClientConfig) {
        config.backoff_strategy = self.strategy.clone();
    }
}

struct WithClient {
    client: Arc<Client>,
}

impl SourceOption for WithClient {
    fn configure_x509_source(&self, config: &mut X509SourceConfig) {
        config.watcher.client = Some(self.client.clone());
    }

    fn configure_jwt_source(&self, config: &mut JWTSourceConfig) {
        config.watcher.client = Some(self.client.clone());
    }

    fn configure_bundle_source(&self, config: &mut BundleSourceConfig) {
        config.watcher.client = Some(self.client.clone());
    }
}

struct WithClientOptions {
    options: Vec<Arc<dyn ClientOption>>,
}

impl SourceOption for WithClientOptions {
    fn configure_x509_source(&self, config: &mut X509SourceConfig) {
        config.watcher.client_options = self.options.clone();
    }

    fn configure_jwt_source(&self, config: &mut JWTSourceConfig) {
        config.watcher.client_options = self.options.clone();
    }

    fn configure_bundle_source(&self, config: &mut BundleSourceConfig) {
        config.watcher.client_options = self.options.clone();
    }
}

struct WithDefaultX509SVIDPicker {
    picker: Arc<dyn Fn(&[crate::svid::x509svid::SVID]) -> crate::svid::x509svid::SVID + Send + Sync>,
}

impl X509SourceOption for WithDefaultX509SVIDPicker {
    fn configure_x509_source(&self, config: &mut X509SourceConfig) {
        config.picker = Some(self.picker.clone());
    }
}

impl SourceOption for WithDefaultX509SVIDPicker {
    fn configure_x509_source(&self, config: &mut X509SourceConfig) {
        X509SourceOption::configure_x509_source(self, config);
    }

    fn configure_jwt_source(&self, _config: &mut JWTSourceConfig) {}

    fn configure_bundle_source(&self, _config: &mut BundleSourceConfig) {}
}

struct WithDefaultJWTSVIDPicker {
    picker: Arc<dyn Fn(&[crate::svid::jwtsvid::SVID]) -> crate::svid::jwtsvid::SVID + Send + Sync>,
}

impl JWTSourceOption for WithDefaultJWTSVIDPicker {
    fn configure_jwt_source(&self, config: &mut JWTSourceConfig) {
        config.picker = Some(self.picker.clone());
    }
}

impl SourceOption for WithDefaultJWTSVIDPicker {
    fn configure_x509_source(&self, _config: &mut X509SourceConfig) {}

    fn configure_jwt_source(&self, config: &mut JWTSourceConfig) {
        JWTSourceOption::configure_jwt_source(self, config);
    }

    fn configure_bundle_source(&self, _config: &mut BundleSourceConfig) {}
}
