use std::sync::Arc;

mod addr;
mod backoff;
mod bundlesource;
mod client;
mod convenience;
mod jwtsource;
mod option;
mod watcher;
mod x509context;
mod x509source;

pub mod proto {
    pub mod google {
        pub mod protobuf {
            include!(concat!(env!("OUT_DIR"), "/google.protobuf.rs"));
        }
    }
    include!(concat!(env!("OUT_DIR"), "/_.rs"));
}

#[derive(Debug, Clone)]
pub struct Error {
    message: String,
    status: Option<tonic::Status>,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(f)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

fn wrap_error(message: impl std::fmt::Display) -> Error {
    Error {
        message: format!("workloadapi: {}", message),
        status: None,
    }
}

impl Error {
    pub fn status(&self) -> Option<&tonic::Status> {
        self.status.as_ref()
    }

    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status: None,
        }
    }
}

impl From<tonic::Status> for Error {
    fn from(status: tonic::Status) -> Self {
        Self {
            message: format!("workloadapi: {}", status),
            status: Some(status),
        }
    }
}

pub type Context = tokio_util::sync::CancellationToken;

pub fn background() -> Context {
    tokio_util::sync::CancellationToken::new()
}

pub use addr::{get_default_address, target_from_address, validate_address, SocketEnv};
pub use backoff::{Backoff, BackoffStrategy, LinearBackoffStrategy};
pub use bundlesource::BundleSource;
pub use client::{Client, JWTBundleWatcher, X509BundleWatcher, X509ContextWatcher};
pub use convenience::*;
pub use jwtsource::JWTSource;
pub use option::*;
pub use watcher::Watcher;
pub use x509context::X509Context;
pub use x509source::X509Source;

pub(crate) type LoggerRef = Arc<dyn crate::logger::Logger>;
