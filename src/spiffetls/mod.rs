mod dial;
mod listen;
mod mode;
mod option;
mod peerid;
pub mod tlsconfig;

pub use dial::{dial, dial_with_mode, ClientStream};
pub use listen::{listen, listen_with_mode, Listener, ServerStream};
pub use mode::*;
pub use option::*;
pub use peerid::{peer_id_from_stream, PeerIdGetter};

/// An error that occurred during a SPIFFE-TLS operation.
#[derive(Debug, Clone)]
pub struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Error {}

/// A specialized Result type for SPIFFE-TLS operations.
pub type Result<T> = std::result::Result<T, Error>;

fn wrap_error(message: impl std::fmt::Display) -> Error {
    Error(format!("spiffetls: {}", message))
}

impl From<crate::workloadapi::Error> for Error {
    fn from(err: crate::workloadapi::Error) -> Self {
        Error(err.to_string())
    }
}
