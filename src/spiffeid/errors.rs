use thiserror::Error;

/// A specialized Result type for SPIFFE ID operations.
pub type Result<T> = std::result::Result<T, Error>;

/// An error that occurred during a SPIFFE ID operation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    /// The trust domain contains an invalid character.
    #[error("trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores")]
    BadTrustDomainChar,
    /// The path contains an invalid character.
    #[error(
        "path segment characters are limited to letters, numbers, dots, dashes, and underscores"
    )]
    BadPathSegmentChar,
    /// The path contains a dot segment (`.` or `..`).
    #[error("path cannot contain dot segments")]
    DotSegment,
    /// The path is missing a leading slash.
    #[error("path must have a leading slash")]
    NoLeadingSlash,
    /// The SPIFFE ID or component is empty.
    #[error("cannot be empty")]
    Empty,
    /// The path contains an empty segment.
    #[error("path cannot contain empty segments")]
    EmptySegment,
    /// The trust domain component is missing.
    #[error("trust domain is missing")]
    MissingTrustDomain,
    /// The path has a trailing slash.
    #[error("path cannot have a trailing slash")]
    TrailingSlash,
    /// The scheme is missing or invalid (expected `spiffe://`).
    #[error("scheme is missing or invalid")]
    WrongScheme,
    /// An unexpected error occurred.
    #[error("{0}")]
    Other(String),
}
