use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores")]
    BadTrustDomainChar,
    #[error("path segment characters are limited to letters, numbers, dots, dashes, and underscores")]
    BadPathSegmentChar,
    #[error("path cannot contain dot segments")]
    DotSegment,
    #[error("path must have a leading slash")]
    NoLeadingSlash,
    #[error("cannot be empty")]
    Empty,
    #[error("path cannot contain empty segments")]
    EmptySegment,
    #[error("trust domain is missing")]
    MissingTrustDomain,
    #[error("path cannot have a trailing slash")]
    TrailingSlash,
    #[error("scheme is missing or invalid")]
    WrongScheme,
    #[error("{0}")]
    Other(String),
}
