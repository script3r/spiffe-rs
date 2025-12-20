use crate::spiffeid::{
    format_path, join_path_segments, trust_domain_from_string, trust_domain_from_uri, ID, Result,
    TrustDomain,
};
use url::Url;

pub fn require_from_path(td: TrustDomain, path: &str) -> ID {
    panic_on_err(ID::from_path(td, path))
}

pub fn require_from_pathf(td: TrustDomain, args: std::fmt::Arguments<'_>) -> ID {
    panic_on_err(ID::from_pathf(td, args))
}

pub fn require_from_segments(td: TrustDomain, segments: &[&str]) -> ID {
    panic_on_err(ID::from_segments(td, segments))
}

pub fn require_from_string(s: &str) -> ID {
    panic_on_err(ID::from_string(s))
}

pub fn require_from_stringf(args: std::fmt::Arguments<'_>) -> ID {
    panic_on_err(ID::from_stringf(args))
}

pub fn require_from_uri(uri: &Url) -> ID {
    panic_on_err(ID::from_uri(uri))
}

pub fn require_trust_domain_from_string(s: &str) -> TrustDomain {
    panic_on_err(trust_domain_from_string(s))
}

pub fn require_trust_domain_from_uri(uri: &Url) -> TrustDomain {
    panic_on_err(trust_domain_from_uri(uri))
}

pub fn require_format_path(args: std::fmt::Arguments<'_>) -> String {
    panic_on_err(format_path(args))
}

pub fn require_join_path_segments(segments: &[&str]) -> String {
    panic_on_err(join_path_segments(segments))
}

fn panic_on_err<T>(result: Result<T>) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{err}"),
    }
}
