use spiffe_rs::spiffeid::{
    join_path_segments, trust_domain_from_string, validate_path, validate_path_segment, Error, ID,
};
use url::Url;

#[test]
fn from_string_accepts_basic_id() {
    let id = ID::from_string("spiffe://example.org/workload").expect("valid spiffe ID");
    assert_eq!(id.trust_domain().name(), "example.org");
    assert_eq!(id.path(), "/workload");
}

#[test]
fn from_string_rejects_bad_scheme() {
    let err = ID::from_string("spiffe:/example.org").unwrap_err();
    assert_eq!(err.to_string(), Error::WrongScheme.to_string());
}

#[test]
fn from_uri_round_trip() {
    let url = Url::parse("spiffe://example.org/service").expect("url parse");
    let id = ID::from_uri(&url).expect("spiffe id");
    assert_eq!(id.to_string(), "spiffe://example.org/service");
}

#[test]
fn validate_path_rules() {
    assert!(validate_path("").is_ok());
    assert!(validate_path("/").is_err());
    assert!(validate_path("/.").is_err());
    assert!(validate_path("/..").is_err());
    assert!(validate_path("/good/path").is_ok());
}

#[test]
fn validate_path_segment_rules() {
    assert!(validate_path_segment("").is_err());
    assert!(validate_path_segment(".").is_err());
    assert!(validate_path_segment("..").is_err());
    assert!(validate_path_segment("seg").is_ok());
}

#[test]
fn join_segments_builds_path() {
    let path = join_path_segments(&["foo", "bar"]).expect("join segments");
    assert_eq!(path, "/foo/bar");
}

#[test]
fn trust_domain_from_string_accepts_id() {
    let td = trust_domain_from_string("spiffe://example.org").expect("trust domain");
    assert_eq!(td.name(), "example.org");
}
