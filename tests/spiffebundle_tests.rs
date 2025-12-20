use spiffe_rs::bundle::jwtbundle;
use spiffe_rs::bundle::spiffebundle::{Bundle, Set};
use spiffe_rs::bundle::x509bundle;
use spiffe_rs::bundle::spiffebundle::JwtKey;
use spiffe_rs::spiffeid::require_trust_domain_from_string;
use std::fs;
use std::time::Duration;

fn load_file(path: &str) -> Vec<u8> {
    fs::read(path).expect("read testdata")
}

#[test]
fn bundle_load_read_parse() {
    let td = require_trust_domain_from_string("domain.test");
    let bytes = load_file("tests/testdata/spiffebundle/spiffebundle_valid_1.json");
    let bundle = Bundle::parse(td.clone(), &bytes).expect("parse");
    assert_eq!(bundle.jwt_authorities().len(), 1);
    assert_eq!(bundle.x509_authorities().len(), 1);
}

#[test]
fn bundle_parse_errors() {
    let td = require_trust_domain_from_string("domain.test");
    let bytes = load_file("tests/testdata/spiffebundle/spiffebundle_missing_kid.json");
    let err = Bundle::parse(td.clone(), &bytes).unwrap_err().to_string();
    assert_eq!(
        err,
        "spiffebundle: error adding authority 1 of JWKS: keyID cannot be empty"
    );

    let bytes = load_file("tests/testdata/spiffebundle/spiffebundle_no_keys.json");
    let err = Bundle::parse(td.clone(), &bytes).unwrap_err().to_string();
    assert_eq!(err, "spiffebundle: no authorities found");
}

#[test]
fn bundle_refresh_hint_and_sequence() {
    let td = require_trust_domain_from_string("domain.test");
    let bundle = Bundle::new(td);
    assert!(bundle.refresh_hint().is_none());
    assert!(bundle.sequence_number().is_none());

    bundle.set_refresh_hint(Duration::from_secs(30));
    assert_eq!(bundle.refresh_hint().unwrap(), Duration::from_secs(30));

    bundle.set_sequence_number(5);
    assert_eq!(bundle.sequence_number().unwrap(), 5);

    bundle.clear_refresh_hint();
    bundle.clear_sequence_number();
    assert!(bundle.refresh_hint().is_none());
    assert!(bundle.sequence_number().is_none());
}

#[test]
fn bundle_marshal_roundtrip() {
    let td = require_trust_domain_from_string("domain.test");
    let bundle = Bundle::load(td.clone(), "tests/testdata/spiffebundle/spiffebundle_valid_2.json")
        .expect("load");
    let bytes = bundle.marshal().expect("marshal");
    let parsed = Bundle::parse(td, &bytes).expect("parse");
    assert!(bundle.equal(&parsed));
}

#[test]
fn bundle_x509_and_jwt_views() {
    let td = require_trust_domain_from_string("domain.test");
    let x509_bundle = x509bundle::Bundle::load(td.clone(), "tests/testdata/x509bundle/cert.pem").expect("load");
    let bundle = Bundle::from_x509_bundle(&x509_bundle);
    assert_eq!(bundle.x509_authorities().len(), 1);

    let jwt_bundle = jwtbundle::Bundle::load(td.clone(), "tests/testdata/jwtbundle/jwks_valid_1.json").expect("load");
    let bundle = Bundle::from_jwt_bundle(&jwt_bundle);
    assert_eq!(bundle.jwt_authorities().len(), 1);
}

#[test]
fn bundle_jwt_and_x509_crud() {
    let td = require_trust_domain_from_string("domain.test");
    let bundle = Bundle::new(td);
    bundle.add_x509_authority(b"CERT1");
    assert!(bundle.has_x509_authority(b"CERT1"));
    bundle.remove_x509_authority(b"CERT1");
    assert!(!bundle.has_x509_authority(b"CERT1"));

    bundle
        .add_jwt_authority(
            "key-1",
            JwtKey::Ec {
                crv: "P-256".to_string(),
                x: vec![1],
                y: vec![2],
            },
        )
        .expect("add");
    assert!(bundle.has_jwt_authority("key-1"));
    bundle.remove_jwt_authority("key-1");
    assert!(!bundle.has_jwt_authority("key-1"));
}

#[test]
fn bundle_get_for_trust_domain() {
    let td = require_trust_domain_from_string("domain.test");
    let td2 = require_trust_domain_from_string("domain2.test");
    let bundle = Bundle::new(td.clone());
    let ok = bundle.get_bundle_for_trust_domain(td.clone()).expect("bundle");
    assert!(bundle.equal(&ok));

    let err = bundle
        .get_bundle_for_trust_domain(td2)
        .unwrap_err()
        .to_string();
    assert_eq!(err, "spiffebundle: no SPIFFE bundle for trust domain \"domain2.test\"");
}

#[test]
fn set_ops() {
    let td = require_trust_domain_from_string("domain.test");
    let td2 = require_trust_domain_from_string("domain2.test");
    let b1 = Bundle::new(td.clone());
    let b2 = Bundle::new(td2.clone());

    let set = Set::new(&[b1.clone_bundle()]);
    assert!(set.has(td.clone()));
    assert!(!set.has(td2.clone()));

    set.add(&b2);
    assert!(set.has(td2.clone()));

    let err = set
        .get_bundle_for_trust_domain(require_trust_domain_from_string("missing.test"))
        .unwrap_err()
        .to_string();
    assert_eq!(err, "spiffebundle: no SPIFFE bundle for trust domain \"missing.test\"");
}
