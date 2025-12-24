use spiffe_rs::bundle::jwtbundle::JwtKey;
use spiffe_rs::bundle::jwtbundle::{Bundle, Set};
use spiffe_rs::spiffeid::require_trust_domain_from_string;
use std::collections::HashMap;
use std::fs;

fn load_file(path: &str) -> Vec<u8> {
    fs::read(path).expect("read testdata")
}

#[test]
fn bundle_load_read_parse() {
    let td = require_trust_domain_from_string("example.org");
    let bundle =
        Bundle::load(td.clone(), "tests/testdata/jwtbundle/jwks_valid_1.json").expect("load");
    assert_eq!(bundle.jwt_authorities().len(), 1);

    let bytes = load_file("tests/testdata/jwtbundle/jwks_valid_2.json");
    let bundle = Bundle::parse(td.clone(), &bytes).expect("parse");
    assert_eq!(bundle.jwt_authorities().len(), 2);
}

#[test]
fn bundle_parse_errors() {
    let td = require_trust_domain_from_string("example.org");
    let err = Bundle::load(td.clone(), "tests/testdata/jwtbundle/does-not-exist.json")
        .unwrap_err()
        .to_string();
    assert!(err.contains("jwtbundle: unable to read JWT bundle"));

    let bytes = load_file("tests/testdata/jwtbundle/jwks_missing_kid.json");
    let err = Bundle::parse(td.clone(), &bytes).unwrap_err().to_string();
    assert_eq!(
        err,
        "jwtbundle: error adding authority 1 of JWKS: keyID cannot be empty"
    );
}

#[test]
fn bundle_crud_and_equal() {
    let td = require_trust_domain_from_string("example.org");
    let mut authorities = HashMap::new();
    authorities.insert(
        "key-1".to_string(),
        JwtKey::Ec {
            crv: "P-256".to_string(),
            x: vec![1],
            y: vec![2],
        },
    );
    let bundle = Bundle::from_jwt_authorities(td.clone(), &authorities);
    assert!(bundle.has_jwt_authority("key-1"));
    assert!(bundle.find_jwt_authority("key-1").is_some());

    bundle.remove_jwt_authority("key-1");
    assert!(!bundle.has_jwt_authority("key-1"));

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

    let cloned = bundle.clone_bundle();
    assert!(bundle.equal(&cloned));
}

#[test]
fn bundle_marshal_roundtrip() {
    let td = require_trust_domain_from_string("example.org");
    let bundle =
        Bundle::load(td.clone(), "tests/testdata/jwtbundle/jwks_valid_2.json").expect("load");
    let bytes = bundle.marshal().expect("marshal");
    let parsed = Bundle::parse(td, &bytes).expect("parse");
    assert!(bundle.equal(&parsed));
}

#[test]
fn bundle_get_for_trust_domain() {
    let td = require_trust_domain_from_string("example.org");
    let td2 = require_trust_domain_from_string("example-2.org");
    let bundle = Bundle::new(td.clone());
    let ok = bundle
        .get_jwt_bundle_for_trust_domain(td.clone())
        .expect("bundle");
    assert!(bundle.equal(&ok));

    let err = bundle
        .get_jwt_bundle_for_trust_domain(td2)
        .unwrap_err()
        .to_string();
    assert_eq!(
        err,
        "jwtbundle: no JWT bundle for trust domain \"example-2.org\""
    );
}

#[test]
fn set_ops() {
    let td = require_trust_domain_from_string("example.org");
    let td2 = require_trust_domain_from_string("example-2.org");
    let b1 = Bundle::new(td.clone());
    let b2 = Bundle::new(td2.clone());

    let set = Set::new(&[b1.clone_bundle()]);
    assert!(set.has(td.clone()));
    assert!(!set.has(td2.clone()));

    set.add(&b2);
    assert!(set.has(td2.clone()));

    let err = set
        .get_jwt_bundle_for_trust_domain(require_trust_domain_from_string("missing.test"))
        .unwrap_err()
        .to_string();
    assert_eq!(
        err,
        "jwtbundle: no JWT bundle for trust domain \"missing.test\""
    );
}
