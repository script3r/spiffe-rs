use spiffe_rs::bundle::x509bundle::{Bundle, Set};
use spiffe_rs::spiffeid::require_trust_domain_from_string;
use std::fs;

fn load_file(path: &str) -> Vec<u8> {
    fs::read(path).expect("read testdata")
}

fn load_raw_certificates(path: &str) -> Vec<u8> {
    let pem_bytes = load_file(path);
    let pems = pem::parse_many(pem_bytes).expect("pem parse");
    let mut out = Vec::new();
    for pem in pems {
        if pem.tag() == "CERTIFICATE" {
            out.extend_from_slice(pem.contents());
        }
    }
    out
}

#[test]
fn bundle_parse_load_and_read() {
    let td = require_trust_domain_from_string("domain.test");
    let bundle = Bundle::load(td.clone(), "tests/testdata/x509bundle/certs.pem").expect("load");
    assert_eq!(bundle.x509_authorities().len(), 2);

    let bytes = load_file("tests/testdata/x509bundle/cert.pem");
    let bundle = Bundle::parse(td.clone(), &bytes).expect("parse");
    assert_eq!(bundle.x509_authorities().len(), 1);

    let bytes = load_file("tests/testdata/x509bundle/empty.pem");
    let bundle = Bundle::parse(td.clone(), &bytes).expect("parse");
    assert!(bundle.empty());
}

#[test]
fn bundle_parse_errors() {
    let td = require_trust_domain_from_string("domain.test");
    let err = Bundle::load(td.clone(), "tests/testdata/x509bundle/does-not-exist.pem")
        .unwrap_err()
        .to_string();
    assert!(err.contains("x509bundle: unable to load X.509 bundle file"));

    let bytes = load_file("tests/testdata/x509bundle/not-pem.pem");
    let err = Bundle::parse(td.clone(), &bytes).unwrap_err().to_string();
    assert!(err.contains("x509bundle: cannot parse certificate: no PEM blocks found"));
}

#[test]
fn bundle_parse_raw() {
    let td = require_trust_domain_from_string("domain.test");
    let bytes = load_raw_certificates("tests/testdata/x509bundle/certs.pem");
    let bundle = Bundle::parse_raw(td.clone(), &bytes).expect("parse raw");
    assert_eq!(bundle.x509_authorities().len(), 2);
}

#[test]
fn bundle_crud_and_clone() {
    let td = require_trust_domain_from_string("domain.test");
    let td2 = require_trust_domain_from_string("domain2.test");

    let bundle1 = Bundle::load(td.clone(), "tests/testdata/x509bundle/cert.pem").expect("load");
    let bundle2 = Bundle::load(td2, "tests/testdata/x509bundle/certs.pem").expect("load");
    assert!(bundle1.has_x509_authority(&bundle1.x509_authorities()[0]));
    assert!(bundle2.has_x509_authority(&bundle1.x509_authorities()[0]));

    bundle1.add_x509_authority(&bundle2.x509_authorities()[1]);
    assert_eq!(bundle1.x509_authorities().len(), 2);
    bundle1.add_x509_authority(&bundle2.x509_authorities()[1]);
    assert_eq!(bundle1.x509_authorities().len(), 2);

    bundle1.remove_x509_authority(&bundle2.x509_authorities()[0]);
    assert_eq!(bundle1.x509_authorities().len(), 1);

    let cloned = bundle1.clone_bundle();
    assert!(bundle1.equal(&cloned));
}

#[test]
fn bundle_get_for_trust_domain() {
    let td = require_trust_domain_from_string("domain.test");
    let td2 = require_trust_domain_from_string("domain2.test");
    let bundle = Bundle::new(td.clone());
    let ok = bundle
        .get_x509_bundle_for_trust_domain(td.clone())
        .expect("bundle");
    assert!(bundle.equal(&ok));

    let err = bundle
        .get_x509_bundle_for_trust_domain(td2)
        .unwrap_err()
        .to_string();
    assert_eq!(
        err,
        "x509bundle: no X.509 bundle found for trust domain: \"domain2.test\""
    );
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
        .get_x509_bundle_for_trust_domain(td2.clone())
        .unwrap()
        .trust_domain();
    assert_eq!(err, td2);

    let err = set
        .get_x509_bundle_for_trust_domain(require_trust_domain_from_string("missing.test"))
        .unwrap_err()
        .to_string();
    assert_eq!(
        err,
        "x509bundle: no X.509 bundle for trust domain \"missing.test\""
    );
}
