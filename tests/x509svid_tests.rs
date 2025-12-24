use spiffe_rs::spiffeid::ID;
use spiffe_rs::svid::x509svid;
use std::fs;

fn load_file(path: &str) -> Vec<u8> {
    fs::read(path).expect("read testdata")
}

fn normalize_pem(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' && i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

fn load_raw_certificates(path: &str) -> Vec<u8> {
    let bytes = load_file(path);
    let pems = pem::parse_many(bytes).expect("pem parse");
    let mut out = Vec::new();
    for pem in pems {
        if pem.tag() == "CERTIFICATE" {
            out.extend_from_slice(pem.contents());
        }
    }
    out
}

#[test]
fn parse_success_cases() {
    let key_rsa = "tests/testdata/x509svid/key-pkcs8-rsa.pem";
    let cert_single = "tests/testdata/x509svid/good-leaf-only.pem";
    let cert_multi = "tests/testdata/x509svid/good-leaf-and-intermediate.pem";
    let key_ecdsa = "tests/testdata/x509svid/key-pkcs8-ecdsa.pem";

    let svid = x509svid::SVID::load(cert_single, key_rsa).expect("load");
    assert_eq!(svid.id.to_string(), "spiffe://example.org/workload-1");
    assert_eq!(svid.certificates.len(), 1);

    let cert_bytes = load_file(cert_multi);
    let key_bytes = load_file(key_ecdsa);
    let svid = x509svid::SVID::parse(&cert_bytes, &key_bytes).expect("parse");
    assert_eq!(svid.certificates.len(), 2);
}

#[test]
fn parse_error_cases() {
    let key_rsa = "tests/testdata/x509svid/key-pkcs8-rsa.pem";
    let cert_single = "tests/testdata/x509svid/good-leaf-only.pem";
    let not_pem = "tests/testdata/x509svid/not-pem";

    let cert_bytes = load_file(cert_single);
    let key_bytes = load_file(not_pem);
    let err = x509svid::SVID::parse(&cert_bytes, &key_bytes)
        .unwrap_err()
        .to_string();
    assert!(err.contains("cannot parse PEM encoded private key"));

    let cert_bytes = load_file(not_pem);
    let key_bytes = load_file(key_rsa);
    let err = x509svid::SVID::parse(&cert_bytes, &key_bytes)
        .unwrap_err()
        .to_string();
    assert!(err.contains("cannot parse PEM encoded certificate"));
}

#[test]
fn marshal_roundtrip() {
    let key_rsa = "tests/testdata/x509svid/key-pkcs8-rsa.pem";
    let cert_single = "tests/testdata/x509svid/good-leaf-only.pem";
    let svid = x509svid::SVID::load(cert_single, key_rsa).expect("load");
    let (certs, key) = svid.marshal().expect("marshal");
    assert_eq!(
        normalize_pem(&certs),
        normalize_pem(&load_file(cert_single))
    );
    assert_eq!(normalize_pem(&key), normalize_pem(&load_file(key_rsa)));
}

#[test]
fn marshal_raw_roundtrip() {
    let key_rsa = "tests/testdata/x509svid/key-pkcs8-rsa.pem";
    let cert_single = "tests/testdata/x509svid/good-leaf-only.pem";
    let svid = x509svid::SVID::load(cert_single, key_rsa).expect("load");
    let (certs, key) = svid.marshal_raw().expect("marshal raw");
    assert_eq!(certs, load_raw_certificates(cert_single));

    let key_der = {
        let key_bytes = load_file(key_rsa);
        let pems = pem::parse_many(key_bytes).expect("pem parse");
        pems.iter()
            .find(|p| p.tag() == "PRIVATE KEY")
            .map(|p| p.contents().to_vec())
            .expect("private key")
    };
    assert_eq!(key, key_der);
}

#[test]
fn parse_raw_roundtrip() {
    let key_rsa = "tests/testdata/x509svid/key-pkcs8-rsa.pem";
    let cert_single = "tests/testdata/x509svid/good-leaf-only.pem";
    let cert_raw = load_raw_certificates(cert_single);
    let key_der = {
        let key_bytes = load_file(key_rsa);
        let pems = pem::parse_many(key_bytes).expect("pem parse");
        pems.iter()
            .find(|p| p.tag() == "PRIVATE KEY")
            .map(|p| p.contents().to_vec())
            .expect("private key")
    };
    let svid = x509svid::SVID::parse_raw(&cert_raw, &key_der).expect("parse raw");
    assert_eq!(
        svid.id,
        ID::from_string("spiffe://example.org/workload-1").unwrap()
    );
}
