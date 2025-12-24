use spiffe_rs::bundle::spiffebundle;
use spiffe_rs::bundle::x509bundle;
use spiffe_rs::federation;
use spiffe_rs::spiffeid;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

fn start_test_server(body: Vec<u8>) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
    let addr = listener.local_addr().expect("local addr");
    let url = format!("http://{}/bundle", addr);
    let handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(&body);
        }
    });
    (url, handle)
}

#[test]
fn fetch_bundle_over_http() {
    let trust_domain = spiffeid::require_trust_domain_from_string("domain.test");
    let body = fs::read("tests/testdata/spiffebundle/spiffebundle_valid_1.json")
        .expect("read test bundle");
    let expected = spiffebundle::Bundle::parse(trust_domain.clone(), &body).expect("parse bundle");
    let (url, handle) = start_test_server(body);

    let bundle = federation::fetch_bundle(trust_domain, &url, &[]).expect("fetch bundle");
    assert!(bundle.equal(&expected));

    let _ = handle.join();
}

#[test]
fn fetch_bundle_option_conflict() {
    let trust_domain = spiffeid::require_trust_domain_from_string("domain.test");
    let id = spiffeid::require_from_string("spiffe://domain.test/workload");
    let bundle_source = Arc::new(x509bundle::Bundle::from_x509_authorities(trust_domain, &[]));
    let options: Vec<Box<dyn federation::FetchOption>> = vec![
        Box::new(federation::with_spiffe_auth(bundle_source, id)),
        Box::new(federation::with_web_pki_roots(
            rustls::RootCertStore::empty(),
        )),
    ];

    let err = federation::fetch_bundle(
        spiffeid::require_trust_domain_from_string("domain.test"),
        "http://example.org",
        &options,
    )
    .expect_err("expected option error");
    assert_eq!(
        err.to_string(),
        "federation: cannot use both SPIFFE and Web PKI authentication"
    );
}

#[test]
fn fetch_bundle_invalid_url() {
    let trust_domain = spiffeid::require_trust_domain_from_string("domain.test");
    let err = federation::fetch_bundle(trust_domain, "not a url", &[])
        .expect_err("expected invalid URL error");
    assert!(err.to_string().starts_with("federation: invalid URL"));
}
