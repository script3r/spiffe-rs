use spiffe_rs::bundle::spiffebundle;
use spiffe_rs::federation;
use spiffe_rs::spiffeid;
use spiffe_rs::workloadapi;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower::Service;

struct TestWatcher {
    updates: Arc<Mutex<Vec<spiffebundle::Bundle>>>,
    errors: Arc<Mutex<Vec<String>>>,
    cancel: workloadapi::Context,
}

impl federation::BundleWatcher for TestWatcher {
    fn next_refresh(&self, _refresh_hint: Duration) -> Duration {
        Duration::from_millis(10)
    }

    fn on_update(&self, bundle: spiffebundle::Bundle) {
        if let Ok(mut updates) = self.updates.lock() {
            updates.push(bundle);
            if updates.len() >= 2 {
                self.cancel.cancel();
            }
        }
    }

    fn on_error(&self, err: federation::Error) {
        if let Ok(mut errors) = self.errors.lock() {
            errors.push(err.to_string());
        }
    }
}

fn start_sequence_server(bodies: Vec<Vec<u8>>) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind server");
    let addr = listener.local_addr().expect("local addr");
    let url = format!("http://{}/bundle", addr);
    let queue = Arc::new(Mutex::new(bodies));
    let handle = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let body = queue
                .lock()
                .ok()
                .and_then(|mut q| {
                    if !q.is_empty() {
                        Some(q.remove(0))
                    } else {
                        None
                    }
                })
                .unwrap_or_default();
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

#[tokio::test]
async fn watch_bundle_updates() {
    let trust_domain = spiffeid::require_trust_domain_from_string("domain.test");
    let body1 = fs::read("tests/testdata/spiffebundle/spiffebundle_valid_1.json").expect("bundle");
    let body2 = fs::read("tests/testdata/spiffebundle/spiffebundle_valid_2.json").expect("bundle");
    let (url, handle) = start_sequence_server(vec![body1, body2]);

    let updates = Arc::new(Mutex::new(Vec::new()));
    let errors = Arc::new(Mutex::new(Vec::new()));
    let cancel = workloadapi::background();
    let watcher = Arc::new(TestWatcher {
        updates: updates.clone(),
        errors: errors.clone(),
        cancel: cancel.clone(),
    });

    let _ = federation::watch_bundle(&cancel, trust_domain, &url, watcher, Vec::new()).await;
    let _ = handle.join();

    let updates = updates.lock().expect("updates lock");
    assert_eq!(updates.len(), 2);
    assert!(errors.lock().expect("errors lock").is_empty());
}

#[tokio::test]
async fn handler_serves_bundle() {
    let trust_domain = spiffeid::require_trust_domain_from_string("domain.test");
    let body = fs::read("tests/testdata/spiffebundle/spiffebundle_valid_1.json").expect("bundle");
    let bundle = spiffebundle::Bundle::parse(trust_domain.clone(), &body).expect("parse bundle");
    let source = spiffebundle::Set::new(&[bundle.clone_bundle()]);
    let mut handler =
        federation::new_handler(trust_domain, Arc::new(source), Vec::new()).expect("handler");

    let response = Service::call(&mut handler, hyper::Request::new(hyper::Body::empty()))
        .await
        .expect("response");
    assert_eq!(response.status(), hyper::StatusCode::OK);

    let bytes = hyper::body::to_bytes(response.into_body())
        .await
        .expect("body bytes");
    assert_eq!(bytes.as_ref(), bundle.marshal().expect("marshal"));
}
