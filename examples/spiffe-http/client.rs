use hyper::body::to_bytes;
use hyper::{Body, Request};
use spiffe_rs::spiffeid;
use spiffe_rs::spiffetls;
use spiffe_rs::workloadapi;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_socket_env();
    let ctx = workloadapi::background();

    let source = Arc::new(workloadapi::X509Source::new(&ctx, Vec::new()).await?);
    let server_id = spiffeid::require_from_string("spiffe://example.org/server");
    let authorizer = spiffetls::tlsconfig::authorize_id(server_id);
    let tls_config =
        spiffetls::tlsconfig::mtls_client_config(source.as_ref(), source.clone(), authorizer)?;
    let connector = TlsConnector::from(Arc::new(tls_config));

    let stream = TcpStream::connect("127.0.0.1:8443").await?;
    let server_name = rustls::ServerName::try_from("example.org")?;
    let tls = connector.connect(server_name, stream).await?;

    let (mut sender, conn) = hyper::client::conn::handshake(tls).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let request = Request::builder()
        .uri("/")
        .header("Host", "localhost")
        .body(Body::empty())?;
    let response = sender.send_request(request).await?;
    let body = to_bytes(response.into_body()).await?;
    println!("{}", String::from_utf8_lossy(&body));
    Ok(())
}

fn ensure_socket_env() {
    if std::env::var("SPIFFE_ENDPOINT_SOCKET").is_err() {
        std::env::set_var("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/agent.sock");
    }
}
