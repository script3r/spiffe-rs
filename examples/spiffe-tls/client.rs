use spiffe_rs::spiffeid;
use spiffe_rs::spiffetls;
use spiffe_rs::workloadapi;
use std::io::{Read, Write};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_socket_env();
    let ctx = workloadapi::background();

    let server_id = spiffeid::require_from_string("spiffe://example.org/server");
    let authorizer = spiffetls::tlsconfig::authorize_id(server_id);
    let server_name = rustls::ServerName::try_from("example.org")?;
    let mut stream = spiffetls::dial(&ctx, "127.0.0.1:55555", server_name, authorizer, Vec::new()).await?;

    stream.write_all(b"Hello server")?;
    stream.flush()?;

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    let message = String::from_utf8_lossy(&buf[..n]);
    println!("received: {}", message);

    stream.close().await?;
    Ok(())
}

fn ensure_socket_env() {
    if std::env::var("SPIFFE_ENDPOINT_SOCKET").is_err() {
        std::env::set_var("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/agent.sock");
    }
}
