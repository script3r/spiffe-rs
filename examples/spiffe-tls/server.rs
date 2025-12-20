use spiffe_rs::spiffeid;
use spiffe_rs::spiffetls;
use spiffe_rs::workloadapi;
use std::io::{Read, Write};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_socket_env();
    let ctx = workloadapi::background();

    let client_id = spiffeid::require_from_string("spiffe://example.org/client");
    let authorizer = spiffetls::tlsconfig::authorize_id(client_id);
    let listener = spiffetls::listen(&ctx, "127.0.0.1:55555", authorizer, Vec::new()).await?;

    println!("listening on {}", listener.local_addr()?);
    let mut stream = listener.accept()?;
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    let message = String::from_utf8_lossy(&buf[..n]);
    println!("received: {}", message);

    stream.write_all(b"Hello client")?;
    stream.flush()?;
    Ok(())
}

fn ensure_socket_env() {
    if std::env::var("SPIFFE_ENDPOINT_SOCKET").is_err() {
        std::env::set_var("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/agent.sock");
    }
}
