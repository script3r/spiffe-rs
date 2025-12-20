use spiffe_rs::spiffeid;
use spiffe_rs::spiffetls;
use spiffe_rs::workloadapi;
use std::sync::Arc;
use hyper::Uri;
use std::io;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

pub mod helloworld {
    tonic::include_proto!("helloworld");
}

use helloworld::greeter_client::GreeterClient;
use helloworld::HelloRequest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_socket_env();
    let ctx = workloadapi::background();

    let source = Arc::new(workloadapi::X509Source::new(&ctx, Vec::new()).await?);
    let server_id = spiffeid::require_from_string("spiffe://example.org/server");
    let authorizer = spiffetls::tlsconfig::authorize_id(server_id);
    let mut tls_config = spiffetls::tlsconfig::mtls_client_config(source.as_ref(), source.clone(), authorizer)?;
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(tls_config));

    let endpoint = Endpoint::from_shared("https://127.0.0.1:50051".to_string())?;
    let channel: Channel = endpoint
        .connect_with_connector(service_fn(move |uri: Uri| {
            let connector = connector.clone();
            async move {
                let authority = uri
                    .authority()
                    .map(|auth| auth.as_str())
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing authority"))?;
                let stream = TcpStream::connect(authority).await?;
                let server_name = rustls::ServerName::try_from("example.org")
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
                connector.connect(server_name, stream).await.map_err(|err| {
                    io::Error::new(io::ErrorKind::Other, err)
                })
            }
        }))
        .await?;

    let mut client = GreeterClient::new(channel);
    let response = client
        .say_hello(HelloRequest {
            name: "world".to_string(),
        })
        .await?;

    println!("response: {}", response.into_inner().message);
    Ok(())
}

fn ensure_socket_env() {
    if std::env::var("SPIFFE_ENDPOINT_SOCKET").is_err() {
        std::env::set_var("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/agent.sock");
    }
}
