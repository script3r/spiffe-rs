use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use spiffe_rs::spiffeid;
use spiffe_rs::spiffetls;
use spiffe_rs::workloadapi;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_socket_env();
    let ctx = workloadapi::background();

    let source = Arc::new(workloadapi::X509Source::new(&ctx, Vec::new()).await?);
    let client_id = spiffeid::require_from_string("spiffe://example.org/client");
    let authorizer = spiffetls::tlsconfig::authorize_id(client_id);
    let tls_config =
        spiffetls::tlsconfig::mtls_server_config(source.as_ref(), source.clone(), authorizer)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind("127.0.0.1:8443").await?;
    println!("HTTP server listening on 127.0.0.1:8443");

    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(stream).await {
                Ok(tls) => tls,
                Err(err) => {
                    eprintln!("tls error: {}", err);
                    return;
                }
            };
            let service = service_fn(handle_request);
            if let Err(err) = hyper::server::conn::Http::new()
                .serve_connection(tls, service)
                .await
            {
                eprintln!("http error: {}", err);
            }
        });
    }
}

async fn handle_request(_req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    println!("Request received");
    Ok(Response::new(Body::from("Success!!!")))
}

fn ensure_socket_env() {
    if std::env::var("SPIFFE_ENDPOINT_SOCKET").is_err() {
        std::env::set_var("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/agent.sock");
    }
}
