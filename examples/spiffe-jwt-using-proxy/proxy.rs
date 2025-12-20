use hyper::body::to_bytes;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use spiffe_rs::spiffeid;
use spiffe_rs::spiffetls;
use spiffe_rs::workloadapi;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_socket_env();
    let ctx = workloadapi::background();

    let x509_source = Arc::new(workloadapi::X509Source::new(&ctx, Vec::new()).await?);
    let server_tls = spiffetls::tlsconfig::tls_server_config(x509_source.as_ref())?;
    let acceptor = TlsAcceptor::from(Arc::new(server_tls));

    let server_id = spiffeid::require_from_string("spiffe://example.org/server");
    let authorizer = spiffetls::tlsconfig::authorize_id(server_id);
    let client_tls = spiffetls::tlsconfig::tls_client_config(x509_source.clone(), authorizer)?;
    let connector = TlsConnector::from(Arc::new(client_tls));

    let listener = TcpListener::bind("127.0.0.1:8443").await?;
    println!("proxy listening on 127.0.0.1:8443");

    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let connector = connector.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(stream).await {
                Ok(tls) => tls,
                Err(err) => {
                    eprintln!("tls error: {}", err);
                    return;
                }
            };
            let service = service_fn(move |req| forward_request(req, connector.clone()));
            if let Err(err) = hyper::server::conn::Http::new()
                .serve_connection(tls, service)
                .await
            {
                eprintln!("http error: {}", err);
            }
        });
    }
}

async fn forward_request(
    req: Request<Body>,
    connector: TlsConnector,
) -> Result<Response<Body>, hyper::Error> {
    println!("{} {}", req.method(), req.uri().path());

    let (parts, body) = req.into_parts();
    let body_bytes = match to_bytes(body).await {
        Ok(bytes) => bytes,
        Err(err) => return Ok(proxy_error(err.to_string())),
    };

    let stream = match TcpStream::connect("127.0.0.1:8080").await {
        Ok(stream) => stream,
        Err(err) => return Ok(proxy_error(err.to_string())),
    };
    let server_name = match rustls::ServerName::try_from("example.org") {
        Ok(name) => name,
        Err(err) => return Ok(proxy_error(err.to_string())),
    };
    let tls = match connector.connect(server_name, stream).await {
        Ok(tls) => tls,
        Err(err) => return Ok(proxy_error(err.to_string())),
    };

    let (mut sender, conn) = match hyper::client::conn::handshake(tls).await {
        Ok(parts) => parts,
        Err(err) => return Ok(proxy_error(err.to_string())),
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let mut builder = Request::builder().method(parts.method).uri(path);
    for (name, value) in parts.headers.iter() {
        builder = builder.header(name, value);
    }
    builder = builder.header("Host", "localhost");
    let request = match builder.body(Body::from(body_bytes)) {
        Ok(req) => req,
        Err(err) => return Ok(proxy_error(err.to_string())),
    };
    match sender.send_request(request).await {
        Ok(resp) => Ok(resp),
        Err(err) => Ok(proxy_error(err.to_string())),
    }
}

fn proxy_error(message: String) -> Response<Body> {
    let mut response = Response::new(Body::from(message));
    *response.status_mut() = hyper::StatusCode::BAD_GATEWAY;
    response
}

fn ensure_socket_env() {
    if std::env::var("SPIFFE_ENDPOINT_SOCKET").is_err() {
        std::env::set_var("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/agent.sock");
    }
}
