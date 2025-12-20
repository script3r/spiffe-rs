use hyper::service::service_fn;
use hyper::{Body, Request, Response, StatusCode};
use spiffe_rs::spiffeid;
use spiffe_rs::spiffetls;
use spiffe_rs::svid::jwtsvid;
use spiffe_rs::workloadapi;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_socket_env();
    let ctx = workloadapi::background();

    let x509_source = Arc::new(workloadapi::X509Source::new(&ctx, Vec::new()).await?);
    let tls_config = spiffetls::tlsconfig::tls_server_config(x509_source.as_ref())?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let jwt_source = Arc::new(workloadapi::JWTSource::new(&ctx, Vec::new()).await?);
    let audience = spiffeid::require_from_string("spiffe://example.org/server").to_string();

    let listener = TcpListener::bind("127.0.0.1:8443").await?;
    println!("JWT HTTP server listening on 127.0.0.1:8443");

    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let jwt_source = jwt_source.clone();
        let audience = audience.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(stream).await {
                Ok(tls) => tls,
                Err(err) => {
                    eprintln!("tls error: {}", err);
                    return;
                }
            };
            let service = service_fn(move |req| handle_request(req, jwt_source.clone(), audience.clone()));
            if let Err(err) = hyper::server::conn::Http::new()
                .serve_connection(tls, service)
                .await
            {
                eprintln!("http error: {}", err);
            }
        });
    }
}

async fn handle_request(
    req: Request<Body>,
    jwt_source: Arc<workloadapi::JWTSource>,
    audience: String,
) -> Result<Response<Body>, hyper::Error> {
    let token = match parse_bearer(req.headers().get("Authorization")) {
        Some(token) => token,
        None => return Ok(unauthorized("missing bearer token")),
    };

    match jwtsvid::parse_and_validate(&token, jwt_source.as_ref(), &[audience]) {
        Ok(_) => {
            println!("Request received");
            Ok(Response::new(Body::from("Success!!!")))
        }
        Err(err) => {
            eprintln!("Invalid token: {}", err);
            Ok(unauthorized("invalid token"))
        }
    }
}

fn parse_bearer(value: Option<&hyper::header::HeaderValue>) -> Option<String> {
    let value = value?.to_str().ok()?;
    let prefix = "Bearer ";
    if value.starts_with(prefix) {
        Some(value[prefix.len()..].trim().to_string())
    } else {
        None
    }
}

fn unauthorized(message: &str) -> Response<Body> {
    let mut response = Response::new(Body::from(message.to_string()));
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    response
}

fn ensure_socket_env() {
    if std::env::var("SPIFFE_ENDPOINT_SOCKET").is_err() {
        std::env::set_var("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/agent.sock");
    }
}
