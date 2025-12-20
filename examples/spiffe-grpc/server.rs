use spiffe_rs::spiffeid;
use spiffe_rs::spiffetls;
use spiffe_rs::workloadapi;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tonic::transport::server::Connected;
use std::pin::Pin;
use std::task::{Context, Poll};

pub mod helloworld {
    tonic::include_proto!("helloworld");
}

use helloworld::greeter_server::{Greeter, GreeterServer};
use helloworld::{HelloReply, HelloRequest};

#[derive(Default)]
struct GreeterService;

#[tonic::async_trait]
impl Greeter for GreeterService {
    async fn say_hello(&self, request: Request<HelloRequest>) -> Result<Response<HelloReply>, Status> {
        let name = request.into_inner().name;
        let reply = HelloReply {
            message: format!("Hello {}", name),
        };
        Ok(Response::new(reply))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_socket_env();
    let ctx = workloadapi::background();

    let source = Arc::new(workloadapi::X509Source::new(&ctx, Vec::new()).await?);
    let client_id = spiffeid::require_from_string("spiffe://example.org/client");
    let authorizer = spiffetls::tlsconfig::authorize_id(client_id);
    let mut tls_config = spiffetls::tlsconfig::mtls_server_config(source.as_ref(), source.clone(), authorizer)?;
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind("127.0.0.1:50051").await?;
    println!("gRPC server listening on 127.0.0.1:50051");

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<TlsIo, std::io::Error>>(32);
    let acceptor = acceptor.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(err) => {
                    eprintln!("accept error: {}", err);
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let tls = match acceptor.accept(stream).await {
                    Ok(tls) => tls,
                    Err(err) => {
                        eprintln!("tls error: {}", err);
                        return;
                    }
                };
                let _ = tx.send(Ok(TlsIo(tls))).await;
            });
        }
    });

    let incoming = ReceiverStream::new(rx);
    Server::builder()
        .add_service(GreeterServer::new(GreeterService::default()))
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}

struct TlsIo(tokio_rustls::server::TlsStream<tokio::net::TcpStream>);

impl Connected for TlsIo {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl AsyncRead for TlsIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, data)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

fn ensure_socket_env() {
    if std::env::var("SPIFFE_ENDPOINT_SOCKET").is_err() {
        std::env::set_var("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/agent.sock");
    }
}
