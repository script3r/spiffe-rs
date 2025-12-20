use spiffe_rs::bundle::jwtbundle;
use spiffe_rs::workloadapi;
use spiffe_rs::workloadapi::{JWTBundleWatcher, X509Context, X509ContextWatcher};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_socket_env();
    let ctx = workloadapi::background();
    let client = Arc::new(workloadapi::Client::new(client_options()).await?);

    let x509 = Arc::new(PrintingX509Watcher);
    let jwt = Arc::new(PrintingJWTWatcher);

    let ctx_x509 = ctx.clone();
    let client_x509 = client.clone();
    tokio::spawn(async move {
        if let Err(err) = client_x509.watch_x509_context(&ctx_x509, x509).await {
            eprintln!("x509 watch error: {}", err);
        }
    });

    let ctx_jwt = ctx.clone();
    let client_jwt = client.clone();
    tokio::spawn(async move {
        if let Err(err) = client_jwt.watch_jwt_bundles(&ctx_jwt, jwt).await {
            eprintln!("jwt watch error: {}", err);
        }
    });

    tokio::signal::ctrl_c().await?;
    ctx.cancel();
    Ok(())
}

struct PrintingX509Watcher;

impl X509ContextWatcher for PrintingX509Watcher {
    fn on_x509_context_update(&self, context: X509Context) {
        for svid in context.svids.iter() {
            println!("SVID updated for \"{}\"", svid.id.to_string());
        }
    }

    fn on_x509_context_watch_error(&self, err: spiffe_rs::workloadapi::Error) {
        eprintln!("x509 watch error: {}", err);
    }
}

struct PrintingJWTWatcher;

impl JWTBundleWatcher for PrintingJWTWatcher {
    fn on_jwt_bundles_update(&self, bundles: jwtbundle::Set) {
        for bundle in bundles.bundles() {
            if let Ok(json) = bundle.marshal() {
                println!(
                    "jwt bundle updated \"{}\": {}",
                    bundle.trust_domain().to_string(),
                    String::from_utf8_lossy(&json)
                );
            }
        }
    }

    fn on_jwt_bundles_watch_error(&self, err: spiffe_rs::workloadapi::Error) {
        eprintln!("jwt watch error: {}", err);
    }
}

fn client_options() -> Vec<Arc<dyn workloadapi::ClientOption>> {
    let addr = std::env::var("SPIFFE_ENDPOINT_SOCKET")
        .ok()
        .unwrap_or_else(|| "unix:///tmp/agent.sock".to_string());
    vec![workloadapi::with_addr(addr)]
}

fn ensure_socket_env() {
    if std::env::var("SPIFFE_ENDPOINT_SOCKET").is_err() {
        std::env::set_var("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/agent.sock");
    }
}
