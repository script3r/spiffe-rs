use crate::workloadapi::{JWTBundleWatcher, Result, X509Context, X509ContextWatcher};
use crate::workloadapi::{option::WatcherConfig, Client, Context};
use std::sync::{Arc, Mutex};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub struct Watcher {
    updated_tx: watch::Sender<u64>,
    updated_rx: watch::Receiver<u64>,
    pub(crate) client: Arc<Client>,
    owns_client: bool,
    cancel: CancellationToken,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl Watcher {
    pub async fn new(
        ctx: &Context,
        config: WatcherConfig,
        x509_context_fn: Option<Arc<dyn Fn(X509Context) + Send + Sync>>,
        jwt_bundles_fn: Option<Arc<dyn Fn(crate::bundle::jwtbundle::Set) + Send + Sync>>,
    ) -> Result<Watcher> {
        let owns_client = config.client.is_none();
        let client = match config.client {
            Some(client) => client,
            None => Arc::new(Client::new(config.client_options).await?),
        };
        let cancel = CancellationToken::new();
        let (updated_tx, updated_rx) = watch::channel(0u64);
        let watcher = Watcher {
            updated_tx,
            updated_rx,
            client,
            owns_client,
            cancel,
            tasks: Mutex::new(Vec::new()),
        };

        watcher
            .spawn_watchers(ctx, x509_context_fn, jwt_bundles_fn)
            .await?;
        Ok(watcher)
    }

    pub async fn close(&self) -> Result<()> {
        self.cancel.cancel();
        if let Ok(mut tasks) = self.tasks.lock() {
            for task in tasks.drain(..) {
                let _ = task.await;
            }
        }
        if self.owns_client {
            self.client.close().await?;
        }
        Ok(())
    }

    pub async fn wait_until_updated(&self, ctx: &Context) -> Result<()> {
        let mut rx = self.updated_rx.clone();
        tokio::select! {
            _ = rx.changed() => Ok(()),
            _ = ctx.cancelled() => Err(crate::workloadapi::wrap_error("context canceled")),
        }
    }

    pub fn updated(&self) -> watch::Receiver<u64> {
        self.updated_rx.clone()
    }


    async fn spawn_watchers(
        &self,
        ctx: &Context,
        x509_context_fn: Option<Arc<dyn Fn(X509Context) + Send + Sync>>,
        jwt_bundles_fn: Option<Arc<dyn Fn(crate::bundle::jwtbundle::Set) + Send + Sync>>,
    ) -> Result<()> {
        let mut tasks = self.tasks.lock().expect("watcher task lock");
        let (err_tx, mut err_rx) = tokio::sync::mpsc::channel(2);

        if let Some(handler) = x509_context_fn.clone() {
            let (ready_tx, ready_rx) = oneshot::channel();
            let watcher = Arc::new(InternalX509Watcher {
                handler,
                ready: Mutex::new(Some(ready_tx)),
                updated: self.updated_tx.clone(),
            });
            let client = self.client.clone();
            let cancel = self.cancel.clone();
            let err_tx = err_tx.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(err) = client.watch_x509_context(&cancel, watcher).await {
                    let _ = err_tx.send(err).await;
                }
            }));
            wait_for_ready(&mut err_rx, ctx, ready_rx).await?;
        }

        if let Some(handler) = jwt_bundles_fn.clone() {
            let (ready_tx, ready_rx) = oneshot::channel();
            let watcher = Arc::new(InternalJWTWatcher {
                handler,
                ready: Mutex::new(Some(ready_tx)),
                updated: self.updated_tx.clone(),
            });
            let client = self.client.clone();
            let cancel = self.cancel.clone();
            let err_tx = err_tx.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(err) = client.watch_jwt_bundles(&cancel, watcher).await {
                    let _ = err_tx.send(err).await;
                }
            }));
            wait_for_ready(&mut err_rx, ctx, ready_rx).await?;
        }

        Ok(())
    }
}

struct InternalX509Watcher {
    handler: Arc<dyn Fn(X509Context) + Send + Sync>,
    ready: Mutex<Option<oneshot::Sender<()>>>,
    updated: watch::Sender<u64>,
}

impl X509ContextWatcher for InternalX509Watcher {
    fn on_x509_context_update(&self, context: X509Context) {
        (self.handler)(context);
        let _ = self.updated.send(*self.updated.borrow() + 1);
        if let Some(tx) = self.ready.lock().ok().and_then(|mut lock| lock.take()) {
            let _ = tx.send(());
        }
    }

    fn on_x509_context_watch_error(&self, _err: crate::workloadapi::Error) {}
}

struct InternalJWTWatcher {
    handler: Arc<dyn Fn(crate::bundle::jwtbundle::Set) + Send + Sync>,
    ready: Mutex<Option<oneshot::Sender<()>>>,
    updated: watch::Sender<u64>,
}

async fn wait_for_ready(
    err_rx: &mut tokio::sync::mpsc::Receiver<crate::workloadapi::Error>,
    ctx: &Context,
    mut ready_rx: oneshot::Receiver<()>,
) -> Result<()> {
    tokio::select! {
        _ = &mut ready_rx => Ok(()),
        err = err_rx.recv() => Err(err.unwrap_or_else(|| crate::workloadapi::wrap_error("watcher failed"))),
        _ = ctx.cancelled() => Err(crate::workloadapi::wrap_error("context canceled")),
    }
}

impl JWTBundleWatcher for InternalJWTWatcher {
    fn on_jwt_bundles_update(&self, bundles: crate::bundle::jwtbundle::Set) {
        (self.handler)(bundles);
        let _ = self.updated.send(*self.updated.borrow() + 1);
        if let Some(tx) = self.ready.lock().ok().and_then(|mut lock| lock.take()) {
            let _ = tx.send(());
        }
    }

    fn on_jwt_bundles_watch_error(&self, _err: crate::workloadapi::Error) {}
}
