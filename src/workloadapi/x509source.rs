use crate::bundle::x509bundle;
use crate::svid::x509svid;
use crate::workloadapi::option::{X509SourceConfig, X509SourceOption};
use crate::workloadapi::{wrap_error, Context, Result, Watcher, X509Context};
use std::sync::{Arc, RwLock};

pub struct X509Source {
    watcher: Watcher,
    svid: Arc<RwLock<Option<x509svid::SVID>>>,
    bundles: Arc<RwLock<Option<x509bundle::Set>>>,
    closed: std::sync::atomic::AtomicBool,
}

impl X509Source {
    pub async fn new<I>(ctx: &Context, options: I) -> Result<X509Source>
    where
        I: IntoIterator<Item = Arc<dyn X509SourceOption>>,
    {
        let mut config = X509SourceConfig::default();
        for opt in options {
            opt.configure_x509_source(&mut config);
        }

        let picker = config.picker.clone();
        let svid_slot = Arc::new(RwLock::new(None));
        let bundles_slot = Arc::new(RwLock::new(None));
        let svid_slot_clone = svid_slot.clone();
        let bundles_slot_clone = bundles_slot.clone();
        let handler = Arc::new(move |context: X509Context| {
            let svid = match &picker {
                Some(picker) => picker(&context.svids),
                None => match context.svids.first() {
                    Some(svid) => svid.clone(),
                    None => return,
                },
            };
            if let Ok(mut guard) = svid_slot_clone.write() {
                *guard = Some(svid);
            }
            if let Ok(mut guard) = bundles_slot_clone.write() {
                *guard = Some(context.bundles);
            }
        });

        let watcher = Watcher::new(ctx, config.watcher, Some(handler), None).await?;
        Ok(X509Source {
            watcher,
            svid: svid_slot,
            bundles: bundles_slot,
            closed: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub async fn close(&self) -> Result<()> {
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        self.watcher.close().await
    }

    pub fn get_x509_svid(&self) -> Result<x509svid::SVID> {
        self.check_closed()?;
        self.svid
            .read()
            .ok()
            .and_then(|guard| guard.clone())
            .ok_or_else(|| wrap_error("missing X509-SVID"))
    }

    pub fn get_x509_bundle_for_trust_domain(
        &self,
        trust_domain: crate::spiffeid::TrustDomain,
    ) -> Result<x509bundle::Bundle> {
        self.check_closed()?;
        self.bundles
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().and_then(|b| b.get_x509_bundle_for_trust_domain(trust_domain).ok()))
            .ok_or_else(|| wrap_error("no X.509 bundle found"))
    }

    pub async fn wait_until_updated(&self, ctx: &Context) -> Result<()> {
        self.watcher.wait_until_updated(ctx).await
    }

    pub fn updated(&self) -> tokio::sync::watch::Receiver<u64> {
        self.watcher.updated()
    }

    fn check_closed(&self) -> Result<()> {
        if self.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(wrap_error("source is closed"));
        }
        Ok(())
    }
}

impl x509svid::Source for X509Source {
    fn get_x509_svid(&self) -> x509svid::Result<x509svid::SVID> {
        self.get_x509_svid()
            .map_err(|err| x509svid::Error::new(err.to_string()))
    }
}

impl x509bundle::Source for X509Source {
    fn get_x509_bundle_for_trust_domain(
        &self,
        trust_domain: crate::spiffeid::TrustDomain,
    ) -> x509bundle::Result<x509bundle::Bundle> {
        self.get_x509_bundle_for_trust_domain(trust_domain)
            .map_err(|err| x509bundle::Error::new(err.to_string()))
    }
}
