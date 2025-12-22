use crate::bundle::jwtbundle;
use crate::svid::jwtsvid;
use crate::workloadapi::option::{JWTSourceConfig, JWTSourceOption};
use crate::workloadapi::{Context, Result, Watcher};
use std::sync::{Arc, RwLock};

/// A source of JWT SVIDs and bundles that is kept up-to-date by watching the
/// Workload API.
pub struct JWTSource {
    watcher: Watcher,
    picker: Option<Arc<dyn Fn(&[jwtsvid::SVID]) -> jwtsvid::SVID + Send + Sync>>,
    bundles: Arc<RwLock<Option<jwtbundle::Set>>>,
    closed: std::sync::atomic::AtomicBool,
}

impl JWTSource {
    /// Creates a new `JWTSource` with the given options.
    ///
    /// It starts watching the Workload API for updates.
    pub async fn new<I>(ctx: &Context, options: I) -> Result<JWTSource>
    where
        I: IntoIterator<Item = Arc<dyn JWTSourceOption>>,
    {
        let mut config = JWTSourceConfig::default();
        for opt in options {
            opt.configure_jwt_source(&mut config);
        }

        let bundles_slot = Arc::new(RwLock::new(None));
        let bundles_slot_clone = bundles_slot.clone();
        let handler = Arc::new(move |bundles: jwtbundle::Set| {
            if let Ok(mut guard) = bundles_slot_clone.write() {
                *guard = Some(bundles);
            }
        });

        let watcher = Watcher::new(ctx, config.watcher, None, Some(handler)).await?;
        Ok(JWTSource {
            watcher,
            picker: config.picker.clone(),
            bundles: bundles_slot,
            closed: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Closes the source.
    pub async fn close(&self) -> Result<()> {
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        self.watcher.close().await
    }

    /// Fetches a JWT SVID with the given parameters.
    pub async fn fetch_jwt_svid(
        &self,
        ctx: &Context,
        params: jwtsvid::Params,
    ) -> Result<jwtsvid::SVID> {
        self.check_closed()?;
        if let Some(picker) = &self.picker {
            let svids = self.watcher.client.fetch_jwt_svids(ctx, params).await?;
            return Ok(picker(&svids));
        }
        self.watcher.client.fetch_jwt_svid(ctx, params).await
    }

    /// Fetches multiple JWT SVIDs with the given parameters.
    pub async fn fetch_jwt_svids(
        &self,
        ctx: &Context,
        params: jwtsvid::Params,
    ) -> Result<Vec<jwtsvid::SVID>> {
        self.check_closed()?;
        self.watcher.client.fetch_jwt_svids(ctx, params).await
    }

    /// Returns the JWT bundle for the given trust domain.
    pub fn get_jwt_bundle_for_trust_domain(
        &self,
        trust_domain: crate::spiffeid::TrustDomain,
    ) -> Result<jwtbundle::Bundle> {
        self.check_closed()?;
        self.bundles
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().and_then(|b| b.get_jwt_bundle_for_trust_domain(trust_domain).ok()))
            .ok_or_else(|| crate::workloadapi::Error::new("jwtsource: no JWT bundle found"))
    }

    /// Waits until the source has been updated for the first time.
    pub async fn wait_until_updated(&self, ctx: &Context) -> Result<()> {
        self.watcher.wait_until_updated(ctx).await
    }

    /// Returns a receiver that can be used to watch for updates to the source.
    pub fn updated(&self) -> tokio::sync::watch::Receiver<u64> {
        self.watcher.updated()
    }

    fn check_closed(&self) -> Result<()> {
        if self.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(crate::workloadapi::Error::new("jwtsource: source is closed"));
        }
        Ok(())
    }
}

impl jwtbundle::Source for JWTSource {
    fn get_jwt_bundle_for_trust_domain(
        &self,
        trust_domain: crate::spiffeid::TrustDomain,
    ) -> jwtbundle::Result<jwtbundle::Bundle> {
        self.get_jwt_bundle_for_trust_domain(trust_domain)
            .map_err(|err| jwtbundle::Error::new(err.to_string()))
    }
}
