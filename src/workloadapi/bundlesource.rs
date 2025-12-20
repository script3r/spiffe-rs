use crate::bundle::{jwtbundle, spiffebundle, x509bundle};
use crate::spiffeid::TrustDomain;
use crate::workloadapi::option::{BundleSourceConfig, BundleSourceOption};
use crate::workloadapi::{wrap_error, Context, Result, Watcher, X509Context};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub struct BundleSource {
    watcher: Watcher,
    x509_authorities: Arc<RwLock<HashMap<TrustDomain, Vec<Vec<u8>>>>>,
    jwt_authorities: Arc<RwLock<HashMap<TrustDomain, HashMap<String, jwtbundle::JwtKey>>>>,
    closed: std::sync::atomic::AtomicBool,
}

impl BundleSource {
    pub async fn new<I>(ctx: &Context, options: I) -> Result<BundleSource>
    where
        I: IntoIterator<Item = Arc<dyn BundleSourceOption>>,
    {
        let mut config = BundleSourceConfig::default();
        for opt in options {
            opt.configure_bundle_source(&mut config);
        }

        let x509_authorities = Arc::new(RwLock::new(HashMap::new()));
        let jwt_authorities = Arc::new(RwLock::new(HashMap::new()));

        let x509_authorities_clone = x509_authorities.clone();
        let jwt_authorities_clone = jwt_authorities.clone();
        let x509_handler = Arc::new(move |context: X509Context| {
            let mut new_auth = HashMap::new();
            for bundle in context.bundles.bundles() {
                new_auth.insert(bundle.trust_domain(), bundle.x509_authorities());
            }
            if let Ok(mut guard) = x509_authorities_clone.write() {
                *guard = new_auth;
            }
        });

        let jwt_handler = Arc::new(move |bundles: jwtbundle::Set| {
            let mut new_auth = HashMap::new();
            for bundle in bundles.bundles() {
                new_auth.insert(bundle.trust_domain(), bundle.jwt_authorities());
            }
            if let Ok(mut guard) = jwt_authorities_clone.write() {
                *guard = new_auth;
            }
        });

        let watcher = Watcher::new(ctx, config.watcher, Some(x509_handler), Some(jwt_handler)).await?;
        Ok(BundleSource {
            watcher,
            x509_authorities,
            jwt_authorities,
            closed: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub async fn close(&self) -> Result<()> {
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        self.watcher.close().await
    }

    pub fn get_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> Result<spiffebundle::Bundle> {
        self.check_closed()?;
        let x509 = self
            .x509_authorities
            .read()
            .ok()
            .and_then(|guard| guard.get(&trust_domain).cloned());
        let jwt = self
            .jwt_authorities
            .read()
            .ok()
            .and_then(|guard| guard.get(&trust_domain).cloned());

        if x509.is_none() && jwt.is_none() {
            return Err(wrap_error(format!(
                "no SPIFFE bundle for trust domain {:?}",
                trust_domain
            )));
        }
        let bundle = spiffebundle::Bundle::new(trust_domain.clone());
        if let Some(x509) = x509 {
            bundle.set_x509_authorities(&x509);
        }
        if let Some(jwt) = jwt {
            bundle.set_jwt_authorities(&jwt);
        }
        Ok(bundle)
    }

    pub fn get_x509_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> Result<x509bundle::Bundle> {
        self.check_closed()?;
        let x509 = self
            .x509_authorities
            .read()
            .ok()
            .and_then(|guard| guard.get(&trust_domain).cloned())
            .ok_or_else(|| wrap_error(format!("no X.509 bundle for trust domain {:?}", trust_domain)))?;
        Ok(x509bundle::Bundle::from_x509_authorities(trust_domain, &x509))
    }

    pub fn get_jwt_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> Result<jwtbundle::Bundle> {
        self.check_closed()?;
        let jwt = self
            .jwt_authorities
            .read()
            .ok()
            .and_then(|guard| guard.get(&trust_domain).cloned())
            .ok_or_else(|| wrap_error(format!("no JWT bundle for trust domain {:?}", trust_domain)))?;
        Ok(jwtbundle::Bundle::from_jwt_authorities(trust_domain, &jwt))
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

impl spiffebundle::Source for BundleSource {
    fn get_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> spiffebundle::Result<spiffebundle::Bundle> {
        self.get_bundle_for_trust_domain(trust_domain)
            .map_err(|err| spiffebundle::Error::new(err.to_string()))
    }
}

impl x509bundle::Source for BundleSource {
    fn get_x509_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> x509bundle::Result<x509bundle::Bundle> {
        self.get_x509_bundle_for_trust_domain(trust_domain)
            .map_err(|err| x509bundle::Error::new(err.to_string()))
    }
}

impl jwtbundle::Source for BundleSource {
    fn get_jwt_bundle_for_trust_domain(&self, trust_domain: TrustDomain) -> jwtbundle::Result<jwtbundle::Bundle> {
        self.get_jwt_bundle_for_trust_domain(trust_domain)
            .map_err(|err| jwtbundle::Error::new(err.to_string()))
    }
}
