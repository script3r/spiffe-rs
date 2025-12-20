use crate::bundle::{jwtbundle, x509bundle};
use crate::svid::{jwtsvid, x509svid};
use crate::workloadapi::{
    Client, ClientOption, Context, JWTBundleWatcher, Result, X509BundleWatcher, X509Context,
    X509ContextWatcher,
};
use std::sync::Arc;

pub async fn fetch_x509_svid<I>(ctx: &Context, options: I) -> Result<x509svid::SVID>
where
    I: IntoIterator<Item = Arc<dyn ClientOption>>,
{
    let client = Client::new(options).await?;
    let result = client.fetch_x509_svid(ctx).await;
    client.close().await?;
    result
}

pub async fn fetch_x509_svids<I>(ctx: &Context, options: I) -> Result<Vec<x509svid::SVID>>
where
    I: IntoIterator<Item = Arc<dyn ClientOption>>,
{
    let client = Client::new(options).await?;
    let result = client.fetch_x509_svids(ctx).await;
    client.close().await?;
    result
}

pub async fn fetch_x509_bundles<I>(ctx: &Context, options: I) -> Result<x509bundle::Set>
where
    I: IntoIterator<Item = Arc<dyn ClientOption>>,
{
    let client = Client::new(options).await?;
    let result = client.fetch_x509_bundles(ctx).await;
    client.close().await?;
    result
}

pub async fn fetch_x509_context<I>(ctx: &Context, options: I) -> Result<X509Context>
where
    I: IntoIterator<Item = Arc<dyn ClientOption>>,
{
    let client = Client::new(options).await?;
    let result = client.fetch_x509_context(ctx).await;
    client.close().await?;
    result
}

pub async fn watch_x509_context<I>(
    ctx: &Context,
    watcher: Arc<dyn X509ContextWatcher>,
    options: I,
) -> Result<()>
where
    I: IntoIterator<Item = Arc<dyn ClientOption>>,
{
    let client = Client::new(options).await?;
    let result = client.watch_x509_context(ctx, watcher).await;
    client.close().await?;
    result
}

pub async fn fetch_jwt_svid<I>(ctx: &Context, params: jwtsvid::Params, options: I) -> Result<jwtsvid::SVID>
where
    I: IntoIterator<Item = Arc<dyn ClientOption>>,
{
    let client = Client::new(options).await?;
    let result = client.fetch_jwt_svid(ctx, params).await;
    client.close().await?;
    result
}

pub async fn fetch_jwt_svids<I>(ctx: &Context, params: jwtsvid::Params, options: I) -> Result<Vec<jwtsvid::SVID>>
where
    I: IntoIterator<Item = Arc<dyn ClientOption>>,
{
    let client = Client::new(options).await?;
    let result = client.fetch_jwt_svids(ctx, params).await;
    client.close().await?;
    result
}

pub async fn fetch_jwt_bundles<I>(ctx: &Context, options: I) -> Result<jwtbundle::Set>
where
    I: IntoIterator<Item = Arc<dyn ClientOption>>,
{
    let client = Client::new(options).await?;
    let result = client.fetch_jwt_bundles(ctx).await;
    client.close().await?;
    result
}

pub async fn watch_jwt_bundles<I>(
    ctx: &Context,
    watcher: Arc<dyn JWTBundleWatcher>,
    options: I,
) -> Result<()>
where
    I: IntoIterator<Item = Arc<dyn ClientOption>>,
{
    let client = Client::new(options).await?;
    let result = client.watch_jwt_bundles(ctx, watcher).await;
    client.close().await?;
    result
}

pub async fn watch_x509_bundles<I>(
    ctx: &Context,
    watcher: Arc<dyn X509BundleWatcher>,
    options: I,
) -> Result<()>
where
    I: IntoIterator<Item = Arc<dyn ClientOption>>,
{
    let client = Client::new(options).await?;
    let result = client.watch_x509_bundles(ctx, watcher).await;
    client.close().await?;
    result
}

pub async fn validate_jwt_svid<I>(ctx: &Context, token: &str, audience: &str, options: I) -> Result<jwtsvid::SVID>
where
    I: IntoIterator<Item = Arc<dyn ClientOption>>,
{
    let client = Client::new(options).await?;
    let result = client.validate_jwt_svid(ctx, token, audience).await;
    client.close().await?;
    result
}
