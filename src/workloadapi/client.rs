use crate::bundle::jwtbundle;
use crate::bundle::x509bundle;
use crate::spiffeid::{self, ID};
use crate::svid::{jwtsvid, x509svid};
use crate::workloadapi::proto::spiffe_workload_api_client::SpiffeWorkloadApiClient;
use crate::workloadapi::proto::{
    JwtBundlesRequest, JwtBundlesResponse, JwtsvidRequest, JwtsvidResponse, ValidateJwtsvidRequest,
    X509BundlesRequest, X509BundlesResponse, X509svidRequest, X509svidResponse,
};
use crate::workloadapi::{target_from_address, wrap_error, Backoff, Error, Result, SocketEnv};
use crate::workloadapi::{option::ClientConfig, Context};
use tower::service_fn;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::net::UnixStream;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request, Status};

pub struct Client {
    inner: SpiffeWorkloadApiClient<Channel>,
    config: ClientConfig,
}

impl Client {
    pub async fn new<I>(options: I) -> Result<Client>
    where
        I: IntoIterator<Item = Arc<dyn crate::workloadapi::ClientOption>>,
    {
        let mut config = ClientConfig::default();
        for opt in options {
            opt.configure_client(&mut config);
        }

        let address = match config.address.clone() {
            Some(addr) => addr,
            None => crate::workloadapi::get_default_address().ok_or_else(|| {
                wrap_error(format!(
                    "workload endpoint socket address is not configured (missing {})",
                    SocketEnv
                ))
            })?,
        };
        let target = target_from_address(&address)?;
        let channel = connect_channel(&target, &config.dial_options).await?;
        let inner = SpiffeWorkloadApiClient::new(channel);
        Ok(Client { inner, config })
    }

    pub async fn close(&self) -> Result<()> {
        Ok(())
    }

    pub async fn fetch_x509_svid(&self, ctx: &Context) -> Result<x509svid::SVID> {
        let mut client = self.inner.clone();
        let request = with_header(Request::new(X509svidRequest {}));
        let mut stream = cancelable(ctx, client.fetch_x509svid(request)).await?.into_inner();
        let response = cancelable(ctx, stream.message()).await?.ok_or_else(|| wrap_error("stream closed"))?;
        let svids = parse_x509_svids(response, true)?;
        Ok(svids
            .into_iter()
            .next()
            .ok_or_else(|| wrap_error("no SVIDs in response"))?)
    }

    pub async fn fetch_x509_svids(&self, ctx: &Context) -> Result<Vec<x509svid::SVID>> {
        let mut client = self.inner.clone();
        let request = with_header(Request::new(X509svidRequest {}));
        let mut stream = cancelable(ctx, client.fetch_x509svid(request)).await?.into_inner();
        let response = cancelable(ctx, stream.message()).await?.ok_or_else(|| wrap_error("stream closed"))?;
        parse_x509_svids(response, false)
    }

    pub async fn fetch_x509_bundles(&self, ctx: &Context) -> Result<x509bundle::Set> {
        let mut client = self.inner.clone();
        let request = with_header(Request::new(X509BundlesRequest {}));
        let mut stream = cancelable(ctx, client.fetch_x509_bundles(request)).await?.into_inner();
        let resp = cancelable(ctx, stream.message()).await?.ok_or_else(|| wrap_error("stream closed"))?;
        parse_x509_bundles_response(resp)
    }

    pub async fn watch_x509_bundles(&self, ctx: &Context, watcher: Arc<dyn X509BundleWatcher>) -> Result<()> {
        let mut backoff = self.config.backoff_strategy.new_backoff();
        loop {
            if let Err(err) = self.watch_x509_bundles_once(ctx, watcher.clone(), &mut *backoff).await {
                watcher.on_x509_bundles_watch_error(err.clone());
                if let Some(err) = self.handle_watch_error(ctx, err, &mut *backoff).await {
                    return Err(err);
                }
            }
        }
    }

    pub async fn fetch_x509_context(&self, ctx: &Context) -> Result<crate::workloadapi::X509Context> {
        let mut client = self.inner.clone();
        let request = with_header(Request::new(X509svidRequest {}));
        let mut stream = cancelable(ctx, client.fetch_x509svid(request)).await?.into_inner();
        let response = cancelable(ctx, stream.message()).await?.ok_or_else(|| wrap_error("stream closed"))?;
        parse_x509_context(response)
    }

    pub async fn watch_x509_context(
        &self,
        ctx: &Context,
        watcher: Arc<dyn X509ContextWatcher>,
    ) -> Result<()> {
        let mut backoff = self.config.backoff_strategy.new_backoff();
        loop {
            if let Err(err) = self.watch_x509_context_once(ctx, watcher.clone(), &mut *backoff).await {
                watcher.on_x509_context_watch_error(err.clone());
                if let Some(err) = self.handle_watch_error(ctx, err, &mut *backoff).await {
                    return Err(err);
                }
            }
        }
    }

    pub async fn fetch_jwt_svid(&self, ctx: &Context, params: jwtsvid::Params) -> Result<jwtsvid::SVID> {
        let mut client = self.inner.clone();
        let audience = params.audience_list();
        let request = with_header(Request::new(JwtsvidRequest {
            spiffe_id: params.subject.to_string(),
            audience: audience.clone(),
        }));
        let response = cancelable(ctx, client.fetch_jwtsvid(request)).await?;
        let svids = parse_jwt_svids(response.into_inner(), &audience, true)?;
        Ok(svids
            .into_iter()
            .next()
            .ok_or_else(|| wrap_error("there were no SVIDs in the response"))?)
    }

    pub async fn fetch_jwt_svids(&self, ctx: &Context, params: jwtsvid::Params) -> Result<Vec<jwtsvid::SVID>> {
        let mut client = self.inner.clone();
        let audience = params.audience_list();
        let request = with_header(Request::new(JwtsvidRequest {
            spiffe_id: params.subject.to_string(),
            audience: audience.clone(),
        }));
        let response = cancelable(ctx, client.fetch_jwtsvid(request)).await?;
        parse_jwt_svids(response.into_inner(), &audience, false)
    }

    pub async fn fetch_jwt_bundles(&self, ctx: &Context) -> Result<jwtbundle::Set> {
        let mut client = self.inner.clone();
        let request = with_header(Request::new(JwtBundlesRequest {}));
        let mut stream = cancelable(ctx, client.fetch_jwt_bundles(request)).await?.into_inner();
        let resp = cancelable(ctx, stream.message()).await?.ok_or_else(|| wrap_error("stream closed"))?;
        parse_jwt_bundles(resp)
    }

    pub async fn watch_jwt_bundles(&self, ctx: &Context, watcher: Arc<dyn JWTBundleWatcher>) -> Result<()> {
        let mut backoff = self.config.backoff_strategy.new_backoff();
        loop {
            if let Err(err) = self.watch_jwt_bundles_once(ctx, watcher.clone(), &mut *backoff).await {
                watcher.on_jwt_bundles_watch_error(err.clone());
                if let Some(err) = self.handle_watch_error(ctx, err, &mut *backoff).await {
                    return Err(err);
                }
            }
        }
    }

    pub async fn validate_jwt_svid(&self, ctx: &Context, token: &str, audience: &str) -> Result<jwtsvid::SVID> {
        let mut client = self.inner.clone();
        let request = with_header(Request::new(ValidateJwtsvidRequest {
            svid: token.to_string(),
            audience: audience.to_string(),
        }));
        cancelable(ctx, client.validate_jwtsvid(request)).await?;
        jwtsvid::parse_insecure(token, &[audience.to_string()]).map_err(|err| wrap_error(err))
    }

    async fn handle_watch_error(
        &self,
        ctx: &Context,
        err: Error,
        backoff: &mut dyn Backoff,
    ) -> Option<Error> {
        let status = err.status().cloned().unwrap_or_else(|| Status::unknown(err.to_string()));
        match status.code() {
            Code::Cancelled => return Some(err),
            Code::InvalidArgument => {
                self.config
                    .log
                    .errorf(format_args!("Canceling watch: {}", status));
                return Some(err);
            }
            _ => {
                self.config
                    .log
                    .errorf(format_args!("Failed to watch the Workload API: {}", status));
            }
        }

        let retry_after = backoff.next();
        self.config
            .log
            .debugf(format_args!("Retrying watch in {:?}", retry_after));
        tokio::select! {
            _ = tokio::time::sleep(retry_after) => None,
            _ = ctx.cancelled() => Some(wrap_error("context canceled")),
        }
    }

    async fn watch_x509_context_once(
        &self,
        ctx: &Context,
        watcher: Arc<dyn X509ContextWatcher>,
        backoff: &mut dyn Backoff,
    ) -> Result<()> {
        let mut client = self.inner.clone();
        let request = with_header(Request::new(X509svidRequest {}));
        let mut stream = cancelable(ctx, client.fetch_x509svid(request)).await?.into_inner();
        self.config.log.debugf(format_args!("Watching X.509 contexts"));
        loop {
            let resp = cancelable(ctx, stream.message()).await?.ok_or_else(|| wrap_error("stream closed"))?;
            backoff.reset();
            match parse_x509_context(resp) {
                Ok(context) => watcher.on_x509_context_update(context),
                Err(err) => {
                    self.config
                        .log
                        .errorf(format_args!("Failed to parse X509-SVID response: {}", err));
                    watcher.on_x509_context_watch_error(err);
                }
            }
        }
    }

    async fn watch_jwt_bundles_once(
        &self,
        ctx: &Context,
        watcher: Arc<dyn JWTBundleWatcher>,
        backoff: &mut dyn Backoff,
    ) -> Result<()> {
        let mut client = self.inner.clone();
        let request = with_header(Request::new(JwtBundlesRequest {}));
        let mut stream = cancelable(ctx, client.fetch_jwt_bundles(request)).await?.into_inner();
        self.config.log.debugf(format_args!("Watching JWT bundles"));
        loop {
            let resp = cancelable(ctx, stream.message()).await?.ok_or_else(|| wrap_error("stream closed"))?;
            backoff.reset();
            match parse_jwt_bundles(resp) {
                Ok(bundles) => watcher.on_jwt_bundles_update(bundles),
                Err(err) => {
                    self.config
                        .log
                        .errorf(format_args!("Failed to parse JWT bundle response: {}", err));
                    watcher.on_jwt_bundles_watch_error(err);
                }
            }
        }
    }

    async fn watch_x509_bundles_once(
        &self,
        ctx: &Context,
        watcher: Arc<dyn X509BundleWatcher>,
        backoff: &mut dyn Backoff,
    ) -> Result<()> {
        let mut client = self.inner.clone();
        let request = with_header(Request::new(X509BundlesRequest {}));
        let mut stream = cancelable(ctx, client.fetch_x509_bundles(request)).await?.into_inner();
        self.config.log.debugf(format_args!("Watching X.509 bundles"));
        loop {
            let resp = cancelable(ctx, stream.message()).await?.ok_or_else(|| wrap_error("stream closed"))?;
            backoff.reset();
            match parse_x509_bundles_response(resp) {
                Ok(bundles) => watcher.on_x509_bundles_update(bundles),
                Err(err) => {
                    self.config
                        .log
                        .errorf(format_args!("Failed to parse X.509 bundle response: {}", err));
                    watcher.on_x509_bundles_watch_error(err);
                }
            }
        }
    }
}

fn with_header<T>(mut request: Request<T>) -> Request<T> {
    request
        .metadata_mut()
        .insert("workload.spiffe.io", MetadataValue::from_static("true"));
    request
}

async fn connect_channel(target: &str, options: &[Arc<dyn crate::workloadapi::DialOption>]) -> Result<Channel> {
    if target.starts_with("unix://") {
        let url = url::Url::parse(target)
            .map_err(|err| wrap_error(format!("workload endpoint socket is not a valid URI: {}", err)))?;
        let path = url
            .to_file_path()
            .map_err(|_| wrap_error("workload endpoint unix socket URI must include a path"))?;
        let mut endpoint = Endpoint::try_from("http://[::]:0")
            .map_err(|err| wrap_error(format!("invalid endpoint: {}", err)))?;
        for opt in options {
            endpoint = opt.apply(endpoint);
        }
        let connector = service_fn(move |_uri| UnixStream::connect(path.clone()));
        let channel = endpoint
            .connect_with_connector(connector)
            .await
            .map_err(|err| wrap_error(format!("unable to connect: {}", err)))?;
        return Ok(channel);
    }

    let mut endpoint = Endpoint::from_shared(format!("http://{}", target))
        .map_err(|err| wrap_error(format!("invalid endpoint: {}", err)))?;
    for opt in options {
        endpoint = opt.apply(endpoint);
    }
    endpoint
        .connect()
        .await
        .map_err(|err| wrap_error(format!("unable to connect: {}", err)))
}

async fn cancelable<T, F>(ctx: &Context, fut: F) -> Result<T>
where
    F: std::future::Future<Output = std::result::Result<T, Status>>,
{
    tokio::select! {
        result = fut => result.map_err(Error::from),
        _ = ctx.cancelled() => Err(wrap_error("context canceled")),
    }
}

fn parse_x509_context(resp: X509svidResponse) -> Result<crate::workloadapi::X509Context> {
    let svids = parse_x509_svids(resp.clone(), false)?;
    let bundles = parse_x509_bundles(resp)?;
    Ok(crate::workloadapi::X509Context { svids, bundles })
}

fn parse_x509_svids(resp: X509svidResponse, first_only: bool) -> Result<Vec<x509svid::SVID>> {
    let mut svids = resp.svids;
    if svids.is_empty() {
        return Err(wrap_error("no SVIDs in response"));
    }
    if first_only {
        svids.truncate(1);
    }

    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for svid in svids {
        if !svid.hint.is_empty() && !seen.insert(svid.hint.clone()) {
            continue;
        }
        let mut parsed = x509svid::SVID::parse_raw(&svid.x509_svid, &svid.x509_svid_key)
            .map_err(|err| wrap_error(err))?;
        parsed.hint = svid.hint;
        out.push(parsed);
    }
    Ok(out)
}

fn parse_x509_bundles(resp: X509svidResponse) -> Result<x509bundle::Set> {
    let mut bundles = Vec::new();
    for svid in resp.svids {
        let td = ID::from_string(&svid.spiffe_id)
            .map_err(|err| wrap_error(err))?
            .trust_domain();
        bundles.push(x509bundle::Bundle::parse_raw(td, &svid.bundle).map_err(|err| wrap_error(err))?);
    }
    for (td_id, bundle) in resp.federated_bundles {
        let td = spiffeid::trust_domain_from_string(&td_id).map_err(|err| wrap_error(err))?;
        bundles.push(x509bundle::Bundle::parse_raw(td, &bundle).map_err(|err| wrap_error(err))?);
    }
    Ok(x509bundle::Set::new(&bundles))
}

fn parse_x509_bundles_response(resp: X509BundlesResponse) -> Result<x509bundle::Set> {
    let mut bundles = Vec::new();
    for (td_id, bundle) in resp.bundles {
        let td = spiffeid::trust_domain_from_string(&td_id).map_err(|err| wrap_error(err))?;
        bundles.push(x509bundle::Bundle::parse_raw(td, &bundle).map_err(|err| wrap_error(err))?);
    }
    Ok(x509bundle::Set::new(&bundles))
}

fn parse_jwt_svids(resp: JwtsvidResponse, audience: &[String], first_only: bool) -> Result<Vec<jwtsvid::SVID>> {
    let mut svids = resp.svids;
    if svids.is_empty() {
        return Err(wrap_error("there were no SVIDs in the response"));
    }
    if first_only {
        svids.truncate(1);
    }

    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for svid in svids {
        if !svid.hint.is_empty() && !seen.insert(svid.hint.clone()) {
            continue;
        }
        let mut parsed = jwtsvid::parse_insecure(&svid.svid, audience).map_err(|err| wrap_error(err))?;
        parsed.hint = svid.hint;
        out.push(parsed);
    }
    Ok(out)
}

fn parse_jwt_bundles(resp: JwtBundlesResponse) -> Result<jwtbundle::Set> {
    let mut bundles = Vec::new();
    for (td_id, bundle) in resp.bundles {
        let td = spiffeid::trust_domain_from_string(&td_id).map_err(|err| wrap_error(err))?;
        bundles.push(jwtbundle::Bundle::parse(td, &bundle).map_err(|err| wrap_error(err))?);
    }
    Ok(jwtbundle::Set::new(&bundles))
}

pub trait X509ContextWatcher: Send + Sync {
    fn on_x509_context_update(&self, context: crate::workloadapi::X509Context);
    fn on_x509_context_watch_error(&self, err: Error);
}

pub trait JWTBundleWatcher: Send + Sync {
    fn on_jwt_bundles_update(&self, bundles: jwtbundle::Set);
    fn on_jwt_bundles_watch_error(&self, err: Error);
}

pub trait X509BundleWatcher: Send + Sync {
    fn on_x509_bundles_update(&self, bundles: x509bundle::Set);
    fn on_x509_bundles_watch_error(&self, err: Error);
}
