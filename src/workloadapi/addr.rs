use crate::workloadapi::{wrap_error, Result};
use std::net::IpAddr;
use std::env;
use url::Url;

#[allow(non_upper_case_globals)]
pub const SocketEnv: &str = "SPIFFE_ENDPOINT_SOCKET";

pub fn get_default_address() -> Option<String> {
    env::var(SocketEnv).ok()
}

pub fn validate_address(addr: &str) -> Result<()> {
    target_from_address(addr).map(|_| ())
}

pub fn target_from_address(addr: &str) -> Result<String> {
    let url = Url::parse(addr)
        .map_err(|err| wrap_error(format!("workload endpoint socket is not a valid URI: {}", err)))?;
    parse_target_from_url(&url)
}

fn parse_target_from_url(url: &Url) -> Result<String> {
    if url.scheme() == "tcp" {
        if url.cannot_be_a_base() {
            return Err(wrap_error(
                "workload endpoint tcp socket URI must not be opaque",
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(wrap_error(
                "workload endpoint tcp socket URI must not include user info",
            ));
        }
        if url.host_str().is_none() {
            return Err(wrap_error(
                "workload endpoint tcp socket URI must include a host",
            ));
        }
        if !url.path().is_empty() && url.path() != "/" {
            return Err(wrap_error(
                "workload endpoint tcp socket URI must not include a path",
            ));
        }
        if url.query().is_some() {
            return Err(wrap_error(
                "workload endpoint tcp socket URI must not include query values",
            ));
        }
        if url.fragment().is_some() {
            return Err(wrap_error(
                "workload endpoint tcp socket URI must not include a fragment",
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| wrap_error("workload endpoint tcp socket URI must include a host"))?;
        let ip: IpAddr = host
            .parse()
            .map_err(|_| wrap_error("workload endpoint tcp socket URI host component must be an IP:port"))?;
        let port = url
            .port()
            .ok_or_else(|| wrap_error("workload endpoint tcp socket URI host component must include a port"))?;
        return Ok(format!("{}:{}", ip, port));
    }

    parse_target_from_url_os(url)
}

fn parse_target_from_url_os(url: &Url) -> Result<String> {
    match url.scheme() {
        "unix" => {
            if url.cannot_be_a_base() {
                return Err(wrap_error(
                    "workload endpoint unix socket URI must not be opaque",
                ));
            }
            if !url.username().is_empty() || url.password().is_some() {
                return Err(wrap_error(
                    "workload endpoint unix socket URI must not include user info",
                ));
            }
            if url.host_str().unwrap_or("").is_empty() && url.path().is_empty() {
                return Err(wrap_error(
                    "workload endpoint unix socket URI must include a path",
                ));
            }
            if url.query().is_some() {
                return Err(wrap_error(
                    "workload endpoint unix socket URI must not include query values",
                ));
            }
            if url.fragment().is_some() {
                return Err(wrap_error(
                    "workload endpoint unix socket URI must not include a fragment",
                ));
            }
            Ok(url.to_string())
        }
        _ => Err(wrap_error(
            "workload endpoint socket URI must have a \"tcp\" or \"unix\" scheme",
        )),
    }
}
