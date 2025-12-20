use spiffe_rs::workloadapi::{get_default_address, validate_address, SocketEnv};
use std::env;

struct ValidateAddressCase {
    addr: &'static str,
    err: &'static str,
}

#[test]
fn get_default_address_env() {
    let original = env::var(SocketEnv).ok();
    env::remove_var(SocketEnv);
    assert!(get_default_address().is_none());

    env::set_var(SocketEnv, "ADDRESS");
    assert_eq!(get_default_address().as_deref(), Some("ADDRESS"));

    match original {
        Some(value) => env::set_var(SocketEnv, value),
        None => env::remove_var(SocketEnv),
    }
}

#[test]
fn validate_address_cases() {
    let mut cases = vec![
        ValidateAddressCase {
            addr: "\t",
            err: "valid URI",
        },
        ValidateAddressCase {
            addr: "foo://bar",
            err: "workload endpoint socket URI must have a \"tcp\" or \"unix\" scheme",
        },
        ValidateAddressCase {
            addr: "tcp:opaque",
            err: "workload endpoint tcp socket URI must not be opaque",
        },
        ValidateAddressCase {
            addr: "tcp://",
            err: "workload endpoint tcp socket URI must include a host",
        },
        ValidateAddressCase {
            addr: "tcp://1.2.3.4:5?whatever",
            err: "workload endpoint tcp socket URI must not include query values",
        },
        ValidateAddressCase {
            addr: "tcp://1.2.3.4:5#whatever",
            err: "workload endpoint tcp socket URI must not include a fragment",
        },
        ValidateAddressCase {
            addr: "tcp://john:doe@1.2.3.4:5/path",
            err: "workload endpoint tcp socket URI must not include user info",
        },
        ValidateAddressCase {
            addr: "tcp://1.2.3.4:5/path",
            err: "workload endpoint tcp socket URI must not include a path",
        },
        ValidateAddressCase {
            addr: "tcp://foo",
            err: "workload endpoint tcp socket URI host component must be an IP:port",
        },
        ValidateAddressCase {
            addr: "tcp://1.2.3.4",
            err: "workload endpoint tcp socket URI host component must include a port",
        },
        ValidateAddressCase {
            addr: "tcp://1.2.3.4:5",
            err: "",
        },
        ValidateAddressCase {
            addr: "unix:opaque",
            err: "workload endpoint unix socket URI must not be opaque",
        },
        ValidateAddressCase {
            addr: "unix://",
            err: "workload endpoint unix socket URI must include a path",
        },
        ValidateAddressCase {
            addr: "unix://foo?whatever",
            err: "workload endpoint unix socket URI must not include query values",
        },
        ValidateAddressCase {
            addr: "unix://foo#whatever",
            err: "workload endpoint unix socket URI must not include a fragment",
        },
        ValidateAddressCase {
            addr: "unix://john:doe@foo/path",
            err: "workload endpoint unix socket URI must not include user info",
        },
        ValidateAddressCase {
            addr: "unix://foo",
            err: "",
        },
    ];

    for case in cases.drain(..) {
        let result = validate_address(case.addr);
        if case.err.is_empty() {
            assert!(result.is_ok(), "expected ok for {}", case.addr);
        } else {
            let err = result.expect_err("expected error");
            assert!(
                err.to_string().contains(case.err),
                "error mismatch for {}: {}",
                case.addr,
                err
            );
        }
    }
}
