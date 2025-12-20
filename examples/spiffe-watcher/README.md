# X.509 SVID Watcher example

This example shows how a service can obtain automatically rotated X.509 SVIDs and JWT Bundles from the SPIFFE Workload API.

The first step is to create a Workload API client:

```rust
let client = workloadapi::Client::new(client_options()).await?;
```

If `SPIFFE_ENDPOINT_SOCKET` is not set, the example defaults to `unix:///tmp/agent.sock`.

The library uses watcher interfaces to receive updates:

```rust
client.watch_x509_context(&ctx, x509_watcher).await?;
client.watch_jwt_bundles(&ctx, jwt_watcher).await?;
```

## Building
Build the example:

```bash
cargo build --example spiffe-watcher
```

## Running
This example assumes:
- SPIRE server and agent are running.
- A Unix workload attestor is configured.
- The trust domain is `example.org`.
- The agent SPIFFE ID is `spiffe://example.org/host`.
- A `spiffe-watcher` user exists.

### 1. Create the registration entry
```bash
./spire-server entry create -spiffeID spiffe://example.org/spiffe-watcher \
                            -parentID spiffe://example.org/host \
                            -selector unix:user:spiffe-watcher
```

### 2. Start the workload
```bash
sudo -u spiffe-watcher SPIFFE_ENDPOINT_SOCKET=unix:///tmp/agent.sock cargo run --example spiffe-watcher
```

The watcher prints the SVID SPIFFE ID every time an SVID is updated and prints JWT bundle updates as they arrive.
