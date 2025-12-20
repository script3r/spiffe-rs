# HTTP over mTLS

This example shows how two services using HTTP can communicate using mTLS with X.509 SVIDs obtained from the SPIFFE Workload API.

The HTTP server uses a rustls `ServerConfig` built by `spiffetls::tlsconfig::mtls_server_config` and a Hyper server over a TLS stream. The client uses `mtls_client_config` with SPIFFE ID authorization.

## Building
Build the client workload:

```bash
cargo build --example spiffe-http-client
```

Build the server workload:

```bash
cargo build --example spiffe-http-server
```

## Running
This example assumes:
- SPIRE server and agent are running.
- A Unix workload attestor is configured.
- The trust domain is `example.org`.
- The agent SPIFFE ID is `spiffe://example.org/host`.
- `server-workload` and `client-workload` users exist.

### 1. Create the registration entries
Server:
```bash
./spire-server entry create -spiffeID spiffe://example.org/server \
                            -parentID spiffe://example.org/host \
                            -selector unix:user:server-workload
```

Client:
```bash
./spire-server entry create -spiffeID spiffe://example.org/client \
                            -parentID spiffe://example.org/host \
                            -selector unix:user:client-workload
```

### 2. Start the server
```bash
sudo -u server-workload SPIFFE_ENDPOINT_SOCKET=unix:///tmp/agent.sock cargo run --example spiffe-http-server
```

### 3. Run the client
```bash
sudo -u client-workload SPIFFE_ENDPOINT_SOCKET=unix:///tmp/agent.sock cargo run --example spiffe-http-client
```

The server should log `Request received` and the client should print `Success!!!`.
