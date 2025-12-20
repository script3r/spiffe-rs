# gRPC over mTLS example

This example shows how two services using gRPC can communicate using mTLS with X.509 SVIDs obtained from the SPIFFE Workload API.

The gRPC server uses a rustls `ServerConfig` built from `spiffetls::tlsconfig::mtls_server_config`, and the client uses `mtls_client_config` with SPIFFE ID authorization.

## Building
Build the client workload:

```bash
cargo build --example spiffe-grpc-client
```

Build the server workload:

```bash
cargo build --example spiffe-grpc-server
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
sudo -u server-workload SPIFFE_ENDPOINT_SOCKET=unix:///tmp/agent.sock cargo run --example spiffe-grpc-server
```

### 3. Run the client
```bash
sudo -u client-workload SPIFFE_ENDPOINT_SOCKET=unix:///tmp/agent.sock cargo run --example spiffe-grpc-client
```

The client should receive a "Hello world" response.
