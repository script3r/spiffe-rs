# Mutually Authenticated TLS (mTLS)

This example shows how to establish an mTLS connection between two workloads using X.509 SVIDs obtained from the SPIFFE Workload API.

One workload acts as a client and the other as the server.

## Listening
The server uses `spiffetls::listen` and authorizes the client SPIFFE ID:

```rust
let client_id = spiffeid::require_from_string("spiffe://example.org/client");
let authorizer = spiffetls::tlsconfig::authorize_id(client_id);
let listener = spiffetls::listen(&ctx, "127.0.0.1:55555", authorizer, Vec::new()).await?;
```

`spiffetls::listen` blocks until the first Workload API response is received. The Workload API socket is taken from `SPIFFE_ENDPOINT_SOCKET` (default example uses `unix:///tmp/agent.sock`).

## Dialing
The client uses `spiffetls::dial` and authorizes the server SPIFFE ID:

```rust
let server_id = spiffeid::require_from_string("spiffe://example.org/server");
let authorizer = spiffetls::tlsconfig::authorize_id(server_id);
let server_name = rustls::ServerName::try_from("example.org")?;
let mut stream = spiffetls::dial(&ctx, "127.0.0.1:55555", server_name, authorizer, Vec::new()).await?;
```

## Building
Build the client workload:

```bash
cargo build --example spiffe-tls-client
```

Build the server workload:

```bash
cargo build --example spiffe-tls-server
```

## Running
This example assumes:
- SPIRE server and agent are running.
- A Unix workload attestor is configured.
- The trust domain is `example.org`.
- The agent SPIFFE ID is `spiffe://example.org/host`.
- `server-workload` and `client-workload` users exist.

### 1. Create registration entries
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
sudo -u server-workload SPIFFE_ENDPOINT_SOCKET=unix:///tmp/agent.sock cargo run --example spiffe-tls-server
```

### 3. Run the client
```bash
sudo -u client-workload SPIFFE_ENDPOINT_SOCKET=unix:///tmp/agent.sock cargo run --example spiffe-tls-client
```

The server should receive a "Hello server" message and respond with "Hello client".
