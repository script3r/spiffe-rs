# Authenticating Workloads over TLS-encrypted HTTP Connections Using JWT-SVIDs

This example shows how to authenticate client workloads using JWT-SVIDs when mTLS is not possible (for example, when a proxy terminates TLS). It uses a server, a proxy, and a client.

Scenario:
1. The server presents an X.509 SVID over TLS and validates JWT-SVIDs from clients.
2. The proxy terminates TLS for the client and forwards HTTP requests to the server over TLS.
3. The client fetches a JWT-SVID and sends it in the `Authorization` header.

## Building
Build the client workload:

```bash
cargo build --example spiffe-jwt-using-proxy-client
```

Build the proxy workload:

```bash
cargo build --example spiffe-jwt-using-proxy-proxy
```

Build the server workload:

```bash
cargo build --example spiffe-jwt-using-proxy-server
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

The proxy runs as the server workload so it presents the server SPIFFE ID.

### 2. Start the server
```bash
sudo -u server-workload SPIFFE_ENDPOINT_SOCKET=unix:///tmp/agent.sock cargo run --example spiffe-jwt-using-proxy-server
```

### 3. Start the proxy
```bash
sudo -u server-workload SPIFFE_ENDPOINT_SOCKET=unix:///tmp/agent.sock cargo run --example spiffe-jwt-using-proxy-proxy
```

### 4. Run the client
```bash
sudo -u client-workload SPIFFE_ENDPOINT_SOCKET=unix:///tmp/agent.sock cargo run --example spiffe-jwt-using-proxy-client
```

For each component, the logs should show:
- Proxy: `GET /`
- Server: `Request received`
- Client: `Success!!!`

To demonstrate a failure, pass a wrong audience value:

```bash
sudo -u client-workload SPIFFE_ENDPOINT_SOCKET=unix:///tmp/agent.sock cargo run --example spiffe-jwt-using-proxy-client spiffe://example.org/some-other-server
```
