# HTTP over TLS with JWT

This example shows how two services using HTTP can communicate using TLS with the server presenting an X.509 SVID and the client authenticating with a JWT-SVID. The SVIDs are retrieved via the SPIFFE Workload API.

The server uses `spiffetls::tlsconfig::tls_server_config` to present its X.509 SVID and validates incoming JWT-SVIDs using `jwtsvid::parse_and_validate` with bundles from `JWTSource`.

The client uses `tls_client_config` to verify the server's SPIFFE ID, fetches a JWT-SVID, and sends it as a bearer token.

## Building
Build the client workload:

```bash
cargo build --example spiffe-jwt-client
```

Build the server workload:

```bash
cargo build --example spiffe-jwt-server
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
sudo -u server-workload SPIFFE_ENDPOINT_SOCKET=unix:///tmp/agent.sock cargo run --example spiffe-jwt-server
```

### 3. Run the client
```bash
sudo -u client-workload SPIFFE_ENDPOINT_SOCKET=unix:///tmp/agent.sock cargo run --example spiffe-jwt-client
```

To demonstrate a failure, pass an alternate audience value:

```bash
sudo -u client-workload SPIFFE_ENDPOINT_SOCKET=unix:///tmp/agent.sock cargo run --example spiffe-jwt-client spiffe://example.org/some-other-server
```
