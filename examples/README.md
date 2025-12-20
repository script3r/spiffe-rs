# spiffe-rs Examples

This section contains standalone examples that demonstrate different use cases for the spiffe-rs library.

## Use cases

- [Mutually Authenticated TLS (mTLS)](spiffe-tls/README.md): Establish mTLS connections between workloads using automatically rotated X.509 SVIDs obtained from the SPIFFE Workload API.
- [SVIDs stream](spiffe-watcher/README.md): Get automatically rotated X.509 SVIDs and JWT Bundles for your workload.
- [gRPC over mTLS](spiffe-grpc/README.md): Send gRPC requests between workloads over mTLS using automatically rotated X.509 SVIDs obtained from the SPIFFE Workload API.
- [HTTP over mTLS](spiffe-http/README.md): Send HTTP requests between workloads over mTLS using automatically rotated X.509 SVIDs obtained from the SPIFFE Workload API.
- [HTTP over TLS with JWT and X.509 SVIDs](spiffe-jwt/README.md): Send HTTP requests between workloads over a TLS + JWT authentication using automatically rotated X.509 SVIDs and JWT SVIDs from the SPIFFE Workload API.
- [HTTP over TLS with JWT SVIDs only](spiffe-jwt-using-proxy/README.md): Authenticate client workloads to the server using JWT-SVIDs sent over TLS-encrypted HTTP connections when a proxy or load balancer prevents mTLS.
