use spiffe_rs::spiffeid;
use spiffe_rs::workloadapi;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[tokio::test]
async fn workloadapi_fetches_from_go_server() {
    if std::env::var("SPIFFE_RS_GO_COMPAT").ok().as_deref() != Some("1") {
        return;
    }
    if Command::new("go").arg("version").output().is_err() {
        return;
    }
    let go_spiffe = Path::new("../go-spiffe");
    if !go_spiffe.exists() {
        return;
    }

    let temp_dir = std::env::temp_dir().join(format!(
        "spiffe_rs_wl_{}_{}",
        std::process::id(),
        chrono_stamp()
    ));
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let go_mod = format!(
        "module compat\n\ngo 1.20\n\nrequire github.com/spiffe/go-spiffe/v2 v2.0.0\n\nreplace github.com/spiffe/go-spiffe/v2 => {}\n",
        go_spiffe.canonicalize().expect("canon").display()
    );
    fs::write(temp_dir.join("go.mod"), go_mod).expect("write go.mod");

    let cert_path = PathBuf::from("tests/testdata/x509svid/good-key-and-cert.pem")
        .canonicalize()
        .expect("cert path");
    let main = format!(
        r#"
package main

import (
    "encoding/pem"
    "fmt"
    "net"
    "os"

    "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
    "google.golang.org/grpc"
)

type server struct {{
    workload.UnimplementedSpiffeWorkloadAPIServer
    certDER []byte
    keyDER []byte
}}

func (s *server) FetchX509SVID(req *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {{
    resp := &workload.X509SVIDResponse{{
        Svids: []*workload.X509SVID{{
            &workload.X509SVID{{
                SpiffeId: "spiffe://example.org/workload-1",
                X509Svid: s.certDER,
                X509SvidKey: s.keyDER,
                Bundle: s.certDER,
            }},
        }},
    }}
    return stream.Send(resp)
}}

func (s *server) FetchX509Bundles(req *workload.X509BundlesRequest, stream workload.SpiffeWorkloadAPI_FetchX509BundlesServer) error {{
    resp := &workload.X509BundlesResponse{{
        Bundles: map[string][]byte{{
            "example.org": s.certDER,
        }},
    }}
    return stream.Send(resp)
}}

func main() {{
    pemBytes, err := os.ReadFile("{cert_path}")
    if err != nil {{
        panic(err)
    }}
    var certDER []byte
    var keyDER []byte
    rest := pemBytes
    for len(rest) > 0 {{
        var block *pem.Block
        block, rest = pem.Decode(rest)
        if block == nil {{
            break
        }}
        switch block.Type {{
        case "CERTIFICATE":
            if certDER == nil {{
                certDER = block.Bytes
            }}
        case "RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY":
            if keyDER == nil {{
                keyDER = block.Bytes
            }}
        }}
    }}
    if certDER == nil {{
        panic("no CERTIFICATE block")
    }}
    if keyDER == nil {{
        panic("no PRIVATE KEY block")
    }}

    lis, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {{
        panic(err)
    }}
    fmt.Println(lis.Addr().String())

    srv := grpc.NewServer()
    workload.RegisterSpiffeWorkloadAPIServer(srv, &server{{certDER: certDER, keyDER: keyDER}})
    if err := srv.Serve(lis); err != nil {{
        panic(err)
    }}
}}
"#,
        cert_path = cert_path.display()
    );
    fs::write(temp_dir.join("main.go"), main).expect("write main.go");

    let mut child = Command::new("go")
        .arg("run")
        .arg("-mod=mod")
        .arg(".")
        .current_dir(&temp_dir)
        .env("GOWORK", "off")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn go server");

    let stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout);
    let mut addr = String::new();
    reader.read_line(&mut addr).expect("read addr");
    let addr = addr.trim().to_string();
    if addr.is_empty() {
        let _ = child.kill();
        panic!("go server did not provide a listen address");
    }

    let ctx = workloadapi::background();
    let client = workloadapi::Client::new(vec![workloadapi::with_addr(format!("tcp://{}", addr))])
        .await
        .expect("client");
    let svid = client.fetch_x509_svid(&ctx).await.expect("fetch svid");
    assert_eq!(svid.id.to_string(), "spiffe://example.org/workload-1");

    let bundles = client
        .fetch_x509_bundles(&ctx)
        .await
        .expect("fetch bundles");
    let td = spiffeid::require_trust_domain_from_string("example.org");
    let bundle = bundles
        .get_x509_bundle_for_trust_domain(td)
        .expect("bundle");
    assert!(!bundle.x509_authorities().is_empty());

    let _ = child.kill();
}

fn chrono_stamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    now.to_string()
}
