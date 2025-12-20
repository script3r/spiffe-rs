use spiffe_rs::bundle::x509bundle;
use spiffe_rs::spiffeid;
use spiffe_rs::spiffetls;
use spiffe_rs::workloadapi;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;

#[tokio::test]
async fn spiffetls_accepts_go_svid_tls_server() {
    if std::env::var("SPIFFE_RS_GO_COMPAT").ok().as_deref() != Some("1") {
        return;
    }
    if Command::new("go").arg("version").output().is_err() {
        return;
    }

    let temp_dir = std::env::temp_dir()
        .join(format!("spiffe_rs_tls_{}_{}", std::process::id(), chrono_stamp()));
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let ca_path = temp_dir.join("ca.pem");
    fs::write(temp_dir.join("go.mod"), "module compat\n\ngo 1.20\n")
        .expect("write go.mod");

    let main = format!(
        r#"
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "fmt"
    "math/big"
    "os"
    "time"
    "net/url"
)

func main() {{
    caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {{
        panic(err)
    }}
    caTemplate := &x509.Certificate{{
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{{Organization: []string{{"SPIFFE"}}}},
        NotBefore: time.Now().Add(-time.Hour),
        NotAfter: time.Now().Add(24 * time.Hour),
        KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
        IsCA: true,
        BasicConstraintsValid: true,
    }}
    caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
    if err != nil {{
        panic(err)
    }}

    leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {{
        panic(err)
    }}
    spiffeURI, err := url.Parse("spiffe://example.org/workload-1")
    if err != nil {{
        panic(err)
    }}
    leafTemplate := &x509.Certificate{{
        SerialNumber: big.NewInt(2),
        Subject: pkix.Name{{Organization: []string{{"SPIRE"}}}},
        NotBefore: time.Now().Add(-time.Hour),
        NotAfter: time.Now().Add(24 * time.Hour),
        KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
        ExtKeyUsage: []x509.ExtKeyUsage{{x509.ExtKeyUsageServerAuth}},
        URIs: []*url.URL{{spiffeURI}},
    }}
    leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
    if err != nil {{
        panic(err)
    }}

    caPEM := pem.EncodeToMemory(&pem.Block{{Type: "CERTIFICATE", Bytes: caDER}})
    if err := os.WriteFile("{ca_path}", caPEM, 0644); err != nil {{
        panic(err)
    }}
    leafPEM := pem.EncodeToMemory(&pem.Block{{Type: "CERTIFICATE", Bytes: leafDER}})
    leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
    if err != nil {{
        panic(err)
    }}
    leafKeyPEM := pem.EncodeToMemory(&pem.Block{{Type: "EC PRIVATE KEY", Bytes: leafKeyDER}})
    cert, err := tls.X509KeyPair(leafPEM, leafKeyPEM)
    if err != nil {{
        panic(err)
    }}
    config := &tls.Config{{Certificates: []tls.Certificate{{cert}}}}
    lis, err := tls.Listen("tcp", "127.0.0.1:0", config)
    if err != nil {{
        panic(err)
    }}
    fmt.Println(lis.Addr().String())

    conn, err := lis.Accept()
    if err != nil {{
        panic(err)
    }}
    defer conn.Close()
    _, _ = conn.Write([]byte("ok"))
    _ = os.Stdout.Sync()
}}
"#,
        ca_path = ca_path.display()
    );
    fs::write(temp_dir.join("main.go"), main).expect("write main.go");

    let mut child = Command::new("go")
        .arg("run")
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

    let bundle = load_ca_bundle(&ca_path);
    let authorizer = spiffetls::tlsconfig::authorize_id(
        spiffeid::require_from_string("spiffe://example.org/workload-1"),
    );
    let ctx = workloadapi::background();
    let server_name = rustls::ServerName::try_from("example.org").expect("server name");
    let mode = spiffetls::tls_client_with_raw_config(authorizer, Arc::new(bundle));
    let mut stream = spiffetls::dial_with_mode(&ctx, &addr, server_name, mode, Vec::new())
        .await
        .expect("dial");
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).expect("read");
    assert_eq!(&buf, b"ok");

    let peer_id = stream.peer_id().expect("peer id");
    assert_eq!(peer_id.to_string(), "spiffe://example.org/workload-1");

    let _ = child.kill();
}

fn load_ca_bundle(path: &Path) -> x509bundle::Bundle {
    let bytes = fs::read(path).expect("read ca pem");
    let pems = pem::parse_many(&bytes).expect("parse pem");
    let trust_domain = spiffeid::require_trust_domain_from_string("example.org");
    let bundle = x509bundle::Bundle::new(trust_domain);
    for pem in pems {
        if pem.tag() != "CERTIFICATE" {
            continue;
        }
        let (_rest, cert) = x509_parser::parse_x509_certificate(pem.contents())
            .expect("parse cert");
        if cert.is_ca() {
            bundle.add_x509_authority(pem.contents());
        }
    }
    if bundle.empty() {
        panic!("no CA certificates found");
    }
    bundle
}

fn chrono_stamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    now.to_string()
}
