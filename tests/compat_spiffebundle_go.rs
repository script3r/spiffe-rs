use spiffe_rs::bundle::spiffebundle;
use spiffe_rs::spiffeid;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn spiffebundle_marshal_matches_go() {
    if std::env::var("SPIFFE_RS_GO_COMPAT").ok().as_deref() != Some("1") {
        return;
    }
    let go_spiffe = Path::new("../go-spiffe");
    if !go_spiffe.exists() {
        return;
    }
    if Command::new("go").arg("version").output().is_err() {
        return;
    }

    let temp_dir = std::env::temp_dir().join(format!(
        "spiffe_rs_compat_{}_{}",
        std::process::id(),
        chrono_stamp()
    ));
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let go_mod = format!(
        "module compat\n\ngo 1.20\n\nrequire github.com/spiffe/go-spiffe/v2 v2.0.0\n\nreplace github.com/spiffe/go-spiffe/v2 => {}\n",
        go_spiffe.canonicalize().expect("canon").display()
    );
    fs::write(temp_dir.join("go.mod"), go_mod).expect("write go.mod");

    let input = PathBuf::from("tests/testdata/spiffebundle/spiffebundle_valid_1.json");
    let input_abs = input.canonicalize().expect("canonicalize test bundle path");
    let trust_domain = "domain.test";
    let main = format!(
        r#"
package main

import (
    "fmt"
    "os"
    "github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
    "github.com/spiffe/go-spiffe/v2/spiffeid"
)

func main() {{
    data, err := os.ReadFile("{input}")
    if err != nil {{
        panic(err)
    }}
    td := spiffeid.RequireTrustDomainFromString("{trust_domain}")
    bundle, err := spiffebundle.Parse(td, data)
    if err != nil {{
        panic(err)
    }}
    out, err := bundle.Marshal()
    if err != nil {{
        panic(err)
    }}
    fmt.Print(string(out))
}}
"#,
        input = input_abs.display(),
        trust_domain = trust_domain
    );
    fs::write(temp_dir.join("main.go"), main).expect("write main.go");

    let output = Command::new("go")
        .arg("run")
        .arg("-mod=mod")
        .arg(".")
        .current_dir(&temp_dir)
        .env("GOWORK", "off")
        .output()
        .expect("go run");
    assert!(
        output.status.success(),
        "go run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let rust_bytes = fs::read(&input).expect("read input");
    let td = spiffeid::require_trust_domain_from_string(trust_domain);
    let rust_bundle = spiffebundle::Bundle::parse(td, &rust_bytes).expect("parse bundle");
    let rust_marshaled = rust_bundle.marshal().expect("marshal bundle");

    let go_value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse go json");
    let rust_value: serde_json::Value =
        serde_json::from_slice(&rust_marshaled).expect("parse rust json");
    assert_eq!(go_value, rust_value);
}

fn chrono_stamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    now.to_string()
}
