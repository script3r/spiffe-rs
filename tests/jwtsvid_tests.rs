use rand::rngs::OsRng;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::RsaPrivateKey;
use sha2::Sha256;
use rsa::signature::{Signer, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use base64::Engine;
use spiffe_rs::bundle::jwtbundle::{Bundle, JwtKey};
use spiffe_rs::svid::jwtsvid;
use spiffe_rs::spiffeid::require_trust_domain_from_string;
use std::time::{Duration, SystemTime};

fn generate_rsa_key() -> RsaPrivateKey {
    RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa key")
}

fn generate_p384_key() -> p384::ecdsa::SigningKey {
    p384::ecdsa::SigningKey::random(&mut OsRng)
}

fn build_jwt(
    alg: &str,
    kid: Option<&str>,
    typ: Option<&str>,
    claims: serde_json::Value,
    signer: &SignerKey,
) -> String {
    let mut header = serde_json::json!({ "alg": alg });
    if let Some(kid) = kid {
        header["kid"] = serde_json::Value::String(kid.to_string());
    }
    if let Some(typ) = typ {
        header["typ"] = serde_json::Value::String(typ.to_string());
    }
    let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header).expect("header json"),
    );
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&claims).expect("claims json"),
    );
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature = signer.sign(signing_input.as_bytes(), alg);
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature);
    format!("{}.{}", signing_input, sig_b64)
}

enum SignerKey {
    Rsa(RsaPrivateKey),
    P384(p384::ecdsa::SigningKey),
}

impl SignerKey {
    fn sign(&self, message: &[u8], alg: &str) -> Vec<u8> {
        match self {
            SignerKey::Rsa(key) => {
                let signer = RsaSigningKey::<Sha256>::new(key.clone());
                signer.sign(message).to_vec()
            }
            SignerKey::P384(key) => {
                if alg != "ES384" {
                    return vec![];
                }
                let sig: p384::ecdsa::Signature = key.sign(message);
                sig.to_bytes().to_vec()
            }
        }
    }
}

fn jwt_key_from_rsa(key: &RsaPrivateKey) -> JwtKey {
    let pub_key = key.to_public_key();
    JwtKey::Rsa {
        n: pub_key.n().to_bytes_be(),
        e: pub_key.e().to_bytes_be(),
    }
}

fn jwt_key_from_p384(key: &p384::ecdsa::SigningKey) -> JwtKey {
    let verifying = p384::ecdsa::VerifyingKey::from(key);
    let point = verifying.to_encoded_point(false);
    let bytes = point.as_bytes();
    let half = (bytes.len() - 1) / 2;
    JwtKey::Ec {
        crv: "P-384".to_string(),
        x: bytes[1..1 + half].to_vec(),
        y: bytes[1 + half..].to_vec(),
    }
}

#[test]
fn parse_and_validate_success() {
    let td = require_trust_domain_from_string("trustdomain");
    let rsa_key = generate_rsa_key();
    let p384_key = generate_p384_key();
    let bundle = Bundle::new(td.clone());
    bundle
        .add_jwt_authority("authority1", jwt_key_from_p384(&p384_key))
        .expect("add");
    bundle
        .add_jwt_authority("authority2", jwt_key_from_rsa(&rsa_key))
        .expect("add");

    let now = SystemTime::now();
    let exp = now + Duration::from_secs(60);
    let exp_secs = exp
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = serde_json::json!({
        "sub": "spiffe://trustdomain/host",
        "aud": ["audience"],
        "exp": exp_secs,
        "iat": exp_secs - 10,
    });
    let token = build_jwt("ES384", Some("authority1"), None, claims, &SignerKey::P384(p384_key));
    let svid = jwtsvid::parse_and_validate(&token, &bundle, &["audience".to_string()])
        .expect("parse");
    assert_eq!(svid.id.to_string(), "spiffe://trustdomain/host");
}

#[test]
fn parse_and_validate_errors() {
    let td = require_trust_domain_from_string("trustdomain");
    let rsa_key = generate_rsa_key();
    let p384_key = generate_p384_key();
    let bundle = Bundle::new(td.clone());
    bundle
        .add_jwt_authority("authority1", jwt_key_from_p384(&p384_key))
        .expect("add");

    let now = SystemTime::now();
    let exp_secs = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims_missing_sub = serde_json::json!({
        "aud": ["audience"],
        "exp": exp_secs,
    });
    let token = build_jwt(
        "ES384",
        Some("authority1"),
        None,
        claims_missing_sub,
        &SignerKey::P384(p384_key.clone()),
    );
    let err = jwtsvid::parse_and_validate(&token, &bundle, &["audience".to_string()])
        .unwrap_err()
        .to_string();
    assert!(err.contains("token missing subject claim"));

    let claims = serde_json::json!({
        "sub": "spiffe://trustdomain/host",
        "aud": ["audience"],
        "exp": exp_secs,
    });
    let token = build_jwt("RS256", None, None, claims, &SignerKey::Rsa(rsa_key));
    let err = jwtsvid::parse_and_validate(&token, &bundle, &["audience".to_string()])
        .unwrap_err()
        .to_string();
    assert!(err.contains("token header missing key id"));
}

#[test]
fn parse_insecure_success() {
    let _td = require_trust_domain_from_string("trustdomain");
    let p384_key = generate_p384_key();
    let now = SystemTime::now();
    let exp_secs = (now + Duration::from_secs(60))
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = serde_json::json!({
        "sub": "spiffe://trustdomain/host",
        "aud": ["audience"],
        "exp": exp_secs,
    });
    let token = build_jwt("ES384", Some("key1"), None, claims, &SignerKey::P384(p384_key));
    let svid = jwtsvid::parse_insecure(&token, &["audience".to_string()]).expect("parse");
    assert_eq!(svid.id.to_string(), "spiffe://trustdomain/host");
}
