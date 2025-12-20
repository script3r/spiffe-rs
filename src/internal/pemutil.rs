use pem::Pem;
use x509_parser::prelude::X509Certificate;

const CERT_TYPE: &str = "CERTIFICATE";

#[derive(Debug)]
pub enum PemError {
    NoPemBlocks,
    Parse(String),
}

impl std::fmt::Display for PemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PemError::NoPemBlocks => write!(f, "no PEM blocks found"),
            PemError::Parse(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for PemError {}

pub fn parse_certificates(certs_bytes: &[u8]) -> Result<Vec<Vec<u8>>, PemError> {
    let pems = pem::parse_many(certs_bytes).map_err(|_| PemError::NoPemBlocks)?;
    let mut found_blocks = false;
    let mut certs = Vec::new();
    for pem in pems {
        found_blocks = true;
        if pem.tag() != CERT_TYPE {
            continue;
        }
        parse_certificate(&pem)?;
        certs.push(pem.contents().to_vec());
    }
    if !found_blocks {
        return Err(PemError::NoPemBlocks);
    }
    Ok(certs)
}

pub fn encode_certificates(certificates: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for cert in certificates {
        let pem = Pem::new(CERT_TYPE, cert.clone());
        out.extend_from_slice(pem::encode(&pem).as_bytes());
    }
    out
}

fn parse_certificate(pem: &Pem) -> Result<X509Certificate<'_>, PemError> {
    let (_rem, cert) = x509_parser::parse_x509_certificate(pem.contents())
        .map_err(|err| PemError::Parse(err.to_string()))?;
    Ok(cert)
}
