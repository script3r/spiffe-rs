pub fn copy_x509_authorities(x509_authorities: &[Vec<u8>]) -> Vec<Vec<u8>> {
    x509_authorities.to_vec()
}

pub fn certs_equal(a: &[Vec<u8>], b: &[Vec<u8>]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).all(|(a, b)| a == b)
}

#[allow(dead_code)]
pub fn raw_certs_from_certs(certs: &[Vec<u8>]) -> Vec<Vec<u8>> {
    certs.to_vec()
}

#[allow(dead_code)]
pub fn concat_raw_certs_from_certs(certs: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for cert in certs {
        out.extend_from_slice(cert);
    }
    out
}
