use crate::spiffeid::ID;
use crate::spiffetls::Result;
use x509_parser::extensions::GeneralName;

pub trait PeerIdGetter {
    fn peer_id(&self) -> Result<ID>;
}

pub fn peer_id_from_stream(certs: Option<&[rustls::Certificate]>) -> Result<ID> {
    let certs = certs.ok_or_else(|| crate::spiffetls::wrap_error("no peer certificates"))?;
    let cert = certs
        .first()
        .ok_or_else(|| crate::spiffetls::wrap_error("no peer certificates"))?;
    let (_rest, parsed) = x509_parser::parse_x509_certificate(&cert.0).map_err(|err| {
        crate::spiffetls::wrap_error(format!("invalid peer certificate: {}", err))
    })?;
    let san = parsed
        .subject_alternative_name()
        .map_err(|_| crate::spiffetls::wrap_error("invalid peer certificate: invalid URI SAN"))?
        .ok_or_else(|| crate::spiffetls::wrap_error("invalid peer certificate: no URI SAN"))?;
    let mut uris = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::URI(uri) => Some(*uri),
            _ => None,
        })
        .collect::<Vec<_>>();
    if uris.len() != 1 {
        return Err(crate::spiffetls::wrap_error(
            "invalid peer certificate: expected single URI SAN",
        ));
    }
    ID::from_string(uris.remove(0))
        .map_err(|err| crate::spiffetls::wrap_error(format!("invalid peer certificate: {}", err)))
}
