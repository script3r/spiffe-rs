use crate::bundle::x509bundle;
use crate::svid::x509svid;

#[derive(Debug)]
pub struct X509Context {
    pub svids: Vec<x509svid::SVID>,
    pub bundles: x509bundle::Set,
}

impl X509Context {
    pub fn default_svid(&self) -> Option<x509svid::SVID> {
        self.svids.first().cloned()
    }
}
