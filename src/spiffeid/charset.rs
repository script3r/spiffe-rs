#[cfg(feature = "spiffeid-charset-backcompat")]
pub fn is_backcompat_trust_domain_char(c: u8) -> bool {
    if is_sub_delim(c) {
        return true;
    }
    matches!(c, b'~')
}

#[cfg(feature = "spiffeid-charset-backcompat")]
pub fn is_backcompat_path_char(c: u8) -> bool {
    if is_sub_delim(c) {
        return true;
    }
    matches!(c, b'~' | b':' | b'[' | b']' | b'@')
}

#[cfg(feature = "spiffeid-charset-backcompat")]
fn is_sub_delim(c: u8) -> bool {
    matches!(
        c,
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    )
}

#[cfg(not(feature = "spiffeid-charset-backcompat"))]
pub fn is_backcompat_trust_domain_char(_c: u8) -> bool {
    false
}

#[cfg(not(feature = "spiffeid-charset-backcompat"))]
pub fn is_backcompat_path_char(_c: u8) -> bool {
    false
}
