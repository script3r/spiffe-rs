use crate::internal::jwk::JwtKey;
use std::collections::HashMap;

pub fn copy_jwt_authorities(jwt_authorities: &HashMap<String, JwtKey>) -> HashMap<String, JwtKey> {
    jwt_authorities.clone()
}

pub fn jwt_authorities_equal(a: &HashMap<String, JwtKey>, b: &HashMap<String, JwtKey>) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (key, value) in a {
        match b.get(key) {
            Some(other) if other == value => {}
            _ => return false,
        }
    }
    true
}
