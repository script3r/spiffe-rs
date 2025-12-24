use crate::spiffeid::{TrustDomain, ID};

/// An error that occurred during SPIFFE ID matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatcherError(String);

impl std::fmt::Display for MatcherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for MatcherError {}

/// A matcher for SPIFFE IDs.
pub type Matcher = Box<dyn Fn(&ID) -> std::result::Result<(), MatcherError> + Send + Sync>;

/// Returns a matcher that matches any SPIFFE ID.
pub fn match_any() -> Matcher {
    Box::new(|_actual| Ok(()))
}

/// Returns a matcher that matches a specific SPIFFE ID.
pub fn match_id(expected: ID) -> Matcher {
    Box::new(move |actual| {
        if *actual != expected {
            return Err(MatcherError(format!("unexpected ID \"{}\"", actual)));
        }
        Ok(())
    })
}

/// Returns a matcher that matches any of the given SPIFFE IDs.
pub fn match_one_of(expected: &[ID]) -> Matcher {
    let expected = expected.to_vec();
    Box::new(move |actual| {
        if expected.iter().any(|id| id == actual) {
            Ok(())
        } else {
            Err(MatcherError(format!("unexpected ID \"{}\"", actual)))
        }
    })
}

/// Returns a matcher that matches any SPIFFE ID in the given trust domain.
pub fn match_member_of(expected: TrustDomain) -> Matcher {
    Box::new(move |actual| {
        if actual.member_of(&expected) {
            Ok(())
        } else {
            Err(MatcherError(format!(
                "unexpected trust domain \"{}\"",
                actual.trust_domain()
            )))
        }
    })
}
