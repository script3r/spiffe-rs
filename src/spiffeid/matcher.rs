use crate::spiffeid::{ID, TrustDomain};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatcherError(String);

impl std::fmt::Display for MatcherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for MatcherError {}

pub type Matcher = Box<dyn Fn(&ID) -> std::result::Result<(), MatcherError> + Send + Sync>;

pub fn match_any() -> Matcher {
    Box::new(|_actual| Ok(()))
}

pub fn match_id(expected: ID) -> Matcher {
    Box::new(move |actual| {
        if *actual != expected {
            return Err(MatcherError(format!("unexpected ID \"{}\"", actual)));
        }
        Ok(())
    })
}

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
