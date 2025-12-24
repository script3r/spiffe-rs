//! Backoff strategies used for Workload API watch retries.
//!
//! The Workload API watch RPCs are long-lived streams. When a stream errors or
//! disconnects, the client retries with a delay determined by a [`Backoff`].
//! Implementations are expected to be cheap and deterministic (no sleeping) and
//! to be reset after a successful receive.

use std::time::Duration;

/// Creates independent [`Backoff`] instances with the same policy.
///
/// A strategy is stored in client configuration and used to construct a fresh
/// backoff state for each watch loop.
pub trait BackoffStrategy: Send + Sync {
    /// Returns a new backoff state machine.
    fn new_backoff(&self) -> Box<dyn Backoff>;
}

/// A stateful backoff timer.
///
/// Implementations return the next delay to wait before retrying, and can be
/// reset after a successful attempt.
pub trait Backoff: Send {
    /// Returns the delay to wait before the next retry.
    fn next(&mut self) -> Duration;
    /// Resets the backoff to its initial state (e.g. after a successful call).
    fn reset(&mut self);
}

/// A simple linear backoff strategy (`delay = initial * n`, capped).
///
/// This is the crate default for Workload API watches.
#[derive(Default)]
pub struct LinearBackoffStrategy;

impl BackoffStrategy for LinearBackoffStrategy {
    fn new_backoff(&self) -> Box<dyn Backoff> {
        Box::new(LinearBackoff::new())
    }
}

pub struct LinearBackoff {
    initial_delay: Duration,
    max_delay: Duration,
    n: u64,
}

impl LinearBackoff {
    /// Creates a linear backoff with defaults:
    ///
    /// - **initial**: 1s
    /// - **max**: 30s
    ///
    /// The first call to [`Backoff::next`] returns 1s, then 2s, etc., capped at
    /// 30s.
    pub fn new() -> Self {
        Self {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            n: 0,
        }
    }
}

impl Backoff for LinearBackoff {
    fn next(&mut self) -> Duration {
        self.n += 1;
        let backoff = self.initial_delay.as_secs_f64() * self.n as f64;
        let secs = backoff.min(self.max_delay.as_secs_f64());
        Duration::from_secs_f64(secs)
    }

    fn reset(&mut self) {
        self.n = 0;
    }
}
