use std::time::Duration;

pub trait BackoffStrategy: Send + Sync {
    fn new_backoff(&self) -> Box<dyn Backoff>;
}

pub trait Backoff: Send {
    fn next(&mut self) -> Duration;
    fn reset(&mut self);
}

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
