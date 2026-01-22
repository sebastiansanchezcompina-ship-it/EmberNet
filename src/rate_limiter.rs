use std::time::{Duration, Instant};

pub struct RateLimiter {
    last: Instant,
    min_interval: Duration,
}

impl RateLimiter {
    /// Permite 1 acción cada X ms
    pub fn new() -> Self {
        Self {
            last: Instant::now() - Duration::from_secs(1),
            min_interval: Duration::from_millis(300),
        }
    }

    /// Devuelve true si se permite la acción
    pub fn allow(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.last) >= self.min_interval {
            self.last = now;
            true
        } else {
            false
        }
    }
}
