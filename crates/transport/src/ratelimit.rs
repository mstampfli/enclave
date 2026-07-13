//! A token-bucket rate limiter (ASVS V11). Time is injected as an `Instant`
//! argument so the bucket is deterministically testable without a real clock.
//! The server keeps one bucket per connection to throttle floods.

use std::time::Instant;

/// A refilling token bucket: bursts up to `capacity`, sustained at
/// `refill_per_sec`.
/// PRIMITIVE: token-bucket rate limiter; the one home for per-connection/
/// per-source flood limiting.
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(capacity: f64, refill_per_sec: f64, now: Instant) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_per_sec,
            last: now,
        }
    }

    /// Try to spend one token. Returns false when the bucket is empty (the
    /// caller is over its rate and the message should be dropped).
    pub fn try_take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TokenBucket;
    use std::time::{Duration, Instant};

    #[test]
    fn allows_a_burst_then_throttles_and_refills() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(5.0, 10.0, t0); // burst 5, 10/sec

        // The full burst is allowed at one instant, the next is denied.
        for _ in 0..5 {
            assert!(bucket.try_take(t0));
        }
        assert!(!bucket.try_take(t0), "over-capacity in the same instant");

        // After 0.3 s, about 3 tokens have refilled.
        let t1 = t0 + Duration::from_millis(300);
        assert!(bucket.try_take(t1));
        assert!(bucket.try_take(t1));
        assert!(bucket.try_take(t1));
        assert!(!bucket.try_take(t1), "only ~3 refilled in 0.3 s at 10/sec");
    }

    #[test]
    fn refill_is_capped_at_capacity() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(4.0, 100.0, t0);
        // A long idle does not let the bucket exceed its capacity.
        let later = t0 + Duration::from_secs(60);
        for _ in 0..4 {
            assert!(bucket.try_take(later));
        }
        assert!(
            !bucket.try_take(later),
            "capacity is the ceiling, not idle time"
        );
    }
}
