//! Sliding-window rate limiting (`PROTOCOL.md` §12).
//!
//! A token-bucket-free design: an exact sliding window of event timestamps. It
//! is easy to reason about and the bounds are exactly the ones the specification
//! states, which matters more here than constant-time accounting.

use std::collections::HashMap;
use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit {
    pub max_events: u32,
    pub window_secs: u64,
}

impl Limit {
    pub const fn new(max_events: u32, window_secs: u64) -> Limit {
        Limit {
            max_events,
            window_secs,
        }
    }
}

#[derive(Debug)]
pub struct RateLimiter {
    limit: Limit,
    events: HashMap<String, VecDeque<u64>>,
}

impl RateLimiter {
    /// The authentication limit defined for a transport (`PROTOCOL.md` §11).
    pub fn for_auth_transport(t: crate::types::Transport) -> RateLimiter {
        let (max_events, window_secs) = t.rate_limit();
        RateLimiter::new(Limit::new(max_events, window_secs))
    }

    pub fn new(limit: Limit) -> RateLimiter {
        RateLimiter {
            limit,
            events: HashMap::new(),
        }
    }

    pub fn limit(&self) -> Limit {
        self.limit
    }

    /// Records an event for `key` and reports whether it is permitted.
    ///
    /// A rejected event is still recorded for over-limit keys so that a client
    /// hammering the endpoint cannot reset the window by retrying.
    pub fn check_and_record(&mut self, key: &str, now: u64) -> bool {
        // `None` means `now` is inside the very first window, so no recorded
        // event can have aged out yet. Using `saturating_sub` here would treat
        // `now == 0` as "everything older than 0 is stale" and discard events
        // that are still inside the window.
        let cutoff = now.checked_sub(self.limit.window_secs);
        let q = self.events.entry(key.to_owned()).or_default();
        while let Some(t) = q.front() {
            if cutoff.is_some_and(|c| *t <= c) {
                q.pop_front();
            } else {
                break;
            }
        }
        let allowed = (q.len() as u32) < self.limit.max_events;
        q.push_back(now);
        allowed
    }

    /// Seconds until the next event for `key` would be permitted. Returns 0
    /// when the key is not currently limited.
    pub fn retry_after(&self, key: &str, now: u64) -> u64 {
        let cutoff = now.checked_sub(self.limit.window_secs);
        match self.events.get(key) {
            None => 0,
            Some(q) => {
                let live_count = match cutoff {
                    None => q.len(),
                    Some(c) => q.iter().filter(|t| **t > c).count(),
                };
                if (live_count as u32) < self.limit.max_events {
                    return 0;
                }
                // The oldest live event must age out before a new one fits.
                let oldest_live = match cutoff {
                    None => q.front().copied(),
                    Some(c) => q.iter().copied().find(|t| *t > c),
                };
                match oldest_live {
                    Some(t) => (t + self.limit.window_secs).saturating_sub(now),
                    None => 0,
                }
            }
        }
    }

    /// Reports whether an event would be permitted without recording it.
    pub fn peek(&self, key: &str, now: u64) -> bool {
        let cutoff = now.checked_sub(self.limit.window_secs);
        match self.events.get(key) {
            None => true,
            Some(q) => {
                let live = match cutoff {
                    None => q.len(),
                    Some(c) => q.iter().filter(|t| **t > c).count(),
                };
                live < self.limit.max_events as usize
            }
        }
    }

    /// Forgets all recorded events for `key`.
    pub fn reset(&mut self, key: &str) {
        self.events.remove(key);
    }

    /// Drops entries that have no events left inside the window, bounding
    /// memory if an attacker rotates keys.
    pub fn prune(&mut self, now: u64) {
        let cutoff = now.checked_sub(self.limit.window_secs);
        self.events.retain(|_, q| {
            while let Some(t) = q.front() {
                if cutoff.is_some_and(|c| *t <= c) {
                    q.pop_front();
                } else {
                    break;
                }
            }
            !q.is_empty()
        });
    }

    pub fn tracked_keys(&self) -> usize {
        self.events.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_the_limit_then_denies() {
        let mut rl = RateLimiter::new(Limit::new(3, 60));
        assert!(rl.check_and_record("a", 0));
        assert!(rl.check_and_record("a", 1));
        assert!(rl.check_and_record("a", 2));
        assert!(!rl.check_and_record("a", 3));
        assert!(!rl.check_and_record("a", 4));
    }

    #[test]
    fn window_slides() {
        let mut rl = RateLimiter::new(Limit::new(2, 10));
        assert!(rl.check_and_record("a", 0));
        assert!(rl.check_and_record("a", 5));
        assert!(!rl.check_and_record("a", 6));
        // At t = 11 the t=0 event has aged out, but t=5 and the *denied* t=6
        // are still inside the window, so the limit is still reached.
        assert!(!rl.check_and_record("a", 11));
        // Once every recorded event has aged out, requests are allowed again.
        assert!(rl.check_and_record("a", 16));
    }

    #[test]
    fn keys_are_independent() {
        let mut rl = RateLimiter::new(Limit::new(1, 60));
        assert!(rl.check_and_record("a", 0));
        assert!(rl.check_and_record("b", 0));
        assert!(!rl.check_and_record("a", 0));
    }

    #[test]
    fn denied_events_still_count_so_retrying_cannot_reset() {
        let mut rl = RateLimiter::new(Limit::new(1, 60));
        assert!(rl.check_and_record("a", 0));
        for t in 1..100 {
            assert!(!rl.check_and_record("a", t));
        }
        // Still saturated: the window is full of recorded (mostly denied) events.
        assert!(!rl.check_and_record("a", 120));
        // Only once every recorded event has aged out does it recover.
        assert!(rl.check_and_record("a", 200));
    }

    #[test]
    fn peek_does_not_record() {
        let rl = RateLimiter::new(Limit::new(1, 60));
        assert!(rl.peek("a", 0));
        assert!(rl.peek("a", 0));
    }

    #[test]
    fn prune_bounds_memory() {
        let mut rl = RateLimiter::new(Limit::new(5, 10));
        for i in 0..100 {
            rl.check_and_record(&format!("k{i}"), i);
        }
        assert_eq!(rl.tracked_keys(), 100);
        rl.prune(1000);
        assert_eq!(rl.tracked_keys(), 0);
    }

    #[test]
    fn reset_clears_one_key() {
        let mut rl = RateLimiter::new(Limit::new(1, 60));
        rl.check_and_record("a", 0);
        assert!(!rl.check_and_record("a", 1));
        rl.reset("a");
        assert!(rl.check_and_record("a", 2));
    }
}
