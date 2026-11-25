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

#[derive(Debug, Clone)]
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

    /// Policy for a potential biometric prompt, shared across transports.
    pub const fn prompt_limit() -> Limit {
        Limit::new(crate::types::RATE_AUTH_PROMPT, crate::types::RATE_AUTH_PROMPT_WINDOW)
    }

    pub const fn pairing_limit() -> Limit {
        Limit::new(crate::types::RATE_PAIRING, crate::types::RATE_PAIRING_WINDOW)
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
    /// Only admitted events are recorded. Denials neither extend the cooldown
    /// nor grow the timestamp queue. The caller supplies nondecreasing time.
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
        if allowed {
            q.push_back(now);
        }
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
                    Some(t) => t.saturating_add(self.limit.window_secs).saturating_sub(now),
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

    /// Serialise the recorded events to a line-oriented string.
    ///
    /// Format: first line is `limit <max> <window>`; subsequent lines are
    /// `<key> <ts1> <ts2> ...`. Empty queues are omitted. Keys must be
    /// nonempty tokens without whitespace. The header is always present.
    pub fn to_lines(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "limit {} {}\n",
            self.limit.max_events, self.limit.window_secs
        ));
        let mut entries: Vec<_> = self.events.iter().collect();
        entries.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        for (key, q) in entries {
            if q.is_empty() {
                continue;
            }
            out.push_str(key);
            for t in q {
                out.push(' ');
                out.push_str(&t.to_string());
            }
            out.push('\n');
        }
        out
    }

    /// Strictly restore a snapshot using the configured limit, never a limit
    /// chosen by persisted data. Corrupt or obsolete snapshots must not reset
    /// the budget silently. `last_admitted` bounds every recorded timestamp.
    pub fn from_lines(s: &str, expected: Limit, last_admitted: u64) -> Option<RateLimiter> {
        let mut lines = s.lines();
        let mut parts = lines.next()?.split_whitespace();
        if parts.next()? != "limit" {
            return None;
        }
        let max: u32 = parts.next()?.parse().ok()?;
        let window: u64 = parts.next()?.parse().ok()?;
        if parts.next().is_some() || Limit::new(max, window) != expected
            || max == 0 || window == 0 {
            return None;
        }
        let mut rl = RateLimiter::new(expected);
        for line in lines {
            let mut parts = line.split_whitespace();
            let key = parts.next()?.to_owned();
            let mut q = VecDeque::new();
            for ts in parts {
                let ts: u64 = ts.parse().ok()?;
                if ts > last_admitted || q.back().is_some_and(|last| *last > ts)
                    || q.len() >= max as usize {
                    return None;
                }
                q.push_back(ts);
            }
            if q.is_empty() || rl.events.insert(key, q).is_some() {
                return None;
            }
        }
        Some(rl)
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
        // At t = 11 the admitted event at t=0 has aged out. Denial at t=6
        // did not move the cooldown.
        assert!(rl.check_and_record("a", 11));
        assert!(!rl.check_and_record("a", 12));
        assert!(rl.check_and_record("a", 15));
    }

    #[test]
    fn keys_are_independent() {
        let mut rl = RateLimiter::new(Limit::new(1, 60));
        assert!(rl.check_and_record("a", 0));
        assert!(rl.check_and_record("b", 0));
        assert!(!rl.check_and_record("a", 0));
    }

    #[test]
    fn denied_events_do_not_extend_cooldown_or_grow_state() {
        let mut rl = RateLimiter::new(Limit::new(1, 60));
        assert!(rl.check_and_record("a", 0));
        for _ in 0..1000 {
            assert!(!rl.check_and_record("a", 59));
        }
        assert_eq!(rl.retry_after("a", 59), 1);
        assert_eq!(rl.events.get("a").unwrap().len(), 1);
        assert!(rl.check_and_record("a", 60));
    }

    #[test]
    fn snapshot_rejects_corruption_and_limit_changes() {
        let limit = Limit::new(2, 60);
        let mut rl = RateLimiter::new(limit);
        assert!(rl.check_and_record("alice", 100));
        let text = rl.to_lines();
        let restored = RateLimiter::from_lines(&text, limit, 100).unwrap();
        assert_eq!(restored.to_lines(), text);
        assert!(RateLimiter::from_lines(&text, Limit::new(3, 60), 100).is_none());
        for bad in ["", "limit 2 60\na 101\n", "limit 2 60\na 100 99\n",
                    "limit 2 60\na 99\na 100\n", "limit 2 60\na 99 100 100\n"] {
            assert!(RateLimiter::from_lines(bad, limit, 100).is_none());
        }
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
