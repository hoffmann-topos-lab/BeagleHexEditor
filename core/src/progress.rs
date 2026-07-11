use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Progress {
    cancelled: AtomicBool,
    done: AtomicU64,
    total: AtomicU64,
}

impl Progress {
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation. The operation stops at the next block boundary —
    /// never in the middle of a write.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    pub fn set_total(&self, total: u64) {
        self.total.store(total, Ordering::Relaxed);
    }

    pub fn add_done(&self, n: u64) {
        self.done.fetch_add(n, Ordering::Relaxed);
    }

    pub fn done(&self) -> u64 {
        self.done.load(Ordering::Relaxed)
    }

    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// Fraction complete in `[0, 1]`; 0 while the total is unknown.
    pub fn fraction(&self) -> f32 {
        let total = self.total();
        if total == 0 {
            return 0.0;
        }
        (self.done() as f64 / total as f64).min(1.0) as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_and_cancellation() {
        let p = Progress::new();
        assert_eq!(p.fraction(), 0.0, "unknown total");
        p.set_total(200);
        p.add_done(50);
        assert_eq!(p.fraction(), 0.25);
        p.add_done(300);
        assert_eq!(p.fraction(), 1.0, "never exceeds 1");
        assert!(!p.is_cancelled());
        p.cancel();
        assert!(p.is_cancelled());
    }
}
