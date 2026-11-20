//! Consecutive equal chi rows have the same polynomial. They can share one
//! evaluation as long as it carries the sum of their individual row weights.
use super::{BITS, E};

pub(in crate::checkpoint_keccak) struct RowRuns {
    // Exclusive end of the equal run containing each logical row.
    ends: Vec<usize>,
}

impl RowRuns {
    pub fn from_words(words: &[u16]) -> Option<Self> {
        let (rows, tail) = words.as_chunks::<BITS>();
        debug_assert!(tail.is_empty());
        let mut ends = Vec::with_capacity(rows.len());
        let mut repeated = false;
        for run in rows.chunk_by(|a, b| a == b) {
            let end = ends.len() + run.len();
            ends.resize(end, end);
            repeated |= run.len() > 1;
        }
        repeated.then_some(Self { ends })
    }

    // A pair repeats only while both its low and high row repeat. After
    // folding, every such pair gives the same field row for any challenge.
    pub fn folded(mut self) -> Option<Self> {
        let half = self.ends.len() / 2;
        let mut repeated = false;
        for i in 0..half {
            let end = self.ends[i].min(self.ends[i + half] - half);
            self.ends[i] = end;
            repeated |= end > i + 1;
        }
        self.ends.truncate(half);
        repeated.then_some(self)
    }

    pub fn weighted(&self, weight: impl Fn(usize) -> E) -> Vec<(usize, E)> {
        let mut groups = Vec::with_capacity(self.ends.len());
        let mut start = 0;
        while start < self.ends.len() {
            let end = self.ends[start];
            let sum = (start + 1..end).fold(weight(start), |acc, i| acc + weight(i));
            groups.push((start, sum));
            start = end;
        }
        groups
    }
}
