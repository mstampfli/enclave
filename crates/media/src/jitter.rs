//! A jitter buffer for received media: reorders frames by their sequence
//! counter and releases them in order, waiting briefly to absorb reordering and
//! declaring a frame lost once enough later frames have piled up (so the decoder
//! can conceal the gap). Depth-driven, so it is deterministically testable.

use std::collections::BTreeMap;

/// What [`JitterBuffer::pop`] yields for the next in-order slot.
#[derive(Debug, PartialEq)]
pub enum Popped {
    /// The next frame, in order.
    Frame(Vec<u8>),
    /// The next frame was lost; the decoder should conceal (Opus PLC).
    Lost,
}

/// Reorders sequenced frames and releases them in order.
pub struct JitterBuffer {
    frames: BTreeMap<u64, Vec<u8>>,
    next_seq: u64,
    started: bool,
    /// How many later frames may accumulate before the missing one is declared
    /// lost. Larger = more reordering tolerance but more latency.
    max_depth: usize,
}

impl JitterBuffer {
    pub fn new(max_depth: usize) -> Self {
        Self {
            frames: BTreeMap::new(),
            next_seq: 0,
            started: false,
            max_depth: max_depth.max(1),
        }
    }

    /// Insert a received frame by its sequence counter. Frames older than what
    /// has already been released are dropped.
    pub fn push(&mut self, seq: u64, frame: Vec<u8>) {
        if self.started && seq < self.next_seq {
            return;
        }
        self.frames.insert(seq, frame);
    }

    /// Release the next slot if it is ready: the in-order frame, or `Lost` once
    /// enough later frames have accumulated, or `None` to keep waiting.
    pub fn pop(&mut self) -> Option<Popped> {
        if !self.started {
            let &first = self.frames.keys().next()?;
            self.next_seq = first;
            self.started = true;
        }
        if let Some(frame) = self.frames.remove(&self.next_seq) {
            self.next_seq += 1;
            return Some(Popped::Frame(frame));
        }
        // The next frame is missing. Wait unless enough later frames have piled
        // up, in which case we give up on it and conceal.
        if self.frames.len() >= self.max_depth {
            self.next_seq += 1;
            return Some(Popped::Lost);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reorders_into_sequence() {
        let mut jb = JitterBuffer::new(4);
        jb.push(1, vec![1]);
        jb.push(0, vec![0]);
        jb.push(2, vec![2]);

        assert_eq!(jb.pop(), Some(Popped::Frame(vec![0])));
        assert_eq!(jb.pop(), Some(Popped::Frame(vec![1])));
        assert_eq!(jb.pop(), Some(Popped::Frame(vec![2])));
        assert_eq!(jb.pop(), None, "buffer drained");
    }

    #[test]
    fn declares_loss_once_later_frames_pile_up() {
        let mut jb = JitterBuffer::new(2);
        jb.push(0, vec![0]);
        assert_eq!(jb.pop(), Some(Popped::Frame(vec![0]))); // next_seq now 1

        // Frames 1 and 2 never arrive; 3 and 4 do -> depth reaches max.
        jb.push(3, vec![3]);
        jb.push(4, vec![4]);
        assert_eq!(jb.pop(), Some(Popped::Lost)); // 1 concealed
        assert_eq!(jb.pop(), Some(Popped::Lost)); // 2 concealed
        assert_eq!(jb.pop(), Some(Popped::Frame(vec![3])));
        assert_eq!(jb.pop(), Some(Popped::Frame(vec![4])));
    }

    #[test]
    fn waits_when_not_enough_has_arrived() {
        let mut jb = JitterBuffer::new(3);
        jb.push(0, vec![0]);
        assert_eq!(jb.pop(), Some(Popped::Frame(vec![0])));
        // Only one later frame; below the depth threshold -> keep waiting.
        jb.push(2, vec![2]);
        assert_eq!(jb.pop(), None);
    }

    #[test]
    fn drops_frames_that_arrive_too_late() {
        let mut jb = JitterBuffer::new(2);
        jb.push(5, vec![5]);
        assert_eq!(jb.pop(), Some(Popped::Frame(vec![5]))); // starts at 5
        jb.push(4, vec![4]); // older than released -> dropped
        assert_eq!(jb.pop(), None);
    }
}
