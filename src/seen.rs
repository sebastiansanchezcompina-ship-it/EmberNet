use std::collections::VecDeque;

pub struct SeenCache {
    buf: VecDeque<u64>,
    max: usize,
}

impl SeenCache {
    pub fn new(max: usize) -> Self {
        Self { buf: VecDeque::new(), max }
    }

    pub fn seen(&mut self, id: u64) -> bool {
        if self.buf.contains(&id) {
            true
        } else {
            self.buf.push_back(id);
            if self.buf.len() > self.max {
                self.buf.pop_front();
            }
            false
        }
    }
}
