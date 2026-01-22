use std::collections::{HashSet, VecDeque};

const MAX_CACHE: usize = 2048;

#[derive(Hash, Eq, PartialEq, Clone)]
pub struct ReplayKey {
    pub sender: [u8; 8],
    pub msg_id: [u8; 8],
}

pub struct ReplayCache {
    set: HashSet<ReplayKey>,
    order: VecDeque<ReplayKey>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self {
            set: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    /// Devuelve true si YA fue visto
    pub fn seen(&mut self, key: ReplayKey) -> bool {
        if self.set.contains(&key) {
            return true;
        }

        self.set.insert(key.clone());
        self.order.push_back(key);

        if self.order.len() > MAX_CACHE {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }

        false
    }
}
