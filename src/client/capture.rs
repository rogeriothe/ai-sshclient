//! Collects a stream keeping only its head and tail once it exceeds `limit` bytes.

pub struct Capture {
    half: usize,
    head: Vec<u8>,
    tail: std::collections::VecDeque<u8>,
    total: usize,
}

impl Capture {
    pub fn new(limit: i64) -> Self {
        let half = if limit > 0 { (limit as usize) / 2 } else { 0 };
        Capture {
            half,
            head: Vec::new(),
            tail: std::collections::VecDeque::new(),
            total: 0,
        }
    }

    pub fn add(&mut self, data: &[u8]) {
        self.total += data.len();
        if self.half == 0 {
            self.head.extend_from_slice(data);
            return;
        }
        let mut data = data;
        let room = self.half.saturating_sub(self.head.len());
        if room > 0 {
            let take = room.min(data.len());
            self.head.extend_from_slice(&data[..take]);
            data = &data[take..];
        }
        if !data.is_empty() {
            self.tail.extend(data.iter().copied());
            while self.tail.len() > self.half {
                self.tail.pop_front();
            }
        }
    }

    pub fn total(&self) -> usize {
        self.total
    }

    pub fn dropped(&self) -> usize {
        self.total - self.head.len() - self.tail.len()
    }

    pub fn text(&self) -> String {
        let head = String::from_utf8_lossy(&self.head);
        let tail_bytes: Vec<u8> = self.tail.iter().copied().collect();
        let tail = String::from_utf8_lossy(&tail_bytes);
        let dropped = self.dropped();
        if dropped > 0 {
            format!("{head}\n...[{dropped} bytes truncated]...\n{tail}")
        } else {
            format!("{head}{tail}")
        }
    }
}
