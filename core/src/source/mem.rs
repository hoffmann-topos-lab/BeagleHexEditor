use std::ops::Range;
use std::sync::RwLock;

use super::{Capabilities, DataSource};
use crate::error::{Error, ErrorKind, Result};

pub struct MemSource {
    data: RwLock<Vec<u8>>,
    writable: bool,
    /// Ranges that must fail on read, simulating bad sectors.
    bad: Vec<Range<u64>>,
}

impl MemSource {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data: RwLock::new(data), writable: true, bad: Vec::new() }
    }

    pub fn read_only(mut self) -> Self {
        self.writable = false;
        self
    }

    /// Marks a range as unreadable. Every read touching it returns `BadBlock`.
    pub fn with_bad_range(mut self, range: Range<u64>) -> Self {
        self.bad.push(range);
        self
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.data.read().unwrap().clone()
    }
}

impl DataSource for MemSource {
    fn size(&self) -> u64 {
        self.data.read().unwrap().len() as u64
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::file(self.writable)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let end = offset + buf.len() as u64;
        if end > self.size() {
            return Err(Error::new(ErrorKind::OutOfBounds, ""));
        }
        if self.bad.iter().any(|b| offset < b.end && b.start < end) {
            return Err(Error::new(ErrorKind::BadBlock, "simulated bad range"));
        }
        let data = self.data.read().unwrap();
        buf.copy_from_slice(&data[offset as usize..end as usize]);
        Ok(())
    }

    fn write_at(&self, offset: u64, src: &[u8]) -> Result<()> {
        if !self.writable {
            return Err(Error::new(ErrorKind::ReadOnly, ""));
        }
        let end = offset + src.len() as u64;
        if end > self.size() {
            return Err(Error::new(ErrorKind::OutOfBounds, ""));
        }
        let mut data = self.data.write().unwrap();
        data[offset as usize..end as usize].copy_from_slice(src);
        Ok(())
    }
}
