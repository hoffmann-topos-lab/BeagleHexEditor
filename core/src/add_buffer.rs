use std::io::Write;
use std::os::unix::fs::FileExt;

use crate::error::Result;

pub const DEFAULT_SPILL_THRESHOLD: usize = 256 * 1024 * 1024;

enum Backing {
    Memory(Vec<u8>),
    /// Unnamed temporary file: the OS deletes it when the handle closes.
    Spilled(tempfile::NamedTempFile),
}

pub struct AddBuffer {
    backing: Backing,
    len: u64,
    threshold: usize,
}

impl AddBuffer {
    pub fn new(threshold: usize) -> Self {
        Self { backing: Backing::Memory(Vec::new()), len: 0, threshold }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn spilled(&self) -> bool {
        matches!(self.backing, Backing::Spilled(_))
    }

    /// Appends `data` and returns the offset at which it starts.
    pub fn append(&mut self, data: &[u8]) -> Result<u64> {
        let start = self.len;

        if let Backing::Memory(mem) = &self.backing
            && mem.len() + data.len() > self.threshold
        {
            self.spill()?;
        }

        match &mut self.backing {
            Backing::Memory(mem) => mem.extend_from_slice(data),
            Backing::Spilled(f) => {
                f.as_file().write_all_at(data, start)?;
            }
        }

        self.len += data.len() as u64;
        Ok(start)
    }

    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        debug_assert!(offset + buf.len() as u64 <= self.len);
        match &self.backing {
            Backing::Memory(mem) => {
                let s = offset as usize;
                buf.copy_from_slice(&mem[s..s + buf.len()]);
            }
            Backing::Spilled(f) => f.as_file().read_exact_at(buf, offset)?,
        }
        Ok(())
    }

    /// Moves the contents from RAM to a temporary file. Offsets already handed
    /// out stay valid: the logical space is the same.
    fn spill(&mut self) -> Result<()> {
        let Backing::Memory(mem) = &self.backing else { return Ok(()) };
        let mut tmp = tempfile::NamedTempFile::new()?;
        tmp.write_all(mem)?;
        tmp.flush()?;
        self.backing = Backing::Spilled(tmp);
        Ok(())
    }
}

impl Default for AddBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_SPILL_THRESHOLD)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_returns_sequential_offsets() {
        let mut b = AddBuffer::new(1024);
        assert_eq!(b.append(b"abc").unwrap(), 0);
        assert_eq!(b.append(b"de").unwrap(), 3);
        assert_eq!(b.len(), 5);
    }

    #[test]
    fn reads_back_what_was_written() {
        let mut b = AddBuffer::new(1024);
        let off = b.append(b"hello world").unwrap();
        let mut out = [0u8; 5];
        b.read_at(off + 6, &mut out).unwrap();
        assert_eq!(&out, b"world");
    }

    #[test]
    fn spills_to_disk_and_preserves_offsets() {
        let mut b = AddBuffer::new(8);
        let a = b.append(b"12345").unwrap();
        assert!(!b.spilled());
        let c = b.append(b"67890").unwrap(); // 5 + 5 > 8, spills
        assert!(b.spilled());
        assert_eq!((a, c), (0, 5));

        let mut out = [0u8; 10];
        b.read_at(0, &mut out).unwrap();
        assert_eq!(&out, b"1234567890");
    }

    #[test]
    fn keeps_working_after_spilling() {
        let mut b = AddBuffer::new(4);
        b.append(b"aaaaa").unwrap();
        let off = b.append(b"bbb").unwrap();
        assert!(b.spilled());
        let mut out = [0u8; 3];
        b.read_at(off, &mut out).unwrap();
        assert_eq!(&out, b"bbb");
    }
}
