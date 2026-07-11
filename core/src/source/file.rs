use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::Path;

use super::{Capabilities, DataSource};
use crate::error::{Error, ErrorKind, Result};

pub struct FileSource {
    file: File,
    size: u64,
    writable: bool,
}

impl FileSource {
    pub fn open(path: impl AsRef<Path>, writable: bool) -> Result<Self> {
        let file = OpenOptions::new().read(true).write(writable).open(path)?;
        let size = file.metadata()?.len();
        Ok(Self { file, size, writable })
    }

    fn check_bounds(&self, offset: u64, len: usize) -> Result<()> {
        let end = offset.checked_add(len as u64).ok_or_else(|| {
            Error::new(ErrorKind::OutOfBounds, "offset + len overflows u64")
        })?;
        if end > self.size {
            return Err(Error::new(
                ErrorKind::OutOfBounds,
                format!("[{offset}, {end}) exceeds size {}", self.size),
            ));
        }
        Ok(())
    }
}

impl DataSource for FileSource {
    fn size(&self) -> u64 {
        self.size
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::file(self.writable)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.check_bounds(offset, buf.len())?;
        let mut done = 0usize;
        while done < buf.len() {
            match self.file.read_at(&mut buf[done..], offset + done as u64) {
                Ok(0) => {
                    return Err(Error::new(ErrorKind::Io, "unexpected EOF"));
                }
                Ok(n) => done += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        if !self.writable {
            return Err(Error::new(ErrorKind::ReadOnly, "file opened without write access"));
        }
        let mut done = 0usize;
        while done < data.len() {
            match self.file.write_at(&data[done..], offset + done as u64) {
                Ok(0) => return Err(Error::new(ErrorKind::Io, "wrote 0 bytes")),
                Ok(n) => done += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        self.file.sync_all()?;
        Ok(())
    }
}
