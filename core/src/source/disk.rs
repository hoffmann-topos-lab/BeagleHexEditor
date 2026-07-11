//! F-49/F-50 — Raw disk (or partition) as a `DataSource`.
//!
//! A block device is not resizable and demands block-aligned I/O: on macOS the
//! raw node `/dev/rdiskN` rejects a `pread`/`pwrite` whose offset or length is
//! not a multiple of the sector size (512 or 4096). This source hides that: it
//! rounds every access out to the enclosing sectors, reads/writes whole
//! sectors through `pread`/`pwrite`, and slices the caller's bytes back out.
//! The read-modify-write on the boundary sectors is what lets a single byte be
//! overwritten on a device that can only be written a sector at a time.
//!
//! Opening is read-only by default (D-constraint: writing is opt-in). Geometry
//! (size, sector size) comes from the caller — `disks::enumerate` provides it —
//! so this stays dependency-free (no `ioctl`).

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::os::unix::fs::FileExt;
use std::path::Path;

use super::{Capabilities, DataSource, align};
use crate::error::{Error, ErrorKind, Result};

pub struct DiskSource {
    file: File,
    size: u64,
    block_size: u64,
    writable: bool,
}

impl DiskSource {
    /// Opens the device at `path` with a known `block_size`. The size is probed
    /// via `lseek(SEEK_END)` — device nodes report 0 through `metadata`.
    pub fn open(path: impl AsRef<Path>, block_size: u32, writable: bool) -> Result<Self> {
        let mut file = OpenOptions::new().read(true).write(writable).open(path)?;
        let size = file.seek(SeekFrom::End(0))?;
        Self::with_geometry(file, size, block_size, writable)
    }

    /// Builds a source over an already-open file with explicit geometry. Kept
    /// separate so tests can wrap a plain temp file as if it were a device.
    pub fn with_geometry(file: File, size: u64, block_size: u32, writable: bool) -> Result<Self> {
        if block_size == 0 {
            return Err(Error::new(ErrorKind::Io, "sector size of zero"));
        }
        Ok(Self { file, size, block_size: block_size as u64, writable })
    }

    fn check_bounds(&self, offset: u64, len: usize) -> Result<u64> {
        let end = offset.checked_add(len as u64).ok_or_else(|| {
            Error::new(ErrorKind::OutOfBounds, "offset + len overflows u64")
        })?;
        if end > self.size {
            return Err(Error::new(
                ErrorKind::OutOfBounds,
                format!("[{offset}, {end}) exceeds device size {}", self.size),
            ));
        }
        Ok(end)
    }

    /// Reads exactly the aligned range `[start, end)` (both multiples of the
    /// sector size) into a fresh buffer.
    fn read_aligned(&self, start: u64, end: u64) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; (end - start) as usize];
        let mut done = 0usize;
        while done < buf.len() {
            match self.file.read_at(&mut buf[done..], start + done as u64) {
                Ok(0) => return Err(Error::new(ErrorKind::Io, "unexpected EOF on the device")),
                Ok(n) => done += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(buf)
    }

    fn write_aligned(&self, start: u64, data: &[u8]) -> Result<()> {
        debug_assert!(
            start.is_multiple_of(self.block_size)
                && (data.len() as u64).is_multiple_of(self.block_size)
        );
        let mut done = 0usize;
        while done < data.len() {
            match self.file.write_at(&data[done..], start + done as u64) {
                Ok(0) => return Err(Error::new(ErrorKind::Io, "wrote 0 bytes to the device")),
                Ok(n) => done += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}

impl DataSource for DiskSource {
    fn size(&self) -> u64 {
        self.size
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            writable: self.writable,
            resizable: false, // a device cannot change size (F-35/F-36 disabled)
            block_size: Some(self.block_size as u32),
            sparse: false,
        }
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        self.check_bounds(offset, buf.len())?;
        align::read_into(offset, buf, self.block_size, |s, e| {
            self.read_aligned(s, e.min(self.size))
        })
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        if !self.writable {
            return Err(Error::new(ErrorKind::ReadOnly, "device opened read-only"));
        }
        self.check_bounds(offset, data.len())?;
        align::write_at(
            offset,
            data,
            self.block_size,
            |s, e| self.read_aligned(s, e),
            |s, block| self.write_aligned(s, block),
        )
    }

    fn flush(&self) -> Result<()> {
        self.file.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_disk(bytes: &[u8], block_size: u32, writable: bool) -> DiskSource {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        tmp.write_all(bytes).unwrap();
        tmp.flush().unwrap();
        let file = OpenOptions::new().read(true).write(writable).open(tmp.path()).unwrap();
        DiskSource::with_geometry(file, bytes.len() as u64, block_size, writable).unwrap()
    }

    #[test]
    fn an_unaligned_read_returns_the_exact_bytes() {
        let data: Vec<u8> = (0..=255u8).cycle().take(2048).collect();
        let src = temp_disk(&data, 512, false);
        // A read that starts and ends mid-sector must still be exact.
        let mut buf = [0u8; 100];
        src.read_at(300, &mut buf).unwrap();
        assert_eq!(&buf[..], &data[300..400]);
    }

    #[test]
    fn capabilities_forbid_resizing() {
        let src = temp_disk(&[0u8; 512], 512, false);
        let caps = src.capabilities();
        assert!(!caps.resizable, "a device is never resizable");
        assert_eq!(caps.block_size, Some(512));
    }

    #[test]
    fn a_read_only_device_refuses_writes() {
        let src = temp_disk(&[0u8; 512], 512, false);
        assert_eq!(src.write_at(0, b"x").unwrap_err().kind, ErrorKind::ReadOnly);
    }

    #[test]
    fn a_sub_sector_write_preserves_the_untouched_bytes() {
        let data = vec![0xAAu8; 1024];
        let src = temp_disk(&data, 512, true);
        // Overwrite 3 bytes in the middle of the first sector.
        src.write_at(10, b"XYZ").unwrap();
        let mut buf = [0u8; 1024];
        src.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf[10..13], b"XYZ");
        assert_eq!(&buf[..10], &[0xAA; 10], "bytes before are untouched");
        assert_eq!(&buf[13..], &[0xAA; 1011], "bytes after are untouched");
    }

    #[test]
    fn a_write_spanning_a_sector_boundary_is_correct() {
        let data = vec![0u8; 1024];
        let src = temp_disk(&data, 512, true);
        let patch: Vec<u8> = (1..=20u8).collect();
        src.write_at(500, &patch).unwrap(); // crosses 512
        let mut buf = [0u8; 20];
        src.read_at(500, &mut buf).unwrap();
        assert_eq!(&buf[..], &patch[..]);
    }

    #[test]
    fn reading_past_the_end_is_out_of_bounds() {
        let src = temp_disk(&[0u8; 512], 512, false);
        let mut buf = [0u8; 8];
        assert_eq!(src.read_at(510, &mut buf).unwrap_err().kind, ErrorKind::OutOfBounds);
    }
}