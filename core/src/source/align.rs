//! Sector-aligned I/O, shared by the two block-device sources (`DiskSource`
//! locally, `HelperSource` over the daemon). A raw device rejects a
//! `pread`/`pwrite` whose offset or length is not a multiple of the sector
//! size; these helpers round every access out to the enclosing sectors and
//! slice the caller's bytes back out. Writing a partial sector is a
//! read-modify-write, since a device is written a whole sector at a time.
//!
//! The `backend` closures are what differs between the two sources: one reads
//! a plain file, the other sends a request to the helper.

use crate::error::Result;

/// The sector-aligned `[start, end)` that covers `[offset, offset + len)`.
pub(crate) fn bounds(offset: u64, len: u64, block_size: u64) -> (u64, u64) {
    let start = offset - offset % block_size;
    let end = (offset + len).div_ceil(block_size) * block_size;
    (start, end)
}

/// Fills `buf` with `[offset, offset + buf.len())` using a backend that reads
/// an aligned span `[start, end)`.
pub(crate) fn read_into(
    offset: u64,
    buf: &mut [u8],
    block_size: u64,
    read_aligned: impl FnOnce(u64, u64) -> Result<Vec<u8>>,
) -> Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    let (start, end) = bounds(offset, buf.len() as u64, block_size);
    let aligned = read_aligned(start, end)?;
    let head = (offset - start) as usize;
    buf.copy_from_slice(&aligned[head..head + buf.len()]);
    Ok(())
}

/// Writes `data` at `offset`, preserving the untouched bytes of the boundary
/// sectors via read-modify-write.
pub(crate) fn write_at(
    offset: u64,
    data: &[u8],
    block_size: u64,
    read_aligned: impl FnOnce(u64, u64) -> Result<Vec<u8>>,
    write_aligned: impl FnOnce(u64, &[u8]) -> Result<()>,
) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    let (start, end) = bounds(offset, data.len() as u64, block_size);
    let mut block = read_aligned(start, end)?;
    let head = (offset - start) as usize;
    block[head..head + data.len()].copy_from_slice(data);
    write_aligned(start, &block)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_round_out_to_sectors() {
        assert_eq!(bounds(0, 512, 512), (0, 512));
        assert_eq!(bounds(10, 20, 512), (0, 512));
        assert_eq!(bounds(500, 100, 512), (0, 1024));
        assert_eq!(bounds(512, 512, 512), (512, 1024));
        assert_eq!(bounds(1000, 1, 512), (512, 1024));
        assert_eq!(bounds(1000, 30, 512), (512, 1536));
    }

    #[test]
    fn read_into_slices_the_middle() {
        let backend = |s: u64, e: u64| -> Result<Vec<u8>> {
            Ok((s as u8..e as u8).collect())
        };
        let mut buf = [0u8; 4];
        read_into(3, &mut buf, 8, backend).unwrap();
        assert_eq!(buf, [3, 4, 5, 6]);
    }

    #[test]
    fn write_at_preserves_the_edges() {
        let stored = std::cell::RefCell::new(vec![0xAAu8; 16]);
        let read = |s: u64, e: u64| -> Result<Vec<u8>> {
            Ok(stored.borrow()[s as usize..e as usize].to_vec())
        };
        let write = |s: u64, data: &[u8]| -> Result<()> {
            stored.borrow_mut()[s as usize..s as usize + data.len()].copy_from_slice(data);
            Ok(())
        };
        write_at(3, b"XY", 8, read, write).unwrap();
        let out = stored.borrow();
        assert_eq!(&out[3..5], b"XY");
        assert_eq!(&out[..3], &[0xAA; 3]);
        assert_eq!(&out[5..8], &[0xAA; 3], "rest of the first sector kept");
        assert_eq!(&out[8..], &[0xAA; 8], "second sector untouched");
    }
}
