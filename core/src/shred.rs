//! F-45 — File shredder.
//!
//! Overwrites a file's bytes in place with pseudo-random data, then optionally
//! removes it. **This does not guarantee the data is unrecoverable.** On SSDs
//! (wear leveling), copy-on-write filesystems (APFS, btrfs) with snapshots, or
//! any journaled filesystem, the overwrite may land on different physical
//! blocks than the original — the old bytes can survive. The UI must say this
//! plainly (§ I.5); shredding is offered for parity, not as a guarantee.

use std::fs::OpenOptions;
use std::os::unix::fs::FileExt;
use std::path::Path;

use crate::error::{Error, ErrorKind, Result};
use crate::progress::Progress;
use crate::rng::Rng;

const CHUNK: usize = 1 << 20;

/// The caveat every caller should surface before shredding.
pub const WARNING: &str = "Shredding overwrites the file's bytes in place. On SSDs, \
copy-on-write filesystems (APFS/btrfs) with snapshots, or journaled filesystems, this \
does NOT guarantee the data becomes unrecoverable.";

/// Overwrites every byte of `path` with `passes` passes of pseudo-random data
/// (at least one), syncing after each pass, then removes the file if `remove`.
/// Cooperative: cancellable through `progress` at chunk boundaries.
pub fn shred_file(path: &Path, passes: u32, remove: bool, progress: &Progress) -> Result<()> {
    let passes = passes.max(1);
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    let size = file.metadata()?.len();
    progress.set_total(size.saturating_mul(passes as u64));

    let mut rng = Rng::new(Rng::seed_from_time());
    let mut buf = vec![0u8; CHUNK];
    for _ in 0..passes {
        let mut off = 0u64;
        while off < size {
            if progress.is_cancelled() {
                return Err(Error::new(ErrorKind::Io, "cancelled"));
            }
            let n = ((size - off) as usize).min(CHUNK);
            rng.fill(&mut buf[..n]);
            file.write_all_at(&buf[..n], off)?;
            off += n as u64;
            progress.add_done(n as u64);
        }
        file.sync_all()?;
    }

    if remove {
        drop(file);
        std::fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.bin");
        std::fs::write(&path, bytes).unwrap();
        (dir, path)
    }

    #[test]
    fn shred_overwrites_the_bytes_but_keeps_the_size() {
        let original = b"TOP SECRET: the launch code is 0000".to_vec();
        let (_dir, path) = temp_file(&original);
        shred_file(&path, 1, false, &Progress::new()).unwrap();

        let after = std::fs::read(&path).unwrap();
        assert_eq!(after.len(), original.len(), "size preserved");
        assert_ne!(after, original, "content overwritten");
    }

    #[test]
    fn shred_can_remove_the_file() {
        let (_dir, path) = temp_file(b"gone soon");
        shred_file(&path, 2, true, &Progress::new()).unwrap();
        assert!(!path.exists(), "file deleted after shredding");
    }

    #[test]
    fn shred_reports_progress() {
        let (_dir, path) = temp_file(&vec![0u8; 4096]);
        let p = Progress::new();
        shred_file(&path, 3, false, &p).unwrap();
        assert_eq!(p.total(), 4096 * 3, "total counts every pass");
        assert_eq!(p.done(), 4096 * 3);
    }

    #[test]
    fn cancellation_stops_the_shred() {
        let (_dir, path) = temp_file(&vec![7u8; 8192]);
        let p = Progress::new();
        p.cancel();
        assert!(shred_file(&path, 1, true, &p).is_err());
        assert!(path.exists(), "a cancelled shred does not delete");
    }
}
