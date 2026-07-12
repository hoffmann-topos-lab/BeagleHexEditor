use crate::error::{Error, ErrorKind, Result};
use crate::rng::Rng;

use super::Document;

/// Chunk generated at a time by `fill` (F-22). Filling 2 GB must not
/// materialize 2 GB at once — the `AddBuffer` spill (D7) handles the rest.
pub(super) const FILL_CHUNK: u64 = 1 << 20;

/// F-22 — What to write into each byte of the selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FillPattern {
    /// Repeats the sequence from the start to the end of the selection (a
    /// single byte being the common case).
    Repeat(Vec<u8>),
    /// Pseudo-random bytes. The seed makes the operation reproducible — which
    /// is what lets it be tested through the CLI.
    Random { seed: u64 },
}

impl Document {
    /// F-22 — Fills `offset..offset + len` with the pattern, as **a single**
    /// undo transaction. It is an overwrite: the document size does not change,
    /// so it works on non-resizable sources too.
    ///
    /// The range must fit inside the document — filling past the end would be
    /// an insertion in disguise.
    pub fn fill(&mut self, offset: u64, len: u64, pattern: &FillPattern) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        let end = offset.checked_add(len).ok_or_else(|| {
            Error::new(ErrorKind::OutOfBounds, "offset + length overflows 64 bits")
        })?;
        self.check_offset(end)?;
        let mut rng = match pattern {
            FillPattern::Repeat(p) if p.is_empty() => {
                return Err(Error::new(ErrorKind::Io, "empty fill pattern"));
            }
            FillPattern::Repeat(_) => None,
            FillPattern::Random { seed } => Some(Rng::new(*seed)),
        };

        let mut done = 0u64;
        while done < len {
            let n = (len - done).min(FILL_CHUNK) as usize;
            let mut buf = vec![0u8; n];
            match (pattern, &mut rng) {
                (FillPattern::Repeat(p), _) => {
                    // Align by the offset within the selection: the pattern
                    // stays correct across chunk boundaries.
                    for (i, b) in buf.iter_mut().enumerate() {
                        *b = p[(done as usize + i) % p.len()];
                    }
                }
                (FillPattern::Random { .. }, Some(rng)) => rng.fill(&mut buf),
                (FillPattern::Random { .. }, None) => unreachable!(),
            }
            self.overwrite(offset + done, &buf)?;
            if done > 0 {
                self.merge_with_previous(); // a single Ctrl+Z for the whole selection
            }
            done += n as u64;
        }
        Ok(())
    }
}
