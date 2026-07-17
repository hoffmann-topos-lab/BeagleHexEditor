//! F-79 — Hashes and checksums as recipe steps: reuse the digest engine from
//! [`crate::hash`] (F-25/F-26) so a recipe like `from-hex | sha256` yields the
//! lowercase hex digest as text. A digest is terminal-ish — its output is the
//! hex string, not raw bytes.

use crate::hash::{Algo, Hasher};

pub fn hash(algo: Algo, data: &[u8]) -> Vec<u8> {
    let mut h = Hasher::new(algo);
    h.update(data);
    h.finalize().into_bytes()
}
