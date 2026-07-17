//! F-68 — The provenance tree and the byte reader that builds it.
//!
//! Every parsed field carries the exact document byte range it came from
//! (`Node::span`), so the GUI tree (F-72) and format-guided patching (F-85) can
//! map any node back to the bytes on disk. `Cursor` is a small endian-aware
//! reader over an in-memory slice that knows the document offset of its first
//! byte, so each read yields the span it consumed for free.

use std::ops::Range;

use crate::error::{Error, ErrorKind, Result};
use crate::inspector::Endian;

/// A node in the structure tree (F-68). A *group* carries children and an empty
/// `value`; a *leaf* carries a rendered `value` and no children. `span` is in
/// document coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub name: String,
    pub value: String,
    pub span: Range<u64>,
    pub children: Vec<Node>,
}

impl Node {
    pub fn leaf(name: impl Into<String>, value: impl Into<String>, span: Range<u64>) -> Node {
        Node { name: name.into(), value: value.into(), span, children: Vec::new() }
    }

    pub fn group(name: impl Into<String>, span: Range<u64>, children: Vec<Node>) -> Node {
        Node { name: name.into(), value: String::new(), span, children }
    }

    /// Depth-first search for the first descendant (or self) named `name`.
    /// Test/CLI convenience — the GUI walks the tree directly.
    pub fn find(&self, name: &str) -> Option<&Node> {
        if self.name == name {
            return Some(self);
        }
        self.children.iter().find_map(|c| c.find(name))
    }
}

fn truncated(at: u64) -> Error {
    Error::new(ErrorKind::OutOfBounds, format!("structure truncated at offset {at:#x}"))
}

/// Endian-aware reader over a byte slice that knows the document offset of its
/// first byte (`base`). Reads advance `pos` and never panic: running past the
/// end returns `OutOfBounds` (a truncated structure is not a valid structure).
pub struct Cursor<'a> {
    data: &'a [u8],
    base: u64,
    pos: usize,
    endian: Endian,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8], base: u64, endian: Endian) -> Self {
        Cursor { data, base, pos: 0, endian }
    }

    pub fn endian(&self) -> Endian {
        self.endian
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Document offset of the current position.
    pub fn abs(&self) -> u64 {
        self.base + self.pos as u64
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn seek(&mut self, pos: usize) -> Result<()> {
        if pos > self.data.len() {
            return Err(truncated(self.base + pos as u64));
        }
        self.pos = pos;
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(|| truncated(self.abs()))?;
        if end > self.data.len() {
            return Err(truncated(self.base + end as u64));
        }
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.take(n).map(|_| ())
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        self.take(n)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        let a = [b[0], b[1]];
        Ok(match self.endian {
            Endian::Little => u16::from_le_bytes(a),
            Endian::Big => u16::from_be_bytes(a),
        })
    }

    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        let a = [b[0], b[1], b[2], b[3]];
        Ok(match self.endian {
            Endian::Little => u32::from_le_bytes(a),
            Endian::Big => u32::from_be_bytes(a),
        })
    }

    pub fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        let a = [b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]];
        Ok(match self.endian {
            Endian::Little => u64::from_le_bytes(a),
            Endian::Big => u64::from_be_bytes(a),
        })
    }

    /// Reads a `u16` and returns it with the span it consumed.
    pub fn take_u16(&mut self) -> Result<(u16, Range<u64>)> {
        let s = self.abs();
        let v = self.u16()?;
        Ok((v, s..self.abs()))
    }

    pub fn take_u32(&mut self) -> Result<(u32, Range<u64>)> {
        let s = self.abs();
        let v = self.u32()?;
        Ok((v, s..self.abs()))
    }

    pub fn take_u64(&mut self) -> Result<(u64, Range<u64>)> {
        let s = self.abs();
        let v = self.u64()?;
        Ok((v, s..self.abs()))
    }

    pub fn take_bytes(&mut self, n: usize) -> Result<(&'a [u8], Range<u64>)> {
        let s = self.abs();
        let b = self.take(n)?;
        Ok((b, s..self.abs()))
    }
}
