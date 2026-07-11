//! Hex editor core.
//!
//! No UI dependencies. Project rule: if a feature cannot be exercised through
//! the `cli`, it is in the wrong place.
//!
//! Map of the decisions (`F-xx` are feature IDs, `Dx` architectural decisions,
//! both from the project spec):
//!
//! - **F-01 / D7** `piece_table`, `add_buffer` — the document is never
//!   materialized; inserting at offset 0 of a 200 GB file is O(1).
//! - **F-02 / D3** `source` — file, disk and memory behind a single trait,
//!   designed as if the source could be remote and fallible.
//! - **F-03** `document` — transactions and undo/redo over the piece table.
//! - **F-04 / D6** `cache` — LRU blocks over `pread`, never `mmap`.
//! - **F-06** `error` — failure per block, not per file.
//! - **F-16/F-17** `inspector` — bidirectional Data Inspector, with endianness.
//! - **F-19** `display` — offset display base.
//! - **F-20** `charset` — character sets for the text pane.
//! - **F-22** `document::fill` — filling a selection.
//! - **F-23** `bookmarks` — bookmarks persisted to a sidecar file.
//! - **F-07** `progress` — progress and cancellation of long operations.
//! - **F-13/F-14/F-15/F-28** `search` — incremental search and replace.
//! - **F-30/F-31** `export` — copy-as / report in textual formats.
//! - **F-27/F-27a** `hexfile` — Intel HEX and S-record, import and export.
//! - **F-57/F-58** `transform` — split into parts and concatenate files.

pub mod add_buffer;
pub mod bookmarks;
pub mod cache;
pub mod charset;
pub mod compare;
pub mod disks;
pub mod display;
pub mod document;
pub mod error;
pub mod export;
pub mod hash;
pub mod hexfile;
pub mod inspector;
pub mod magic;
pub mod piece_table;
pub mod progress;
mod rng;
pub mod search;
pub mod shred;
pub mod source;
pub mod stats;
pub mod strings;
pub mod transform;

pub use bookmarks::{Bookmark, Bookmarks};
pub use charset::Charset;
pub use disks::DiskInfo;
pub use display::OffsetBase;
pub use document::{Document, FillPattern, ReadResult, backup_file};
pub use error::{Error, ErrorKind, Result};
pub use export::{ExportFormat, ExportJob, ExportOptions};
pub use hexfile::RecordFormat;
pub use inspector::{Endian, FieldKind};
pub use piece_table::{Piece, PieceTable, StoreId};
pub use progress::Progress;
pub use search::{Pattern, Searcher, StepResult, find_all, find_next, replace_all};
pub use shred::shred_file;
pub use source::{Capabilities, DataSource, DiskSource, FileSource, HelperSource, MemSource};

/// Default Unix socket the privileged helper listens on (F-47).
pub use hexed_helper_proto::DEFAULT_SOCKET as DEFAULT_HELPER_SOCKET;
