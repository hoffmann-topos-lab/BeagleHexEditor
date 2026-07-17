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
//! - **F-68/F-69** `format` — executable format model (ELF/PE/Mach-O) with a
//!   provenance tree; ELF is parsed, PE/Mach-O detected (Fase 9, em progresso).
//! - **F-79/F-80** `recipe` — CyberChef-style transformations composed into a
//!   pipeline over a selection (Fase 12).
//! - **F-81** `funcdiff` — function-aware binary diff (Fase 13): match by symbol
//!   then by normalized-instruction fingerprint.
//! - **F-84** `dump` — memory-image inspector (Fase 15): ELF core parsing;
//!   detection of raw / Mach-O core / Windows crashdump / hiberfil.
//! - **F-82** `trace` — dynamic syscall tracer (Fase 14), **Linux only** (D5);
//!   macOS reports that plainly instead of failing silently.

pub mod add_buffer;
pub mod bookmarks;
pub mod cache;
pub mod charset;
pub mod compare;
pub mod disasm;
pub mod disks;
pub mod dump;
pub mod display;
pub mod document;
pub mod error;
pub mod export;
pub mod format;
pub mod funcdiff;
pub mod hash;
pub mod hexfile;
pub mod identify;
pub mod inspector;
pub mod magic;
pub mod patch;
pub mod piece_table;
pub mod progress;
pub mod recipe;
mod rng;
pub mod search;
pub mod shred;
pub mod source;
pub mod stats;
pub mod strings;
pub mod trace;
pub mod transform;

pub use bookmarks::{Bookmark, Bookmarks};
pub use charset::Charset;
pub use disasm::{
    DisArch, DisasmJob, DisasmMode, DisasmOptions, Flow, Insn, Listing, StackString,
};
pub use disks::DiskInfo;
pub use display::OffsetBase;
pub use dump::{DumpKind, DumpReport, MemRegion, Module, ProcInfo};
pub use document::{Document, FillPattern, ReadResult, backup_file};
pub use error::{Error, ErrorKind, Result};
pub use export::{ExportFormat, ExportJob, ExportOptions};
pub use format::{Arch, BinaryInfo, Bits, ExtraEntry, Format, Import, Reloc, Section, Symbol};
pub use funcdiff::{FuncChange, FuncDiffReport, FuncRef, Renamed};
pub use hexfile::RecordFormat;
pub use identify::{
    Detection, IdKind, IdentifyReport, Indicator, PackReport, SectionEntropy, Severity,
};
pub use inspector::{Endian, FieldKind};
pub use patch::{PeChecksum, pe_checksum};
pub use piece_table::{Piece, PieceTable, StoreId};
pub use progress::Progress;
pub use recipe::{AesMode, Base64Variant, Base85Variant, Op, Recipe, RecipeJob};
pub use search::{Pattern, Searcher, StepResult, find_all, find_next, replace_all};
pub use shred::shred_file;
pub use source::{Capabilities, DataSource, DiskSource, FileSource, HelperSource, MemSource};

/// Default Unix socket the privileged helper listens on (F-47).
pub use hexed_helper_proto::DEFAULT_SOCKET as DEFAULT_HELPER_SOCKET;
