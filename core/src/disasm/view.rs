//! F-77 — Disassembly view: linear sweep and recursive descent, with xrefs.
//!
//! Decoder-agnostic (drives [`decode_one`]). A [`DisasmJob`] holds the code in
//! memory (loaded VA-indexed) and a worklist; `step` decodes a budget of
//! instructions per call so a GUI stays responsive, while `run` drains it for
//! the CLI. Recursive descent seeds from the entry point and function symbols
//! and follows direct branches; linear sweep decodes every byte in range.

use std::collections::{BTreeMap, BTreeSet};

use crate::document::Document;
use crate::error::{Error, ErrorKind, Result};
use crate::format::{BinaryInfo, SymKind};
use crate::search::StepResult;

use super::{DisArch, Flow, Insn, decode_one};

/// How the walk chooses successors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisasmMode {
    /// Decode every byte in range, ignoring control flow.
    Linear,
    /// Follow calls/branches from the seeds; decode only reachable code.
    Recursive,
}

/// A loaded span of code: `bytes` mapped at virtual address `vaddr`.
#[derive(Debug, Clone)]
pub struct Region {
    pub vaddr: u64,
    pub bytes: Vec<u8>,
}

/// The result of a disassembly: instructions sorted by address, plus the
/// cross-references (`target → sources`) discovered along the way.
#[derive(Debug, Clone)]
pub struct Listing {
    pub insns: Vec<Insn>,
    pub xrefs: BTreeMap<u64, Vec<u64>>,
}

/// A cooperative disassembly job over in-memory code regions.
pub struct DisasmJob {
    arch: DisArch,
    regions: Vec<Region>,
    mode: DisasmMode,
    pending: Vec<u64>,
    visited: BTreeSet<u64>,
    insns: BTreeMap<u64, Insn>,
    xrefs: BTreeMap<u64, Vec<u64>>,
}

impl DisasmJob {
    pub fn new(arch: DisArch, regions: Vec<Region>, mode: DisasmMode, seeds: Vec<u64>) -> Self {
        let mut job = DisasmJob {
            arch,
            regions,
            mode,
            pending: Vec::new(),
            visited: BTreeSet::new(),
            insns: BTreeMap::new(),
            xrefs: BTreeMap::new(),
        };
        for s in seeds {
            job.push_if(s);
        }
        // Nothing landed in a region (bad seeds): fall back to region starts.
        if job.pending.is_empty() {
            let starts: Vec<u64> = job.regions.iter().map(|r| r.vaddr).collect();
            for s in starts {
                job.push_if(s);
            }
        }
        job
    }

    /// Decodes up to `budget` instructions. Cheap to call repeatedly.
    pub fn step(&mut self, budget: usize) -> StepResult {
        let mut scanned = 0u64;
        for _ in 0..budget {
            let Some(addr) = self.pending.pop() else {
                return StepResult { finished: true, scanned };
            };
            if !self.visited.insert(addr) {
                continue;
            }
            scanned += 1;
            let Some(bytes) = self.bytes_at(addr) else {
                continue;
            };
            match decode_one(self.arch, bytes, addr) {
                Some(insn) => {
                    let (len, flow, target) = (insn.len as u64, insn.flow, insn.target);
                    if let Some(t) = target {
                        self.xrefs.entry(t).or_default().push(addr);
                    }
                    self.insns.insert(addr, insn);
                    self.enqueue_successors(addr, len, flow, target);
                }
                None => {
                    let bad = Insn::bad(addr, bytes[0]);
                    self.insns.insert(addr, bad);
                    if self.mode == DisasmMode::Linear {
                        self.push_if(addr + 1);
                    }
                }
            }
        }
        StepResult { finished: self.pending.is_empty(), scanned }
    }

    /// Drains the job to completion (CLI).
    pub fn run(mut self) -> Listing {
        while !self.step(4096).finished {}
        self.finish()
    }

    pub fn finish(self) -> Listing {
        Listing { insns: self.insns.into_values().collect(), xrefs: self.xrefs }
    }

    fn enqueue_successors(&mut self, addr: u64, len: u64, flow: Flow, target: Option<u64>) {
        if self.mode == DisasmMode::Linear {
            self.push_if(addr + len);
            return;
        }
        match flow {
            Flow::Return | Flow::Halt => {}
            Flow::Jump => {
                if let Some(t) = target {
                    self.push_if(t);
                }
            }
            Flow::Call | Flow::CondJump => {
                if let Some(t) = target {
                    self.push_if(t);
                }
                self.push_if(addr + len);
            }
            Flow::Normal => self.push_if(addr + len),
        }
    }

    fn push_if(&mut self, va: u64) {
        if !self.visited.contains(&va) && self.region_of(va).is_some() {
            self.pending.push(va);
        }
    }

    fn region_of(&self, va: u64) -> Option<&Region> {
        self.regions.iter().find(|r| va >= r.vaddr && va < r.vaddr + r.bytes.len() as u64)
    }

    fn bytes_at(&self, va: u64) -> Option<&[u8]> {
        let r = self.region_of(va)?;
        Some(&r.bytes[(va - r.vaddr) as usize..])
    }
}

/// What to disassemble and how.
#[derive(Debug, Clone)]
pub struct DisasmOptions {
    pub mode: DisasmMode,
    /// A specific section by name, or `None` for every executable section.
    pub section: Option<String>,
    /// Extra recursive seeds / linear start addresses (`--from`).
    pub extra_seeds: Vec<u64>,
    /// Maximum bytes loaded per region.
    pub cap: u64,
}

/// Builds a job from a document: resolves the sections, loads their bytes (VA
/// mapped through the section table) and seeds the walk.
pub fn build(doc: &mut Document, info: &BinaryInfo, opts: &DisasmOptions) -> Result<DisasmJob> {
    let arch = DisArch::from_format(info.arch, info.bits).ok_or_else(|| {
        Error::new(ErrorKind::Io, format!("no disassembler for {}", info.arch.name()))
    })?;

    let selected: Vec<_> = match &opts.section {
        Some(name) => info.sections.iter().filter(|s| &s.name == name).collect(),
        None => info.sections.iter().filter(|s| s.perms.x && !s.file.is_empty()).collect(),
    };
    if selected.is_empty() {
        return Err(Error::new(ErrorKind::Io, "no executable section to disassemble"));
    }

    let mut regions = Vec::new();
    for s in &selected {
        if s.file.is_empty() {
            continue;
        }
        let len = (s.file.end - s.file.start).min(opts.cap) as usize;
        let r = doc.read(s.file.start, len);
        if r.is_clean() && !r.data.is_empty() {
            regions.push(Region { vaddr: s.vaddr, bytes: r.data });
        }
    }
    if regions.is_empty() {
        return Err(Error::new(ErrorKind::BadBlock, "executable section(s) unreadable"));
    }

    let seeds = seeds_for(info, opts, &regions);
    Ok(DisasmJob::new(arch, regions, opts.mode, seeds))
}

fn seeds_for(info: &BinaryInfo, opts: &DisasmOptions, regions: &[Region]) -> Vec<u64> {
    let mut seeds = Vec::new();
    match opts.mode {
        DisasmMode::Linear => {
            if opts.extra_seeds.is_empty() {
                seeds.extend(regions.iter().map(|r| r.vaddr));
            } else {
                seeds.extend(opts.extra_seeds.iter().copied());
            }
        }
        DisasmMode::Recursive => {
            if info.entry != 0 {
                seeds.push(info.entry);
            }
            for sym in &info.symbols {
                if sym.defined && sym.kind == SymKind::Func && sym.value != 0 {
                    seeds.push(sym.value);
                }
            }
            seeds.extend(opts.extra_seeds.iter().copied());
        }
    }
    seeds
}
