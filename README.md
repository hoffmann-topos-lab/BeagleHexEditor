# hexed

A hex editor for macOS and Linux, written in Rust, aiming for feature parity
with [HxD](https://mh-nexus.de/en/hxd/). It edits files of any size — a 100 GB
image opens instantly and inserting a byte at offset 0 is O(1) — through a
piece-table document model that never loads the file into memory.

The project is a Cargo workspace split into a UI-free core, a headless CLI, and
an egui-based GUI:

| Crate                | Binary      | Role                                                     |
| -------------------- | ----------- | ------------------------------------------------------- |
| `hexed-core`         | –           | All logic: piece table, data sources, search, analysis, I/O. No UI dependencies. |
| `hexed-cli`          | `hexed`     | Headless frontend. Dependency-free argument parsing; exists so the core is testable in CI. |
| `hexed-gui`          | `hexed-gui` | Graphical interface (egui). A thin layer over the core. |
| `hexed-helper`       | `hexhelper` | Privileged daemon for raw `/dev/` I/O. Minimal and auditable; runs as root behind a Unix socket. |
| `hexed-helper-proto` | –           | Zero-dependency wire protocol shared by the helper and its client. |

**Project rule:** every feature must be exercisable through the CLI. If it
cannot be, it is in the wrong place.

## Features

- **Any file size.** A piece table (with an append-only add buffer that spills
  to a temp file past 256 MB) means the original file is never mutated and no
  edit scales with file size — only with the number of edits.
- **Editing.** Insert, delete, overwrite; unlimited undo/redo where undo splices
  removed *pieces* back rather than copying bytes. Overwrite is a single Ctrl+Z.
- **Robust I/O.** Reads use `pread`, never `mmap` (no `SIGBUS` on truncation). A
  bad sector never fails the whole read — unreadable ranges render as `??` and
  saving refuses to write zeros over data that merely could not be read. Saves
  are atomic (temp file + `rename`).
- **Presentation & inspection.** Data Inspector (27 field types, bidirectional
  decode/encode, endianness per field), character sets (ASCII, CP1252, CP437,
  EBCDIC, Mac Roman, UTF-8, UTF-16 LE/BE), configurable columns/grouping/offset
  base, selection fill, and bookmarks persisted to a sidecar file.
- **Search & replace.** Hex with nibble wildcards (`DE ?? BE EF`), text per
  charset, typed values (`i32=1234`, `f32~3.14` with tolerance), case-insensitive
  search, find-all, and atomic replace-all (one undo for the whole operation).
  Search is cooperative and cancellable, so searching 100 GB never freezes the UI.
- **Analysis.** Cryptographic hashes and checksums (MD5, SHA-1/256/512, BLAKE3,
  CRC-16/32/64, Adler-32, …), string extraction (UTF-8 and UTF-16 LE/BE),
  histogram and per-block Shannon entropy, byte-by-byte tab comparison, and file
  signature identification / carving.
- **Import & export.** Copy-as and reports (C, Java, C#, Pascal, Python byte
  literals; TXT/HTML/RTF/TeX dumps), Intel HEX and Motorola S-record (import and
  export, every checksum validated), and file split/concatenate.
- **Raw disks.** Enumerate disks and partitions (`hexed disks`), and open any
  `/dev/` node read-only and by sector — sector-aligned access is handled
  transparently. Raw access needs privilege: it works directly under `sudo`, or
  through a small, auditable privileged helper (`hexhelper`) installed once with
  `helper/install-helper.sh` (LaunchDaemon on macOS, systemd on Linux; no Apple
  Developer account required). Disk images (`.img`/`.dd`/`.iso`) are just files
  and open normally. Process-memory editing is planned for a later version.
- **GUI conveniences.** Persistent preferences (view defaults, theme, options) in
  a human-readable config file, light/dark/system theme, recent files and session
  restore, configurable keyboard shortcuts, and an optional `.bak` backup before
  overwriting on save.
- **Shredder.** Overwrite a file's bytes and delete it (`hexed shred <file> --yes`,
  or Tools → Shred file… in the GUI) — with an explicit warning that this does not
  guarantee destruction on SSDs, copy-on-write, or journaled filesystems.

## Building & running

The toolchain is pinned by `rust-toolchain.toml` (Rust 1.96.1, edition 2024); a
fresh clone downloads it automatically.

```sh
# GUI
cargo run -p hexed-gui [file]

# CLI
cargo run -p hexed -- <subcommand> …

# Tests, lints, release build
cargo test --workspace
cargo clippy --workspace --all-targets   # zero-warnings policy
cargo build --release
```

### Clickable app (icon in the Dock / application menu)

The GUI already shows its icon in the window/title bar. To install it as a
double-clickable application with a Dock / launcher icon:

```sh
# macOS — builds "Beagle Hex Editor.app" (ad-hoc signed; no Apple Developer account)
packaging/macos/bundle.sh          # then drag the .app into /Applications

# Linux — installs the binary, hicolor icons and a .desktop entry
packaging/linux/install.sh                        # into ~/.local
PREFIX=/usr/local sudo packaging/linux/install.sh # system-wide
```

The icon assets are generated from `logo.png` by `packaging/gen-icons.py`
(Pillow); the derived files are committed, so building the app needs neither
Pillow nor `iconutil`. See `packaging/README.md`.

## CLI usage

```sh
hexed dump <file> [offset] [len] [--charset <name>] [--base hex|dec|oct]
hexed inspect <file> [offset] [--be] [--charset <name>]
hexed patch <input> <offset> <hex> -o <output>
hexed fill <input> <offset> <len> <hex|--random [--seed n]> -o <output>
hexed find <file> "DE ?? BE EF" [--text s | --typed i32=1234] [--all]
hexed replace <input> <hex> <new-hex> -o <output> [--all]
hexed hash <file> [--algos sha256,crc32 | --all]
hexed strings <file> [--min n] [--enc utf8,utf16le]
hexed stats <file> [--full]          # histogram + entropy
hexed magic <file> [--scan]          # identify / carve signatures
hexed diff <a> <b>                   # exits 1 when files differ
hexed export <file> [--format c|python|html|…] [-o out]
hexed ihex import <in.hex> -o <out.bin> [--fill 0xFF]   # same shape for srec
hexed ihex export <in.bin> -o <out.hex> [--addr 0x8000] [--width 16]
hexed split <file> <size e.g. 512m> -o <prefix>         # prefix.000, .001…
hexed concat <a> <b>… -o <out>
hexed disks                                             # list disks/partitions
hexed shred <file> [--passes n] [--keep] --yes          # overwrite, then delete
```

Any `<file>` may be a raw device under `/dev/` (e.g. `/dev/rdisk2`, `/dev/sda`);
it opens read-only and by sector (`sudo` or the installed helper is needed for
raw access).

Run `hexed --help` for the full reference. Offsets accept decimal (`4096`) or
hex (`0x1000`); sizes also take `k`/`m`/`g` suffixes (`512k`, `16m`, `2g`).

## Testing

The core is validated by property-based differential tests: a naive `Vec<u8>`
oracle and the real `Document` receive the same random sequence of
insert/delete/overwrite/undo/redo operations, and their contents are compared
after every step (`cargo test -p hexed-core --test oracle`). A separate,
`--ignored` test builds a 100 GB sparse file and asserts that opening it and
editing it stay instantaneous:

```sh
cargo test --release --test huge_file -- --ignored --nocapture
```

## License

MIT.
