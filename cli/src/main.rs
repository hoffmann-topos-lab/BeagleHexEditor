//! F-08 — Headless CLI.
//!
//! Not an extra: it is what lets the core be exercised in CI without simulating
//! clicks. No dependencies beyond `core` — argument parsing by hand (`args`),
//! to keep the dependency tree empty while it still fits in one's head. The
//! subcommands live in `commands`, grouped by area.

mod args;
mod commands;

use std::process::ExitCode;

use hexed_core::hexfile::RecordFormat;

use commands::{analyze, detect, device, disasm, edit, format, io, recipe, search, trace, view};

const USAGE: &str = "\
hexed — hex editor (headless frontend)

USAGE:
    hexed len <file>
    hexed dump <file> [offset] [length] [--charset <name>] [--base hex|dec|oct]
    hexed patch <input> <offset> <hex> -o <output>
    hexed poke <file> <offset> <hex> --yes           (in-place overwrite; F-05/F-51)
    hexed inspect <file> [offset] [--be] [--charset <name>]
    hexed fill <input> <offset> <length> <hex> -o <output>
    hexed fill <input> <offset> <length> --random [--seed <n>] -o <output>
    hexed find <file> <hex-with-??> [search options]
    hexed find <file> --text <s> [--charset <name>] [--ci] [search options]
    hexed find <file> --typed <i32=1234|f32~3.14> [--be] [--tol <x>] [options]
    hexed replace <input> <hex> <new-hex> -o <output> [--all] [options]
    hexed replace <input> --text <s> --with <new-s> -o <output> [--all] [options]
    hexed hash <file> [--algos md5,sha256,crc32,…|--all] [--start/--end]
    hexed strings <file> [--min <n>] [--enc utf8,utf16le,utf16be] [--limit <n>]
    hexed strings <file> --stack [--min <n>]         (recover stack strings F-78)
    hexed stats <file> [--full] [--block <n>] [--start/--end]
    hexed magic <file> [--scan] [--limit <n>]
    hexed diff <a> <b> [--limit <n>]
    hexed bindiff <a> <b> [--all] [--limit <n>]      (function-aware diff; F-81)
    hexed memscan <file> [--limit <n>]               (inspect a memory dump; F-84)
    hexed trace [--] <program> [args…]               (syscall tracer; F-82, Linux only)
    hexed elf <file> [views]                         (ELF: readelf/nm)
    hexed pe <file> [views]                          (PE: dumpbin/PE-bear)
    hexed pe <file> --checksum [-o <fixed>]          (recompute PE checksum; F-85)
    hexed macho <file> [views]                       (Mach-O: otool)
    hexed struct <file>                              (auto-detect: field tree)
    hexed detect <file> [--entropy] [--indicators] [--all]
                                     (identify toolchain/packer; packing; IOCs)
    hexed disasm <file> [--section <name>] [--linear] [--from <addr>] [--limit <n>]
                                     (disassemble x86/x64/ARM64; recursive default)
    hexed recipe <file> \"<step> | <step> | …\" [--start/--end] [--cap <size>] [-o <out>]
                                     (CyberChef-style transform pipeline; F-79/F-80)
    hexed bookmarks <file>
    hexed bookmarks <file> add <offset> <length> <name> [description]
    hexed bookmarks <file> rm <index>
    hexed export <file> [--format <fmt>] [--cols <n>] [--name <var>]
                 [--charset <name>] [--base hex|dec|oct] [--offset-start <off>]
                 [--start/--end] [-o <output>]       (default: stdout)
    hexed ihex import <input.hex> -o <output.bin> [--fill <byte>]
    hexed ihex export <input.bin> -o <output.hex> [--addr <base>] [--width <n>]
    hexed srec import <input.srec> -o <output.bin> [--fill <byte>]
    hexed srec export <input.bin> -o <output.srec> [--addr <base>] [--width <n>]
    hexed split <file> <size> -o <prefix>            (writes prefix.000, .001…)
    hexed concat <input>… -o <output>
    hexed disks                                      (list disks and partitions)
    hexed shred <file> [--passes <n>] [--keep] --yes  (overwrite, then delete)

Any <file> argument may be a raw device under /dev/ (e.g. /dev/rdisk2, /dev/sda);
it opens read-only and by sector. Raw device access needs privilege — run with
sudo, or install the privileged helper.

SEARCH OPTIONS: --from <off> (default 0), --back, --all, --limit <n>,
    --start <off> and --end <off> restrict the range (F-15).
OFFSETS accept decimal (4096) or hexadecimal (0x1000).
SIZES also accept the suffixes k, m and g: 512k, 16m, 2g.
HEX is a byte sequence; ?? and ? nibbles are wildcards: \"DE ?? BE EF\", \"D?\".
CHARSETS: ascii, cp1252, cp437, ebcdic, macroman, utf8, utf16le, utf16be.
ALGOS: md5, sha1, sha256, sha512, blake3, crc16, crc32, crc64, adler32, sum, xor8.
EXPORT FORMATS: hex (default), c, java, csharp, pascal, python — byte literals;
    txt, html, rtf, tex — a report with offset + hex + text (F-31).
FORMAT VIEWS (elf/pe/macho): default is summary + sections + libraries; add
    --symbols, --imports, --relocs, --tree, or --all.
RECIPE STEPS (recipe, `|`-separated, applied left to right):
    to-base64[url]/from-base64[url], to-base32/from-base32, to-base85/from-base85,
    to-z85/from-z85, to-hex/from-hex, to-url/from-url;
    xor <hex>, add/sub <n>, rol/ror <n>, not, reverse;
    deflate/inflate, zlib/unzlib, gzip/gunzip;
    aes-enc/aes-dec <cbc|ctr|ecb> <hexkey> [hexiv], rc4 <hexkey>;
    md5, sha1, sha256, sha512, blake3, crc32, … (emit the hex digest as text).

EXAMPLES:
    hexed find firmware.bin \"DE AD BE EF\" --all
    hexed find savegame.bin --typed i32=9999
    hexed replace config.bin --text v1.0 --with v2.0 --ci --all -o new.bin
    hexed hash evidence.dd --algos sha256,blake3
    hexed magic image.dd --scan
    hexed export payload.bin --format c --name payload -o payload.c
    hexed ihex export firmware.bin --addr 0x8000 -o firmware.hex
    hexed split image.dd 512m -o image.dd.part
    hexed concat image.dd.part.000 image.dd.part.001 -o image.dd
    hexed recipe payload.bin \"from-base64 | gunzip\" -o payload.out
    hexed recipe firmware.bin \"xor 3a | sha256\"
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("hexed: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let Some(cmd) = args.first() else {
        print!("{USAGE}");
        return Ok(());
    };

    match cmd.as_str() {
        "len" => view::cmd_len(&args[1..]),
        "dump" => view::cmd_dump(&args[1..]),
        "patch" => edit::cmd_patch(&args[1..]),
        "poke" => edit::cmd_poke(&args[1..]),
        "inspect" => view::cmd_inspect(&args[1..]),
        "fill" => edit::cmd_fill(&args[1..]),
        "find" => search::cmd_find(&args[1..]),
        "replace" => search::cmd_replace(&args[1..]),
        "hash" => analyze::cmd_hash(&args[1..]),
        "strings" => analyze::cmd_strings(&args[1..]),
        "stats" => analyze::cmd_stats(&args[1..]),
        "magic" => analyze::cmd_magic(&args[1..]),
        "diff" => analyze::cmd_diff(&args[1..]),
        "bindiff" => analyze::cmd_bindiff(&args[1..]),
        "memscan" => analyze::cmd_memscan(&args[1..]),
        "trace" => trace::cmd_trace(&args[1..]),
        "elf" => format::cmd_elf(&args[1..]),
        "pe" => format::cmd_pe(&args[1..]),
        "macho" => format::cmd_macho(&args[1..]),
        "struct" => format::cmd_struct(&args[1..]),
        "detect" => detect::cmd_detect(&args[1..]),
        "disasm" => disasm::cmd_disasm(&args[1..]),
        "recipe" => recipe::cmd_recipe(&args[1..]),
        "bookmarks" => edit::cmd_bookmarks(&args[1..]),
        "export" => io::cmd_export(&args[1..]),
        "ihex" => io::cmd_records(RecordFormat::IntelHex, &args[1..]),
        "srec" => io::cmd_records(RecordFormat::Srec, &args[1..]),
        "split" => io::cmd_split(&args[1..]),
        "concat" => io::cmd_concat(&args[1..]),
        "disks" => device::cmd_disks(&args[1..]),
        "shred" => device::cmd_shred(&args[1..]),
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command: {other}\n\n{USAGE}")),
    }
}
