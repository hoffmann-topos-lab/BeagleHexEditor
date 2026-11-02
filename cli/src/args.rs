//! Hand-rolled argument parsing, shared by every subcommand.

use hexed_core::{Charset, hex};

/// A command's `--flag [value]` pairs; boolean flags have value "".
#[derive(Debug, Default)]
pub(crate) struct Flags(Vec<(String, String)>);

impl Flags {
    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.0.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }

    /// A boolean flag (or any flag) is present.
    pub(crate) fn has(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// `--name <number>` (0x-hex or decimal); `None` when absent.
    pub(crate) fn u64(&self, name: &str) -> Result<Option<u64>, String> {
        self.get(name).map(parse_u64).transpose()
    }

    pub(crate) fn u64_or(&self, name: &str, default: u64) -> Result<u64, String> {
        Ok(self.u64(name)?.unwrap_or(default))
    }

    /// Counts and limits.
    pub(crate) fn usize_or(&self, name: &str, default: usize) -> Result<usize, String> {
        Ok(self.u64(name)?.map_or(default, |n| n as usize))
    }

    /// `--name <value>` resolved by `lookup` (an enum's `from_name`); `None`
    /// when absent, an "unknown <what>" error when not recognized.
    pub(crate) fn named<T>(
        &self,
        name: &str,
        what: &str,
        lookup: impl Fn(&str) -> Option<T>,
    ) -> Result<Option<T>, String> {
        self.get(name).map(|v| lookup(v).ok_or(format!("unknown {what}: {v}"))).transpose()
    }

    /// `--name a,b,c`, each item resolved by `lookup`; `None` when absent.
    pub(crate) fn list<T>(
        &self,
        name: &str,
        what: &str,
        lookup: impl Fn(&str) -> Option<T>,
    ) -> Result<Option<Vec<T>>, String> {
        self.get(name)
            .map(|list| {
                list.split(',').map(|v| lookup(v).ok_or(format!("unknown {what}: {v}"))).collect()
            })
            .transpose()
    }

    /// `-o`/`--out`.
    pub(crate) fn out(&self) -> Option<&str> {
        self.get("o").or_else(|| self.get("out"))
    }

    /// `-o`/`--out` for the commands that never overwrite their input.
    pub(crate) fn required_out(&self) -> Result<&str, String> {
        self.out().ok_or("missing -o <output>. This command never overwrites its input.".into())
    }

    /// `--charset <name>`, ASCII by default.
    pub(crate) fn charset(&self) -> Result<Charset, String> {
        Ok(self.named("charset", "charset", Charset::from_name)?.unwrap_or(Charset::Ascii))
    }

    /// The restricted range (F-15): `--start`/`--end`, else the document.
    pub(crate) fn range(&self, doc_len: u64) -> Result<std::ops::Range<u64>, String> {
        let start = self.u64_or("start", 0)?;
        let end = self.u64_or("end", doc_len)?;
        if start > end {
            return Err(format!("inverted range: {start:#x} > {end:#x}"));
        }
        Ok(start..end.min(doc_len))
    }
}

/// Separates `--flag [value]` from the positional arguments. `boolean` lists
/// the flags that carry no value.
pub(crate) fn split_flags(args: &[String], boolean: &[&str]) -> Result<(Vec<String>, Flags), String> {
    let mut positional = Vec::new();
    let mut flags = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(name) = a.strip_prefix("--").or_else(|| a.strip_prefix('-')) {
            if boolean.contains(&name) {
                flags.push((name.to_string(), String::new()));
            } else {
                i += 1;
                let value = args.get(i).ok_or(format!("--{name} requires a value"))?;
                flags.push((name.to_string(), value.clone()));
            }
        } else {
            positional.push(a.clone());
        }
        i += 1;
    }
    Ok((positional, Flags(flags)))
}

/// Sizes accept a k/m/g suffix (binary: 512k = 512 × 1024).
pub(crate) fn parse_size(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let (num, shift) = match t.chars().last().map(|c| c.to_ascii_lowercase()) {
        Some('k') => (&t[..t.len() - 1], 10u32),
        Some('m') => (&t[..t.len() - 1], 20),
        Some('g') => (&t[..t.len() - 1], 30),
        _ => (t, 0),
    };
    let v = parse_u64(num)?;
    if v != 0 && v.leading_zeros() < shift {
        return Err(format!("size overflows 64 bits: {s}"));
    }
    Ok(v << shift)
}

pub(crate) fn parse_u64(s: &str) -> Result<u64, String> {
    hex::parse_u64(s).ok_or_else(|| format!("invalid number: {}", s.trim()))
}

pub(crate) fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    hex::parse_bytes(s).ok_or_else(|| format!("invalid hex sequence (odd digit count or non-hex digit): {s}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_u64_accepts_decimal_and_hex() {
        assert_eq!(parse_u64("4096").unwrap(), 4096);
        assert_eq!(parse_u64("0x1000").unwrap(), 4096);
        assert_eq!(parse_u64("0X1000").unwrap(), 4096);
        assert!(parse_u64("nope").is_err());
    }

    #[test]
    fn parse_size_accepts_binary_suffixes() {
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert_eq!(parse_size("512k").unwrap(), 512 << 10);
        assert_eq!(parse_size("16M").unwrap(), 16 << 20);
        assert_eq!(parse_size("2g").unwrap(), 2 << 30);
        assert_eq!(parse_size("0x10k").unwrap(), 16 << 10);
        assert!(parse_size("999999999999g").is_err(), "overflow detected");
        assert!(parse_size("abc").is_err());
    }

    #[test]
    fn parse_hex_accepts_spaces() {
        assert_eq!(parse_hex("DEADBEEF").unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(parse_hex("DE AD BE EF").unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(parse_hex("ABC").is_err());
        assert!(parse_hex("ZZ").is_err());
    }

    #[test]
    fn split_flags_separates_positionals_from_flags() {
        let args: Vec<String> =
            ["a.bin", "--charset", "cp437", "0x10", "--random", "-o", "out.bin"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        let (pos, flags) = split_flags(&args, &["random"]).unwrap();
        assert_eq!(pos, vec!["a.bin", "0x10"]);
        assert_eq!(flags.get("charset"), Some("cp437"));
        assert!(flags.has("random"));
        assert_eq!(flags.out(), Some("out.bin"));
        assert_eq!(flags.get("seed"), None);
    }

    #[test]
    fn split_flags_requires_a_value_for_a_non_boolean_flag() {
        let args: Vec<String> = ["x", "--charset"].iter().map(|s| s.to_string()).collect();
        assert!(split_flags(&args, &[]).is_err());
    }

    #[test]
    fn typed_flag_accessors() {
        let args: Vec<String> = ["--limit", "0x10", "--algos", "md5,sha256", "--start", "9", "--end", "4"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (_, flags) = split_flags(&args, &[]).unwrap();
        assert_eq!(flags.usize_or("limit", 7).unwrap(), 16);
        assert_eq!(flags.usize_or("min", 7).unwrap(), 7);
        let pick = |v: &str| ["md5", "sha256"].contains(&v).then(|| v.to_string());
        assert_eq!(flags.list("algos", "algorithm", pick).unwrap().unwrap(), ["md5", "sha256"]);
        assert!(flags.list("algos", "algorithm", |_| None::<u8>).is_err());
        assert!(flags.range(100).is_err(), "inverted range");
        assert!(flags.required_out().is_err());
    }
}
