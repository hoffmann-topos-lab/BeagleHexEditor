//! Hand-rolled argument parsing, shared by every subcommand.

use hexed_core::Charset;

/// (name, value) pairs of a command's flags; boolean flags have value "".
pub(crate) type Flags = Vec<(String, String)>;

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
    Ok((positional, flags))
}

pub(crate) fn flag<'a>(flags: &'a [(String, String)], name: &str) -> Option<&'a str> {
    flags.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
}

pub(crate) fn parse_charset(flags: &[(String, String)]) -> Result<Charset, String> {
    match flag(flags, "charset") {
        Some(name) => Charset::from_name(name).ok_or(format!("unknown charset: {name}")),
        None => Ok(Charset::Ascii),
    }
}

/// The search's restricted range (F-15): `--start`/`--end`, else the document.
pub(crate) fn search_range(flags: &Flags, doc_len: u64) -> Result<std::ops::Range<u64>, String> {
    let start = match flag(flags, "start") {
        Some(s) => parse_u64(s)?,
        None => 0,
    };
    let end = match flag(flags, "end") {
        Some(s) => parse_u64(s)?,
        None => doc_len,
    };
    if start > end {
        return Err(format!("inverted range: {start:#x} > {end:#x}"));
    }
    Ok(start..end.min(doc_len))
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
    let s = s.trim();
    let r = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => s.parse::<u64>(),
    };
    r.map_err(|_| format!("invalid number: {s}"))
}

pub(crate) fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !clean.len().is_multiple_of(2) {
        return Err(format!("hex sequence with an odd number of digits: {s}"));
    }
    clean
        .as_bytes()
        .chunks(2)
        .map(|p| {
            let pair = std::str::from_utf8(p).unwrap();
            u8::from_str_radix(pair, 16).map_err(|_| format!("invalid hex byte: {pair}"))
        })
        .collect()
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
        assert_eq!(flag(&flags, "charset"), Some("cp437"));
        assert_eq!(flag(&flags, "random"), Some(""));
        assert_eq!(flag(&flags, "o"), Some("out.bin"));
        assert_eq!(flag(&flags, "seed"), None);
    }

    #[test]
    fn split_flags_requires_a_value_for_a_non_boolean_flag() {
        let args: Vec<String> = ["x", "--charset"].iter().map(|s| s.to_string()).collect();
        assert!(split_flags(&args, &[]).is_err());
    }
}
