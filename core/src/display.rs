
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OffsetBase {
    #[default]
    Hex,
    Dec,
    Oct,
}

impl OffsetBase {
    pub const ALL: [OffsetBase; 3] = [OffsetBase::Hex, OffsetBase::Dec, OffsetBase::Oct];

    pub fn name(self) -> &'static str {
        match self {
            OffsetBase::Hex => "hexadecimal",
            OffsetBase::Dec => "decimal",
            OffsetBase::Oct => "octal",
        }
    }

    pub fn from_name(s: &str) -> Option<OffsetBase> {
        Some(match s.to_ascii_lowercase().as_str() {
            "hex" | "hexadecimal" | "16" => OffsetBase::Hex,
            "dec" | "decimal" | "10" => OffsetBase::Dec,
            "oct" | "octal" | "8" => OffsetBase::Oct,
            _ => return None,
        })
    }

    /// Digits needed to display `max` in this base (minimum 8, like the
    /// classic offset column of a hex editor).
    pub fn digits_for(self, max: u64) -> usize {
        let mut digits = 1;
        let radix = match self {
            OffsetBase::Hex => 16,
            OffsetBase::Dec => 10,
            OffsetBase::Oct => 8,
        };
        let mut v = max;
        while v >= radix {
            v /= radix;
            digits += 1;
        }
        digits.max(8)
    }

    pub fn format(self, v: u64, width: usize) -> String {
        match self {
            OffsetBase::Hex => format!("{v:0width$X}"),
            OffsetBase::Dec => format!("{v:0width$}"),
            OffsetBase::Oct => format!("{v:0width$o}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_in_all_three_bases() {
        assert_eq!(OffsetBase::Hex.format(255, 8), "000000FF");
        assert_eq!(OffsetBase::Dec.format(255, 8), "00000255");
        assert_eq!(OffsetBase::Oct.format(255, 8), "00000377");
    }

    #[test]
    fn width_follows_document_size() {
        assert_eq!(OffsetBase::Hex.digits_for(0xFFFF), 8, "never fewer than 8");
        assert_eq!(OffsetBase::Hex.digits_for(u64::MAX), 16);
        assert_eq!(OffsetBase::Dec.digits_for(1_000_000_000), 10);
        assert_eq!(OffsetBase::Oct.digits_for(0o777_7777_7777), 11);
    }

    #[test]
    fn from_name_accepts_aliases() {
        assert_eq!(OffsetBase::from_name("HEX"), Some(OffsetBase::Hex));
        assert_eq!(OffsetBase::from_name("10"), Some(OffsetBase::Dec));
        assert_eq!(OffsetBase::from_name("bin"), None);
    }
}
