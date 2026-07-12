//! F-27/F-27a import — parsers for Intel HEX and Motorola S-record.

use crate::error::{Error, ErrorKind, Result};

use super::{Image, RecordFormat, Segment};

fn parse_err(fmt: RecordFormat, line_no: usize, detail: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Io, format!("{}, line {line_no}: {detail}", fmt.name()))
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
        .collect()
}

/// F-27 — Intel HEX. Supported types: 00 (data), 01 (EOF), 02/04 (extended
/// address), 03/05 (entry address). Reading stops at the EOF record.
pub fn parse_ihex(text: &str) -> Result<Image> {
    let fmt = RecordFormat::IntelHex;
    let mut image = Image::default();
    // Base added to each data record's 16-bit address: record 02 (segment ×16)
    // or 04 (upper 16 bits).
    let mut base: u64 = 0;

    for (i, raw) in text.lines().enumerate() {
        let line_no = i + 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let Some(hex) = line.strip_prefix(':') else {
            return Err(parse_err(fmt, line_no, "record does not start with ':'"));
        };
        let bytes = hex_bytes(hex)
            .ok_or_else(|| parse_err(fmt, line_no, "invalid hexadecimal digits"))?;
        if bytes.len() < 5 {
            return Err(parse_err(fmt, line_no, "record too short"));
        }
        let len = bytes[0] as usize;
        if bytes.len() != len + 5 {
            return Err(parse_err(
                fmt,
                line_no,
                format!("declared length {len} does not match the record"),
            ));
        }
        let sum = bytes.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        if sum != 0 {
            return Err(parse_err(fmt, line_no, "invalid checksum"));
        }
        let addr = u16::from_be_bytes([bytes[1], bytes[2]]) as u64;
        let rec_type = bytes[3];
        let data = &bytes[4..4 + len];
        match rec_type {
            0x00 => image.segments.push(Segment { addr: base + addr, data: data.to_vec() }),
            0x01 => {
                image.normalize()?;
                return Ok(image);
            }
            0x02 | 0x04 => {
                if len != 2 {
                    return Err(parse_err(fmt, line_no, "an address record requires 2 bytes"));
                }
                let v = u16::from_be_bytes([data[0], data[1]]) as u64;
                base = if rec_type == 0x02 { v << 4 } else { v << 16 };
            }
            0x03 | 0x05 => {
                if len != 4 {
                    return Err(parse_err(fmt, line_no, "an entry address requires 4 bytes"));
                }
                let v = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64;
                // 03 is the 8086's CS:IP; 05 is linear.
                image.entry =
                    Some(if rec_type == 0x03 { (v >> 16 << 4) + (v & 0xFFFF) } else { v });
            }
            t => return Err(parse_err(fmt, line_no, format!("record type {t:#04x}"))),
        }
    }
    Err(Error::new(ErrorKind::Io, "Intel HEX without an EOF record (:00000001FF)"))
}

/// F-27a — Motorola S-record. S0 (header), S1/S2/S3 (data), S5/S6 (count,
/// validated), S7/S8/S9 (terminator carrying the entry address).
pub fn parse_srec(text: &str) -> Result<Image> {
    let fmt = RecordFormat::Srec;
    let mut image = Image::default();
    let mut data_records: u64 = 0;
    let mut terminated = false;

    for (i, raw) in text.lines().enumerate() {
        let line_no = i + 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if terminated {
            return Err(parse_err(fmt, line_no, "record after the terminator"));
        }
        let rest = line
            .strip_prefix('S')
            .or_else(|| line.strip_prefix('s'))
            .ok_or_else(|| parse_err(fmt, line_no, "record does not start with 'S'"))?;
        let (t, hex) = rest.split_at(rest.len().min(1));
        let bytes =
            hex_bytes(hex).ok_or_else(|| parse_err(fmt, line_no, "invalid hexadecimal digits"))?;
        if bytes.len() < 3 {
            return Err(parse_err(fmt, line_no, "record too short"));
        }
        let count = bytes[0] as usize;
        if bytes.len() != count + 1 {
            return Err(parse_err(
                fmt,
                line_no,
                format!("declared count {count} does not match the record"),
            ));
        }
        // Checksum: one's complement of the sum of count + address + data.
        let sum = bytes[..bytes.len() - 1].iter().fold(0u8, |a, b| a.wrapping_add(*b));
        if !sum != bytes[bytes.len() - 1] {
            return Err(parse_err(fmt, line_no, "invalid checksum"));
        }
        let addr_len = match t {
            "0" | "1" | "5" | "9" => 2,
            "2" | "6" | "8" => 3,
            "3" | "7" => 4,
            t => return Err(parse_err(fmt, line_no, format!("record type S{t}"))),
        };
        if count < addr_len + 1 {
            return Err(parse_err(fmt, line_no, "record shorter than its address"));
        }
        let addr = bytes[1..1 + addr_len].iter().fold(0u64, |a, b| (a << 8) | *b as u64);
        let data = &bytes[1 + addr_len..bytes.len() - 1];
        match t {
            "0" => {} // header: only the checksum matters
            "1" | "2" | "3" => {
                image.segments.push(Segment { addr, data: data.to_vec() });
                data_records += 1;
            }
            "5" | "6" => {
                if addr != data_records {
                    return Err(parse_err(
                        fmt,
                        line_no,
                        format!("count {addr} differs from the {data_records} data records"),
                    ));
                }
            }
            "7" | "8" | "9" => {
                image.entry = Some(addr);
                terminated = true;
            }
            _ => unreachable!(),
        }
    }
    if !terminated {
        return Err(Error::new(ErrorKind::Io, "S-record without a terminator record (S7/S8/S9)"));
    }
    image.normalize()?;
    Ok(image)
}
