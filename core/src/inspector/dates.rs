//! Date fields: time_t, FILETIME, DOS date/time and OLE DATE.

/// Days between 1899-12-30 (the OLE DATE epoch) and 1970-01-01.
pub(super) const OLE_EPOCH_DAYS: i64 = 25_569;

/// (year, month, day) from days since 1970-01-01 (Hinnant).
pub(super) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Days since 1970-01-01 from (year, month, day) (Hinnant).
pub(super) fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

pub(super) fn format_unix(secs: i64) -> Result<String, String> {
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    if !(0..=9999).contains(&y) {
        return Err(format!("year {y} outside the displayable range"));
    }
    Ok(format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        sod / 3600,
        sod / 60 % 60,
        sod % 60
    ))
}

/// Accepts `YYYY-MM-DD`, `YYYY-MM-DD HH:MM` and `YYYY-MM-DD HH:MM:SS` (UTC).
pub(super) fn parse_datetime(s: &str) -> Result<i64, String> {
    let bad = || format!("invalid date: {s} (use YYYY-MM-DD HH:MM:SS)");
    let mut it = s.split_whitespace();
    let date = it.next().ok_or_else(bad)?;
    let time = it.next();
    if it.next().is_some() {
        return Err(bad());
    }

    let mut dp = date.split('-');
    let y: i64 = dp.next().and_then(|x| x.parse().ok()).ok_or_else(bad)?;
    let m: u32 = dp.next().and_then(|x| x.parse().ok()).ok_or_else(bad)?;
    let d: u32 = dp.next().and_then(|x| x.parse().ok()).ok_or_else(bad)?;
    if dp.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return Err(bad());
    }

    let (mut h, mut mi, mut sec) = (0u32, 0u32, 0u32);
    if let Some(t) = time {
        let mut tp = t.split(':');
        h = tp.next().and_then(|x| x.parse().ok()).ok_or_else(bad)?;
        mi = tp.next().and_then(|x| x.parse().ok()).ok_or_else(bad)?;
        sec = tp.next().map(|x| x.parse().map_err(|_| bad())).transpose()?.unwrap_or(0);
        if tp.next().is_some() || h > 23 || mi > 59 || sec > 59 {
            return Err(bad());
        }
    }
    Ok(days_from_civil(y, m, d) * 86_400 + (h * 3600 + mi * 60 + sec) as i64)
}

pub(super) fn decode_dos(v: u32) -> Result<String, String> {
    // FAT layout: low word = time, high word = date.
    let time = v & 0xFFFF;
    let date = v >> 16;
    let (d, m, y) = (date & 0x1F, date >> 5 & 0x0F, (date >> 9) + 1980);
    let (s, mi, h) = ((time & 0x1F) * 2, time >> 5 & 0x3F, time >> 11);
    if !(1..=12).contains(&m) || d == 0 || h > 23 || mi > 59 || s > 59 {
        return Err("not a valid DOS date/time".into());
    }
    Ok(format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02}"))
}

pub(super) fn encode_dos(text: &str) -> Result<u32, String> {
    let secs = parse_datetime(text)?;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400) as u32;
    let (y, m, d) = civil_from_days(days);
    if !(1980..=2107).contains(&y) {
        return Err("a DOS date only covers 1980–2107".into());
    }
    let date = ((y - 1980) as u32) << 9 | m << 5 | d;
    let time = (sod / 3600) << 11 | (sod / 60 % 60) << 5 | ((sod % 60) / 2);
    Ok(date << 16 | time)
}

pub(super) fn decode_ole(v: f64) -> Result<String, String> {
    if !v.is_finite() || v.abs() >= 3_000_000.0 {
        return Err("not a plausible OLE DATE".into());
    }
    // Integer part = days since 1899-12-30; fraction = time of day, always as
    // a magnitude (the OLE convention for negative dates).
    let days = v.trunc() as i64;
    let sod = ((v - v.trunc()).abs() * 86_400.0).round() as i64;
    format_unix((days - OLE_EPOCH_DAYS) * 86_400 + sod)
}

pub(super) fn encode_ole(text: &str) -> Result<f64, String> {
    let secs = parse_datetime(text)?;
    let days = secs.div_euclid(86_400) + OLE_EPOCH_DAYS;
    let frac = secs.rem_euclid(86_400) as f64 / 86_400.0;
    Ok(if days >= 0 { days as f64 + frac } else { days as f64 - frac })
}
