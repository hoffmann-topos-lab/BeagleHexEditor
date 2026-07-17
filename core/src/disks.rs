//! F-48/F-51 — Enumerate disks and partitions, and detect mounts.
//!
//! Listing devices needs no privilege: macOS reads it from `diskutil`, Linux
//! from `/sys/block`. Opening a device for I/O *does* need privilege — that is
//! `DiskSource` (directly, when root) or the helper (F-47) otherwise.
//!
//! F-51: `DiskInfo::mount_point` is `Some` when the device is mounted; the UI
//! blocks writing to a mounted volume and demands it be unmounted first.

use std::path::PathBuf;

use crate::error::{Error, ErrorKind, Result};

/// One disk or partition as reported by the OS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskInfo {
    /// Short identifier: `disk0s2` (macOS) or `sda1` (Linux).
    pub id: String,
    /// Device node to open for I/O. On macOS this is the raw node
    /// (`/dev/rdisk0s2`), which is what a hex editor wants.
    pub node: PathBuf,
    /// Size in bytes.
    pub size: u64,
    /// Sector size (512 or 4096). Reads/writes must be aligned to it.
    pub block_size: u32,
    /// Human-readable model / media name, empty if unknown.
    pub model: String,
    /// Whole disk (`true`) vs. a partition of one (`false`).
    pub whole: bool,
    /// Internal device (`false` for USB sticks, SD cards, images…).
    pub internal: bool,
    /// Where it is mounted, if it is (F-51).
    pub mount_point: Option<PathBuf>,
}

impl DiskInfo {
    pub fn is_mounted(&self) -> bool {
        self.mount_point.is_some()
    }
}

/// Lists every disk and partition the OS reports. Requires no privilege.
pub fn enumerate() -> Result<Vec<DiskInfo>> {
    #[cfg(target_os = "macos")]
    {
        macos::enumerate()
    }
    #[cfg(target_os = "linux")]
    {
        linux::enumerate()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(Error::new(ErrorKind::Io, "disk enumeration is unsupported on this platform"))
    }
}

/// Looks up a single device by its node path or short id (for the CLI).
pub fn find(spec: &str) -> Result<DiskInfo> {
    let list = enumerate()?;
    list.into_iter()
        .find(|d| d.id == spec || d.node.as_os_str() == spec || d.node.ends_with(spec))
        .ok_or_else(|| Error::new(ErrorKind::OutOfBounds, format!("no disk matches {spec}")))
}

// ---- macOS (diskutil) ----

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::process::Command;

    pub fn enumerate() -> Result<Vec<DiskInfo>> {
        let list = diskutil(&["list", "-plist"])?;
        let mut out = Vec::new();
        for id in plist::string_array(&list, "AllDisks") {
            let info = diskutil(&["info", "-plist", &id])?;
            if let Some(disk) = parse_info(&id, &info) {
                out.push(disk);
            }
        }
        Ok(out)
    }

    fn diskutil(args: &[&str]) -> Result<String> {
        let output = Command::new("diskutil")
            .args(args)
            .output()
            .map_err(|e| Error::new(ErrorKind::Io, format!("diskutil: {e}")))?;
        if !output.status.success() {
            return Err(Error::new(
                ErrorKind::Io,
                format!("diskutil {} failed", args.join(" ")),
            ));
        }
        String::from_utf8(output.stdout)
            .map_err(|_| Error::new(ErrorKind::Io, "diskutil output is not UTF-8"))
    }

    fn parse_info(id: &str, xml: &str) -> Option<DiskInfo> {
        let node = plist::string(xml, "DeviceNode")?;
        let size = plist::integer(xml, "Size").or_else(|| plist::integer(xml, "TotalSize"))?;
        let block_size = plist::integer(xml, "DeviceBlockSize").unwrap_or(512) as u32;
        let model = plist::string(xml, "MediaName").unwrap_or_default();
        let whole = plist::boolean(xml, "WholeDisk").unwrap_or(!id.contains('s'));
        let internal = plist::boolean(xml, "Internal").unwrap_or(false);
        let mount_point = plist::string(xml, "MountPoint").filter(|s| !s.is_empty()).map(PathBuf::from);

        // Prefer the raw node (/dev/rdiskN): unbuffered, aligned I/O — what a
        // hex editor wants. Fall back to the buffered node if the shape is odd.
        let read_node = node
            .strip_prefix("/dev/disk")
            .map(|rest| PathBuf::from(format!("/dev/rdisk{rest}")))
            .unwrap_or_else(|| PathBuf::from(&node));

        Some(DiskInfo {
            id: id.to_string(),
            node: read_node,
            size,
            block_size,
            model: model.trim().to_string(),
            whole,
            internal,
            mount_point,
        })
    }

    /// Minimal reader for the flat `<dict>` that `diskutil info -plist` emits,
    /// plus the `AllDisks` string array from `diskutil list -plist`. Not a
    /// general plist parser — just enough to pull the fields we name.
    pub(super) mod plist {
        fn after_key<'a>(xml: &'a str, key: &str) -> Option<&'a str> {
            let needle = format!("<key>{key}</key>");
            let pos = xml.find(&needle)?;
            Some(&xml[pos + needle.len()..])
        }

        fn between<'a>(s: &'a str, open: &str, close: &str) -> Option<&'a str> {
            let start = s.find(open)? + open.len();
            let end = s[start..].find(close)? + start;
            Some(&s[start..end])
        }

        pub fn string(xml: &str, key: &str) -> Option<String> {
            let rest = after_key(xml, key)?.trim_start();
            // Guard against reading past the value into the next key's element.
            if !rest.starts_with("<string>") {
                if rest.starts_with("<string/>") {
                    return Some(String::new());
                }
                return None;
            }
            between(rest, "<string>", "</string>").map(unescape)
        }

        pub fn integer(xml: &str, key: &str) -> Option<u64> {
            let rest = after_key(xml, key)?.trim_start();
            between(rest, "<integer>", "</integer>")?.trim().parse().ok()
        }

        pub fn boolean(xml: &str, key: &str) -> Option<bool> {
            let rest = after_key(xml, key)?.trim_start();
            if rest.starts_with("<true/>") {
                Some(true)
            } else if rest.starts_with("<false/>") {
                Some(false)
            } else {
                None
            }
        }

        pub fn string_array(xml: &str, key: &str) -> Vec<String> {
            let Some(rest) = after_key(xml, key) else { return Vec::new() };
            let Some(body) = between(rest, "<array>", "</array>") else { return Vec::new() };
            let mut out = Vec::new();
            let mut cur = body;
            while let Some(start) = cur.find("<string>") {
                let from = start + "<string>".len();
                let Some(end) = cur[from..].find("</string>") else { break };
                out.push(unescape(&cur[from..from + end]));
                cur = &cur[from + end..];
            }
            out
        }

        fn unescape(s: &str) -> String {
            s.replace("&amp;", "&")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&apos;", "'")
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const INFO: &str = r#"<?xml version="1.0"?>
<plist version="1.0"><dict>
    <key>Content</key><string>Apple_APFS</string>
    <key>DeviceBlockSize</key><integer>4096</integer>
    <key>DeviceNode</key><string>/dev/disk0s2</string>
    <key>Internal</key><true/>
    <key>MediaName</key><string>Rock &amp; Roll SSD</string>
    <key>MountPoint</key><string></string>
    <key>Size</key><integer>250000000000</integer>
    <key>WholeDisk</key><false/>
</dict></plist>"#;

        #[test]
        fn parses_the_named_fields() {
            let d = parse_info("disk0s2", INFO).unwrap();
            assert_eq!(d.node, PathBuf::from("/dev/rdisk0s2"), "raw node preferred");
            assert_eq!(d.size, 250000000000);
            assert_eq!(d.block_size, 4096);
            assert_eq!(d.model, "Rock & Roll SSD", "entities unescaped");
            assert!(d.internal);
            assert!(!d.whole);
            assert_eq!(d.mount_point, None, "empty MountPoint is not mounted");
        }

        #[test]
        fn a_mounted_volume_reports_its_mount_point() {
            let xml = INFO.replace("<key>MountPoint</key><string></string>",
                "<key>MountPoint</key><string>/Volumes/Data</string>");
            let d = parse_info("disk0s2", &xml).unwrap();
            assert_eq!(d.mount_point, Some(PathBuf::from("/Volumes/Data")));
            assert!(d.is_mounted());
        }

        #[test]
        fn all_disks_array_is_read() {
            let list = r#"<dict><key>AllDisks</key><array>
                <string>disk0</string><string>disk0s1</string><string>disk1</string>
            </array><key>Other</key><string>x</string></dict>"#;
            assert_eq!(plist::string_array(list, "AllDisks"), vec!["disk0", "disk0s1", "disk1"]);
        }

        #[test]
        fn a_missing_key_yields_none_not_a_wrong_value() {
            // "Size" absent: must not accidentally read the next integer.
            let xml = "<dict><key>DeviceBlockSize</key><integer>512</integer></dict>";
            assert_eq!(plist::integer(xml, "Size"), None);
            assert_eq!(plist::integer(xml, "DeviceBlockSize"), Some(512));
        }
    }
}

// ---- Linux (/sys/block, /proc/mounts) ----

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::collections::HashMap;
    use std::path::Path;

    pub fn enumerate() -> Result<Vec<DiskInfo>> {
        let mounts = mounts();
        let mut out = Vec::new();
        let entries = std::fs::read_dir("/sys/block")
            .map_err(|e| Error::new(ErrorKind::Io, format!("/sys/block: {e}")))?;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let dir = entry.path();
            // Skip loop/ram pseudo-devices unless they carry a real size.
            let Some(whole) = read_device(&name, &dir, true, &mounts) else { continue };
            out.push(whole);
            // Partitions: subdirs that contain a `partition` file.
            if let Ok(parts) = std::fs::read_dir(&dir) {
                for p in parts.flatten() {
                    let pname = p.file_name().to_string_lossy().into_owned();
                    if p.path().join("partition").exists()
                        && let Some(part) = read_device(&pname, &p.path(), false, &mounts)
                    {
                        out.push(part);
                    }
                }
            }
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    fn read_u64(path: &Path) -> Option<u64> {
        std::fs::read_to_string(path).ok()?.trim().parse().ok()
    }

    fn read_device(name: &str, dir: &Path, whole: bool, mounts: &HashMap<PathBuf, PathBuf>) -> Option<DiskInfo> {
        // `size` is always in 512-byte units, regardless of the logical block size.
        let sectors = read_u64(&dir.join("size"))?;
        if sectors == 0 {
            return None;
        }
        let block_size = if whole {
            read_u64(&dir.join("queue/logical_block_size")).unwrap_or(512) as u32
        } else {
            // A partition inherits its parent's queue.
            read_u64(&dir.join("../queue/logical_block_size")).unwrap_or(512) as u32
        };
        let model = std::fs::read_to_string(dir.join("device/model"))
            .ok()
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let removable = read_u64(&dir.join("removable")).unwrap_or(0) == 1;
        let node = PathBuf::from(format!("/dev/{name}"));
        let mount_point = mounts.get(&node).cloned();
        Some(DiskInfo {
            id: name.to_string(),
            node: node.clone(),
            size: sectors * 512,
            block_size,
            model,
            whole,
            internal: !removable,
            mount_point,
        })
    }

    /// Maps device node → mount point from `/proc/mounts`.
    fn mounts() -> HashMap<PathBuf, PathBuf> {
        let mut map = HashMap::new();
        if let Ok(text) = std::fs::read_to_string("/proc/mounts") {
            for line in text.lines() {
                let mut it = line.split_whitespace();
                if let (Some(dev), Some(mp)) = (it.next(), it.next())
                    && dev.starts_with("/dev/")
                {
                    map.insert(PathBuf::from(unescape_mount(dev)), PathBuf::from(unescape_mount(mp)));
                }
            }
        }
        map
    }

    /// `/proc/mounts` octal-escapes spaces and a few other characters (`\040`).
    fn unescape_mount(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\\'
                && i + 3 < bytes.len()
                && let Ok(code) = u8::from_str_radix(&s[i + 1..i + 4], 8)
            {
                out.push(code as char);
                i += 4;
                continue;
            }
            out.push(bytes[i] as char);
            i += 1;
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn mount_paths_are_unescaped() {
            assert_eq!(unescape_mount(r"/mnt/my\040disk"), "/mnt/my disk");
            assert_eq!(unescape_mount("/dev/sda1"), "/dev/sda1");
        }
    }
}
