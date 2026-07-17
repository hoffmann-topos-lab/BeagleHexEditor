//! F-75 — Static indicators, in the spirit of PEStudio's flags: risky imports,
//! writable+executable sections, entry-point anomalies, TLS callbacks, and IOC
//! strings (URLs, IPs, registry run-keys, LOLBins). Offline only — no VirusTotal,
//! no network (the deliberate scope cut).

use crate::document::Document;
use crate::format::BinaryInfo;
use crate::progress::Progress;
use crate::strings::{self, StrEncoding};

use super::entropy::PackReport;

/// How much of the file the IOC-string pass reads, and how many hits it keeps.
const IOC_SCAN_CAP: u64 = 64 << 20;
const IOC_MAX: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Noteworthy but not inherently malicious (a bare URL, an IP).
    Info,
    /// Commonly abused; worth a closer look.
    Suspicious,
}

impl Severity {
    pub fn name(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Suspicious => "suspicious",
        }
    }
}

/// One flagged trait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Indicator {
    pub severity: Severity,
    /// Where it came from: "import", "section", "header", "tls", "string".
    pub category: &'static str,
    pub detail: String,
}

/// F-75 — Collects the static indicators for a binary.
pub fn scan(
    doc: &mut Document,
    info: &BinaryInfo,
    packing: &PackReport,
    progress: &Progress,
) -> Vec<Indicator> {
    let mut out = Vec::new();
    suspicious_imports(info, &mut out);
    wx_sections(info, &mut out);
    high_entropy_code(packing, &mut out);
    entry_anomaly(info, &mut out);
    tls_callbacks(info, &mut out);
    ioc_strings(doc, progress, &mut out);
    out
}

fn suspicious_imports(info: &BinaryInfo, out: &mut Vec<Indicator>) {
    for imp in &info.imports {
        if let Some(reason) = import_reason(&imp.name) {
            let lib = if imp.library.is_empty() {
                String::new()
            } else {
                format!("{}!", imp.library)
            };
            out.push(Indicator {
                severity: Severity::Suspicious,
                category: "import",
                detail: format!("{lib}{} — {reason}", imp.name),
            });
        }
    }
}

/// Maps a commonly-abused API name to why it matters. Matches the normalised
/// base (lowercase, no leading underscore), also trying the name without its
/// ANSI/Wide `A`/`W` suffix so `CreateProcessW` and `_system` both hit.
fn import_reason(name: &str) -> Option<&'static str> {
    let base = name.trim_start_matches('_').to_ascii_lowercase();
    if let Some(r) = api_reason(&base) {
        return Some(r);
    }
    base.strip_suffix(['a', 'w']).and_then(api_reason)
}

fn api_reason(n: &str) -> Option<&'static str> {
    let r = match n {
        "virtualalloc" | "virtualallocex" => "allocates memory for unpacked/injected code",
        "virtualprotect" | "virtualprotectex" => "changes memory protection (unpacking / RWX)",
        "writeprocessmemory" => "writes into another process (code injection)",
        "readprocessmemory" => "reads another process's memory",
        "createremotethread" | "createremotethreadex" => "runs code in another process (injection)",
        "ntunmapviewofsection" | "zwunmapviewofsection" => "process hollowing",
        "queueuserapc" | "ntqueueapcthread" => "APC injection",
        "setwindowshookex" => "installs a global hook (keylogging / injection)",
        "getasynckeystate" | "getkeystate" => "captures keystrokes",
        "loadlibrary" | "loadlibraryex" => "loads a library at runtime",
        "getprocaddress" => "resolves APIs dynamically (hides imports)",
        "winexec" | "shellexecute" | "shellexecuteex" | "createprocess" => "spawns a process",
        "urldownloadtofile" | "internetopen" | "internetopenurl" | "internetreadfile"
        | "httpopenrequest" | "httpsendrequest" => "downloads from the network",
        "isdebuggerpresent" | "checkremotedebuggerpresent" | "ntqueryinformationprocess" => {
            "anti-debugging check"
        }
        "adjusttokenprivileges" | "openprocesstoken" => "adjusts process privileges",
        "regsetvalueex" | "regcreatekeyex" => "writes the registry (persistence)",
        "cryptencrypt" | "cryptdecrypt" | "cryptacquirecontext" => "cryptography (ransomware?)",
        "createtoolhelp32snapshot" | "process32first" | "process32next" => "enumerates processes",
        // POSIX
        "ptrace" => "anti-debugging / process tracing",
        "execve" | "execl" | "execlp" | "execvp" | "system" | "popen" => "executes a command",
        "fork" | "vfork" | "clone" => "creates a process",
        "mprotect" => "changes memory protection (RWX / unpacking)",
        "dlopen" | "dlsym" => "loads a library at runtime",
        "memfd_create" => "fileless in-memory execution",
        "setuid" | "setgid" => "changes process privileges",
        _ => return None,
    };
    Some(r)
}

fn wx_sections(info: &BinaryInfo, out: &mut Vec<Indicator>) {
    for s in &info.sections {
        if s.perms.w && s.perms.x {
            out.push(Indicator {
                severity: Severity::Suspicious,
                category: "section",
                detail: format!("section '{}' is writable and executable (W^X violation)", s.name),
            });
        }
    }
}

fn high_entropy_code(packing: &PackReport, out: &mut Vec<Indicator>) {
    for s in &packing.sections {
        if s.executable && s.entropy > 7.0 {
            out.push(Indicator {
                severity: Severity::Suspicious,
                category: "section",
                detail: format!(
                    "executable section '{}' entropy {:.2}/8 (packed or encrypted)",
                    s.name, s.entropy
                ),
            });
        }
    }
}

fn entry_anomaly(info: &BinaryInfo, out: &mut Vec<Indicator>) {
    if info.entry == 0 {
        return;
    }
    match super::section_at_vaddr(info, info.entry) {
        None => out.push(Indicator {
            severity: Severity::Suspicious,
            category: "header",
            detail: format!("entry point {:#x} is not inside any section", info.entry),
        }),
        Some(sec) if !sec.perms.x => out.push(Indicator {
            severity: Severity::Suspicious,
            category: "header",
            detail: format!("entry point is in non-executable section '{}'", sec.name),
        }),
        Some(sec) if sec.perms.w => out.push(Indicator {
            severity: Severity::Suspicious,
            category: "header",
            detail: format!("entry point is in writable section '{}'", sec.name),
        }),
        Some(_) => {}
    }
}

fn tls_callbacks(info: &BinaryInfo, out: &mut Vec<Indicator>) {
    let n = info.extra_entries.iter().filter(|e| e.kind == "TLS callback").count();
    if n > 0 {
        out.push(Indicator {
            severity: Severity::Suspicious,
            category: "tls",
            detail: format!("{n} TLS callback(s) run before the entry point"),
        });
    }
}

fn ioc_strings(doc: &mut Document, progress: &Progress, out: &mut Vec<Indicator>) {
    let cap = doc.len().min(IOC_SCAN_CAP);
    if cap == 0 {
        return;
    }
    let (found, _) = strings::extract(
        doc,
        &[StrEncoding::Utf8, StrEncoding::Utf16Le],
        5,
        0..cap,
        50_000,
        progress,
    );
    let mut seen = Vec::new();
    for s in &found {
        let mut add = |sev, detail: String| {
            if !seen.contains(&detail) {
                seen.push(detail.clone());
                out.push(Indicator { severity: sev, category: "string", detail });
            }
        };
        // A single string can hold several IOCs, so each kind is checked.
        if let Some(url) = find_url(&s.text) {
            add(Severity::Info, format!("URL: {url}"));
        }
        if let Some(ip) = find_ipv4(&s.text) {
            add(Severity::Info, format!("IPv4: {ip}"));
        }
        if let Some(key) = registry_key(&s.text) {
            add(Severity::Suspicious, format!("registry key: {key}"));
        }
        if let Some(tool) = lolbin(&s.text) {
            add(Severity::Suspicious, format!("references {tool}"));
        }
        if seen.len() >= IOC_MAX {
            break;
        }
    }
}

fn find_url(text: &str) -> Option<&str> {
    for scheme in ["https://", "http://", "ftp://"] {
        if let Some(pos) = text.find(scheme) {
            let rest = &text[pos..];
            let end = rest.find([' ', '"', '\'', '<', '>', ')']).unwrap_or(rest.len());
            if end > scheme.len() {
                return Some(&rest[..end]);
            }
        }
    }
    None
}

/// The first dotted-quad in `text`, if every octet is 0..=255. Rejects the
/// trivial `0.0.0.0` to cut noise.
fn find_ipv4(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
            let cand = &text[start..i];
            if is_ipv4(cand) {
                return Some(cand.to_string());
            }
        } else {
            i += 1;
        }
    }
    None
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    let ok = parts.iter().all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u8>().is_ok());
    ok && s != "0.0.0.0"
}

fn registry_key(text: &str) -> Option<&str> {
    let hives = ["HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "HKLM\\", "HKCU\\"];
    let run = "\\Microsoft\\Windows\\CurrentVersion\\Run";
    if text.contains(run) || hives.iter().any(|h| text.contains(h)) {
        return Some(text.trim());
    }
    None
}

fn lolbin(text: &str) -> Option<&'static str> {
    const TOOLS: &[&str] = &[
        "powershell", "cmd.exe", "rundll32", "regsvr32", "mshta", "wscript", "cscript",
        "schtasks", "bitsadmin", "certutil", "wmic",
    ];
    let low = text.to_ascii_lowercase();
    TOOLS.iter().copied().find(|t| low.contains(t))
}
