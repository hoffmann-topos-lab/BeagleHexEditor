//! F-82 — Dynamic syscall tracer (Fase 14). **Linux only** (D5).
//!
//! Live-process instrumentation needs `ptrace` and privilege; the project scopes
//! it out of macOS (D5), where — like `F-56` for raw disks — the CLI says "Linux
//! only" plainly instead of failing silently. The Linux path spawns the target,
//! `PTRACE_TRACEME`s it and streams one line per syscall (an `strace`-lite). It
//! is written with **raw syscalls, no libc** (the project's zero-dependency
//! ethos, like the helper); per D5 it is developed on macOS and verified on a
//! Linux host — this build only cross-compiles it.
//!
//! Currently x86-64 Linux only (the register layout carrying the syscall number
//! is arch-specific); other Linux arches report that clearly.

use std::io::Write;

use crate::error::{Error, ErrorKind, Result};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_x86_64;

/// Spawns `cmd` (`cmd[0]` is the program) under a syscall tracer, streaming one
/// line per syscall to `out`, and returns the child's exit code.
pub fn trace(cmd: &[String], out: &mut dyn Write) -> Result<i32> {
    if cmd.is_empty() {
        return Err(Error::new(ErrorKind::Io, "no command to trace"));
    }
    run(cmd, out)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn run(cmd: &[String], out: &mut dyn Write) -> Result<i32> {
    linux_x86_64::trace(cmd, out)
}

#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
fn run(_cmd: &[String], _out: &mut dyn Write) -> Result<i32> {
    Err(Error::new(
        ErrorKind::Io,
        "syscall tracing supports x86-64 Linux only for now (the syscall-number \
         register layout is architecture-specific)",
    ))
}

#[cfg(not(target_os = "linux"))]
fn run(_cmd: &[String], _out: &mut dyn Write) -> Result<i32> {
    Err(Error::new(
        ErrorKind::Io,
        "dynamic tracing is Linux only (D5): tracing a live process needs ptrace \
         and privilege, out of scope on macOS",
    ))
}

/// The mnemonic for an x86-64 Linux syscall number, or `syscall_<nr>` for one
/// outside the built-in table. Kept here (not in the Linux-gated module) so the
/// table compiles and is tested on every platform; only the Linux x86-64 build
/// actually calls it, hence the platform-conditional `dead_code` allowance.
#[cfg_attr(not(all(target_os = "linux", target_arch = "x86_64")), allow(dead_code))]
pub(crate) fn syscall_name(nr: u64) -> String {
    let name = match nr {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        4 => "stat",
        5 => "fstat",
        8 => "lseek",
        9 => "mmap",
        10 => "mprotect",
        11 => "munmap",
        12 => "brk",
        13 => "rt_sigaction",
        14 => "rt_sigprocmask",
        21 => "access",
        22 => "pipe",
        23 => "select",
        32 => "dup",
        33 => "dup2",
        39 => "getpid",
        41 => "socket",
        42 => "connect",
        43 => "accept",
        44 => "sendto",
        45 => "recvfrom",
        49 => "bind",
        50 => "listen",
        56 => "clone",
        57 => "fork",
        58 => "vfork",
        59 => "execve",
        60 => "exit",
        61 => "wait4",
        62 => "kill",
        63 => "uname",
        72 => "fcntl",
        78 => "getdents",
        79 => "getcwd",
        80 => "chdir",
        83 => "mkdir",
        84 => "rmdir",
        87 => "unlink",
        89 => "readlink",
        96 => "gettimeofday",
        101 => "ptrace",
        102 => "getuid",
        105 => "setuid",
        137 => "statfs",
        157 => "prctl",
        158 => "arch_prctl",
        202 => "futex",
        217 => "getdents64",
        218 => "set_tid_address",
        228 => "clock_gettime",
        231 => "exit_group",
        257 => "openat",
        262 => "newfstatat",
        273 => "set_robust_list",
        302 => "prlimit64",
        318 => "getrandom",
        _ => return format!("syscall_{nr}"),
    };
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_and_unknown_syscall_names() {
        assert_eq!(syscall_name(59), "execve");
        assert_eq!(syscall_name(257), "openat");
        assert_eq!(syscall_name(9999), "syscall_9999");
    }

    #[test]
    fn tracing_reports_linux_only_off_linux() {
        // On the macOS dev host this is the D5-mandated behaviour.
        #[cfg(not(target_os = "linux"))]
        {
            let mut out = Vec::new();
            let err = trace(&["ls".to_string()], &mut out).unwrap_err();
            assert!(err.detail.contains("Linux only"), "{}", err.detail);
        }
        let mut out = Vec::new();
        assert!(trace(&[], &mut out).is_err(), "empty command is rejected everywhere");
    }
}
