//! F-82 — The x86-64 Linux ptrace loop, in raw syscalls (no libc, D-note).
//!
//! `Command` forks/execs the target; a `pre_exec` hook does `PTRACE_TRACEME` so
//! the child stops at `execve`. The parent then single-steps by syscall
//! (`PTRACE_SYSCALL`), reading the syscall number from `orig_rax` (index 15 of
//! `user_regs_struct`) at each entry stop and streaming its name.

use std::arch::asm;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::process::Command;

use super::syscall_name;
use crate::error::{Error, ErrorKind, Result};

const PTRACE_TRACEME: usize = 0;
const PTRACE_GETREGS: usize = 12;
const PTRACE_SYSCALL: usize = 24;
const PTRACE_SETOPTIONS: usize = 0x4200;
const PTRACE_O_TRACESYSGOOD: usize = 1;
const SYS_WAIT4: usize = 61;
const SYS_PTRACE: usize = 101;
/// A syscall-stop is reported as `SIGTRAP | 0x80` once `TRACESYSGOOD` is set.
const SYSCALL_STOP_SIG: i32 = 0x85;

/// `user_regs_struct` on x86-64 is 27 `u64`s; `orig_rax` (the syscall number at
/// entry) is index 15.
const ORIG_RAX: usize = 15;
const NREGS: usize = 27;

#[inline]
unsafe fn syscall4(n: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
    let ret: isize;
    // SAFETY: a bare `syscall`; the kernel clobbers rcx/r11, declared below.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") n as isize => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

fn ptrace(request: usize, pid: i32, addr: usize, data: usize) -> isize {
    unsafe { syscall4(SYS_PTRACE, request, pid as usize, addr, data) }
}

fn wait4(pid: i32, status: &mut i32) -> isize {
    unsafe { syscall4(SYS_WAIT4, pid as usize, status as *mut i32 as usize, 0, 0) }
}

fn wifexited(status: i32) -> bool {
    status & 0x7f == 0
}

fn exit_code(status: i32) -> i32 {
    (status >> 8) & 0xff
}

fn is_syscall_stop(status: i32) -> bool {
    // WIFSTOPPED && stop signal == SIGTRAP|0x80.
    status & 0xff == 0x7f && (status >> 8) & 0xff == SYSCALL_STOP_SIG
}

pub(super) fn trace(cmd: &[String], out: &mut dyn Write) -> Result<i32> {
    let child = unsafe {
        Command::new(&cmd[0])
            .args(&cmd[1..])
            .pre_exec(|| {
                // In the child, after fork, before execve.
                if syscall4(SYS_PTRACE, PTRACE_TRACEME, 0, 0, 0) < 0 {
                    return Err(std::io::Error::other("PTRACE_TRACEME failed"));
                }
                Ok(())
            })
            .spawn()
    }
    .map_err(|e| Error::new(ErrorKind::Io, format!("cannot start {}: {e}", cmd[0])))?;
    let pid = child.id() as i32;

    let mut status = 0i32;
    // The initial stop at execve.
    if wait4(pid, &mut status) < 0 {
        return Err(Error::new(ErrorKind::Io, "wait for the tracee failed"));
    }
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);

    let mut count = 0u64;
    let mut at_entry = true;
    loop {
        if ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0 {
            break;
        }
        if wait4(pid, &mut status) < 0 {
            break;
        }
        if wifexited(status) {
            let code = exit_code(status);
            let _ = writeln!(out, "+++ exited with {code} after {count} syscalls +++");
            return Ok(code);
        }
        if is_syscall_stop(status) {
            if at_entry {
                let mut regs = [0u64; NREGS];
                if ptrace(PTRACE_GETREGS, pid, 0, regs.as_mut_ptr() as usize) >= 0 {
                    let _ = writeln!(out, "{}", syscall_name(regs[ORIG_RAX]));
                    count += 1;
                }
            }
            at_entry = !at_entry;
        }
    }
    Ok(0)
}
