//! Fase 14 — `trace`: dynamic syscall tracer (F-82), **Linux only** (D5).
//!
//! Everything after `trace` is the program to run (plus its own arguments), so
//! the tracer's output goes to stderr like `strace` and the program keeps its
//! stdout. On macOS this reports "Linux only" instead of failing silently.

pub(crate) fn cmd_trace(args: &[String]) -> Result<(), String> {
    // An optional `--` separates the tracer from the command.
    let cmd = match args.first().map(String::as_str) {
        Some("--") => &args[1..],
        _ => args,
    };
    if cmd.is_empty() {
        return Err("usage: hexed trace [--] <program> [args…]".into());
    }
    let mut out = std::io::stderr().lock();
    match hexed_core::trace::trace(cmd, &mut out) {
        Ok(0) => Ok(()),
        Ok(code) => Err(format!("the traced program exited with {code}")),
        Err(e) => Err(e.to_string()),
    }
}
