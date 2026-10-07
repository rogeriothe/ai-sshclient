//! Shrinks command output for AI agents: strips terminal escapes, keeps only the final state of
//! `\r`-redrawn lines (progress bars) and folds runs of identical lines.
//!
//! Lossy on purpose, so only used where the output is read by a model (MCP), never for the CLI,
//! whose stdout may be redirected to a file.

use std::sync::LazyLock;

use regex::Regex;

/// Environment exported before compact runs so remote tools skip colors and pagers.
/// Server and per-call `env` override these.
pub const QUIET_ENV: &[(&str, &str)] = &[
    ("NO_COLOR", "1"),
    ("TERM", "dumb"),
    ("PAGER", "cat"),
    ("GIT_PAGER", "cat"),
    ("SYSTEMD_PAGER", "cat"),
    ("SYSTEMD_COLORS", "0"),
];

/// Runs of at least this many identical lines are folded into one line plus a marker.
const MIN_REPEAT: usize = 3;

static ANSI: LazyLock<Regex> = LazyLock::new(|| {
    // CSI (colors, cursor moves), OSC (titles, hyperlinks) and two-byte escapes.
    Regex::new(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")
        .expect("valid regex")
});

pub fn compact(text: &str) -> String {
    let text = ANSI.replace_all(text, "");
    let trailing_newline = text.ends_with('\n');
    let body = text.strip_suffix('\n').unwrap_or(&text);
    if body.is_empty() {
        return text.into_owned();
    }

    let mut out = String::with_capacity(body.len());
    let mut prev: Option<&str> = None;
    let mut count = 0usize;
    for line in body.split('\n') {
        let line = last_redraw(line);
        if prev == Some(line) {
            count += 1;
            continue;
        }
        if let Some(p) = prev {
            push_run(&mut out, p, count);
        }
        prev = Some(line);
        count = 1;
    }
    if let Some(p) = prev {
        push_run(&mut out, p, count);
    }
    if !trailing_newline {
        out.pop();
    }
    out
}

/// A line redrawn with `\r` shows only what was written after the last `\r` (CRLF excluded).
fn last_redraw(line: &str) -> &str {
    let line = line.strip_suffix('\r').unwrap_or(line);
    match line.rfind('\r') {
        Some(i) => &line[i + 1..],
        None => line,
    }
}

fn push_run(out: &mut String, line: &str, count: usize) {
    if count >= MIN_REPEAT {
        out.push_str(line);
        out.push('\n');
        out.push_str(&format!(
            "[previous line repeated {} more times]\n",
            count - 1
        ));
    } else {
        for _ in 0..count {
            out.push_str(line);
            out.push('\n');
        }
    }
}
