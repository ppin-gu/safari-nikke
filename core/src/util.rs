//! Small helpers shared by the checks.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Largest file a check reads.
pub const MAX_READ: u64 = 64 * 1024 * 1024;
pub const MAX_EVIDENCE: usize = 5;
pub const MAX_LINE: usize = 240;

/// The file's bytes, up to `MAX_READ`. None if it cannot be read.
pub fn read_capped(p: &Path) -> Option<Vec<u8>> {
    let f = fs::File::open(p).ok()?;
    let mut buf = Vec::new();
    f.take(MAX_READ).read_to_end(&mut buf).ok()?;
    Some(buf)
}

pub fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

pub fn contains(hay: &[u8], needle: &str) -> bool {
    find(hay, needle.as_bytes()).is_some()
}

/// The printable text around the first `needle`, for a finding's evidence.
pub fn snippet(hay: &[u8], needle: &str) -> Option<String> {
    let i = find(hay, needle.as_bytes())?;
    let printable = |b: u8| (0x20..0x7f).contains(&b) || b >= 0x80;
    let mut s = i;
    while s > 0 && printable(hay[s - 1]) && i - s < 120 {
        s -= 1;
    }
    let mut e = i + needle.len();
    while e < hay.len() && printable(hay[e]) && e - i < 200 {
        e += 1;
    }
    Some(cut(&String::from_utf8_lossy(&hay[s..e])))
}

/// Cut to `MAX_LINE` characters.
pub fn cut(s: &str) -> String {
    let s = s.trim();
    if s.chars().count() <= MAX_LINE {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(MAX_LINE).collect();
        t.push('…');
        t
    }
}

/// Never quote the agent's saved password.
pub fn hide_secret(s: &str) -> String {
    match s.find("agent_pass") {
        Some(i) => format!("{}…", &s[..i]),
        None => s.to_string(),
    }
}

pub fn eq_ci(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

pub fn name_of(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// The child of `dir` whose name matches `name` without regard to case.
pub fn child_ci(dir: &Path, name: &str) -> Option<PathBuf> {
    let direct = dir.join(name);
    if direct.exists() {
        return Some(direct);
    }
    fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .find(|p| eq_ci(&name_of(p), name))
}

/// `rel` ("a/b/c") under `base`, each part matched without regard to case.
pub fn path_ci(base: &Path, rel: &str) -> Option<PathBuf> {
    let mut cur = base.to_path_buf();
    for part in rel.split('/').filter(|p| !p.is_empty()) {
        cur = child_ci(&cur, part)?;
    }
    Some(cur)
}

pub fn mtime(p: &Path) -> Option<u64> {
    fs::metadata(p)
        .ok()?
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// "YYYY-MM-DD HH:MM:SS" (UTC) from Unix seconds.
pub fn fmt_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil from days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// The time at the start of a launcher log line.
///
/// `[2026-11-03 01:47:35.556][316]...` -> `2026-11-03 01:47:35`
/// `[1103/120001.001:INFO:...` -> `11-03 12:00:01 (연도 미기록)`
pub fn log_time(line: &str) -> Option<String> {
    let l = line.trim_start().strip_prefix('[')?;
    let b = l.as_bytes();
    if b.len() >= 19
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b' '
        && b[13] == b':'
        && b[16] == b':'
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[..19].is_ascii()
    {
        return Some(l[..19].to_string());
    }
    // Chromium style: MMDD/HHMMSS
    if b.len() >= 11 && b[4] == b'/' && b[..4].iter().all(u8::is_ascii_digit) && b[5..11].iter().all(u8::is_ascii_digit) {
        return Some(format!(
            "{}-{} {}:{}:{} (연도 미기록)",
            &l[0..2],
            &l[2..4],
            &l[5..7],
            &l[7..9],
            &l[9..11]
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_utc() {
        assert_eq!(fmt_utc(0), "1970-01-01 00:00:00");
        assert_eq!(fmt_utc(crate::iocs::AGENT_FROM_UNIX), "2026-10-23 00:00:00");
    }

    #[test]
    fn reads_log_times() {
        assert_eq!(
            log_time("[2026-11-03 01:47:35.556][316][ERROR]x").as_deref(),
            Some("2026-11-03 01:47:35")
        );
        assert_eq!(
            log_time("[1103/120001.001:INFO:CONSOLE(61)] x").as_deref(),
            Some("11-03 12:00:01 (연도 미기록)")
        );
        assert_eq!(log_time("no time"), None);
    }

    #[test]
    fn hides_agent_pass() {
        assert_eq!(hide_secret(r#"{"agent_id":"x","agent_pass":"s3cret"}"#), r#"{"agent_id":"x","…"#);
    }
}
