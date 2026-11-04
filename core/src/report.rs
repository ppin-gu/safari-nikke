//! The text report, and hiding personal details before it is shared.

use std::fmt::Write;

use crate::env::Env;
use crate::model::{ScanResult, Severity};
use crate::util::fmt_utc;

pub struct Redact {
    /// (text, replacement), longest first.
    pairs: Vec<(String, String)>,
}

impl Redact {
    pub fn from_env(env: &Env) -> Redact {
        let mut pairs = Vec::new();
        if let Some(p) = &env.profile {
            pairs.push((p.display().to_string(), "%USERPROFILE%".to_string()));
        }
        if let Some(u) = env.user_name.as_ref().filter(|u| u.len() >= 2) {
            pairs.push((u.clone(), "<사용자>".to_string()));
        }
        if let Some(c) = env.computer_name.as_ref().filter(|c| c.len() >= 2) {
            pairs.push((c.clone(), "<PC>".to_string()));
        }
        pairs.sort_by_key(|(a, _)| std::cmp::Reverse(a.len()));
        Redact { pairs }
    }

    pub fn apply(&self, s: &str) -> String {
        let mut out = s.to_string();
        for (a, b) in &self.pairs {
            out = replace_ci(&out, a, b);
        }
        let out = hide_after(&out, "agent started as ", "<PC>");
        hide_uuids(&out)
    }
}

fn replace_ci(hay: &str, needle: &str, with: &str) -> String {
    if needle.is_empty() {
        return hay.to_string();
    }
    let lower = hay.to_lowercase();
    let n = needle.to_lowercase();
    // Byte offsets only line up when lowercasing kept the length (ASCII names).
    if lower.len() != hay.len() {
        return hay.replace(needle, with);
    }
    let mut out = String::new();
    let mut i = 0;
    while let Some(j) = lower[i..].find(&n) {
        out.push_str(&hay[i..i + j]);
        out.push_str(with);
        i += j + n.len();
    }
    out.push_str(&hay[i..]);
    out
}

fn hide_after(s: &str, marker: &str, with: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find(marker) {
        out.push_str(&rest[..i + marker.len()]);
        out.push_str(with);
        let after = &rest[i + marker.len()..];
        let end = after
            .find(|c: char| c.is_whitespace() || c == '"' || c == ',')
            .unwrap_or(after.len());
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

/// 8-4-4-4-12 hex IDs (the agent ID) and 32-hex tokens.
fn hide_uuids(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let hex = |c: u8| c.is_ascii_hexdigit();
    let is_uuid = |at: usize| -> bool {
        if at + 36 > b.len() {
            return false;
        }
        let w = &b[at..at + 36];
        w.iter()
            .enumerate()
            .all(|(k, &c)| if [8, 13, 18, 23].contains(&k) { c == b'-' } else { hex(c) })
    };
    let boundary = |at: usize| at == 0 || !hex(b[at - 1]);
    while i < b.len() {
        if boundary(i) && is_uuid(i) {
            out.push_str("<ID>");
            i += 36;
            continue;
        }
        if boundary(i) && i + 32 <= b.len() && b[i..i + 32].iter().all(|&c| hex(c)) && (i + 32 == b.len() || !hex(b[i + 32])) {
            out.push_str("<ID>");
            i += 32;
            continue;
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

pub fn text(r: &ScanResult) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "Safari NIKKE Guard v{} 검사 리포트", r.tool_version);
    let _ = writeln!(
        s,
        "검사 시각: {} (UTC) · 소요 {:.1}초 · 항목 {}개",
        fmt_utc(r.started),
        r.duration_ms as f64 / 1000.0,
        r.entries_visited
    );
    let mode = match r.mode {
        crate::model::Mode::Quick => "빠른 검사",
        crate::model::Mode::Full => "전체 검사",
        crate::model::Mode::Folder => "폴더 지정",
    };
    let _ = writeln!(s, "검사 방식: {mode}");
    let _ = writeln!(s);
    let _ = writeln!(s, "판정: {} — {}", r.verdict.label(), r.verdict.sub());
    let _ = writeln!(
        s,
        "치명 {} · 경고 {} · 정보 {}",
        r.count(Severity::Critical),
        r.count(Severity::Warning),
        r.count(Severity::Info)
    );
    if let Some(t) = r.last_launcher_activity {
        let _ = writeln!(
            s,
            "런처 최근 활동: {} (UTC){}",
            fmt_utc(t),
            if r.used_since_agent { " · 10/23 이후 사용" } else { "" }
        );
    }

    let _ = writeln!(s, "\n[발견 항목]");
    let mut fs = r.findings.clone();
    fs.sort_by_key(|f| std::cmp::Reverse(f.severity));
    for f in &fs {
        let _ = writeln!(s, "[{}] {}", f.severity.label(), f.title);
        let _ = writeln!(s, "    {}", f.location);
        for e in &f.evidence {
            let _ = writeln!(s, "    > {e}");
        }
    }
    if fs.is_empty() {
        let _ = writeln!(s, "없음");
    }

    if !r.timeline.is_empty() {
        let _ = writeln!(s, "\n[타임라인] (로그 시각, 해당 PC 현지 시간)");
        for e in &r.timeline {
            let _ = writeln!(s, "{}  {}", e.time, e.what);
        }
    }

    let x = &r.exposure;
    if !x.is_empty() {
        let _ = writeln!(s, "\n[유출 가능 정보]");
        for (b, p) in &x.logins {
            let _ = writeln!(s, "· 저장 로그인: {b} ({p})");
        }
        for (w, b) in &x.wallets {
            let _ = writeln!(s, "· 지갑 확장: {w} ({b})");
        }
        for (w, p) in &x.secrets {
            let _ = writeln!(s, "· {w}: {p}");
        }
    }

    let _ = writeln!(s, "\n[hosts 차단]");
    for h in &r.hosts {
        let st = match h.blocked {
            Some(true) => "차단됨",
            Some(false) => "미차단",
            None => "확인 불가",
        };
        let _ = writeln!(s, "{:<26}{st}", h.domain);
    }

    let _ = writeln!(s, "\n[조치]");
    for (i, st) in r.steps.iter().enumerate() {
        let _ = writeln!(
            s,
            "{}. {}{}",
            i + 1,
            st.title,
            if st.body.is_empty() {
                String::new()
            } else {
                format!(" — {}", st.body)
            }
        );
        for it in &st.items {
            let _ = writeln!(s, "   □ {it}");
        }
        for t in &st.targets {
            let _ = writeln!(s, "   {}: {}", t.label, t.value);
        }
        for c in &st.commands {
            let _ = writeln!(s, "   $ {c}");
        }
    }

    if !r.notes.is_empty() {
        let _ = writeln!(s, "\n[참고]");
        for n in &r.notes {
            let _ = writeln!(s, "· {n}");
        }
    }
    let _ = writeln!(
        s,
        "\n미탐지가 안전을 보장하지 않음. 검사 엔진 기준: MotherSphere/NIKKE-Launcher-Check (GPL-3.0)."
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hides_ids_and_hosts() {
        let r = Redact {
            pairs: vec![(r"C:\Users\Bob".into(), "%USERPROFILE%".into())],
        };
        let s = r.apply(
            r"c:\users\bob\x adopted 3c4c9b75-09e5-4619-99ee-97c1dc3c0373 agent started as DESKTOP-1 px/0123456789abcdef0123456789abcdef",
        );
        assert_eq!(s, r"%USERPROFILE%\x adopted <ID> agent started as <PC> px/<ID>");
    }
}
