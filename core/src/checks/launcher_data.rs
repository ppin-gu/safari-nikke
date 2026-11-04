//! The launcher data folder: `%APPDATA%\nikke_launcher` (and `_hmt`).

use std::path::Path;

use base64::Engine;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use super::Collector;
use crate::iocs;
use crate::model::{Kind, Severity};
use crate::util::{contains, eq_ci, hide_secret, mtime, read_capped, snippet, MAX_READ};

/// Chromium stores HSTS hosts as base64(SHA-256(host in DNS wire format)).
pub fn hsts_key(host: &str) -> String {
    let mut wire = Vec::new();
    for label in host.split('.') {
        wire.push(label.len() as u8);
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
    base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&wire))
}

fn in_cache(p: &Path) -> bool {
    p.components().any(|c| {
        let n = c.as_os_str().to_string_lossy();
        eq_ci(&n, "Code Cache") || eq_ci(&n, "Cache")
    })
}

pub fn check(dir: &Path, c: &mut Collector) {
    let mut files = 0u64;
    let analytics_key = hsts_key("analytics.insightjs.com");
    let loader_keys = [hsts_key("insightjs.com"), hsts_key("insightjs.org")];
    for e in WalkDir::new(dir).max_depth(12).follow_links(false).into_iter().flatten() {
        if !e.file_type().is_file() {
            continue;
        }
        if e.metadata().map(|m| m.len()).unwrap_or(0) > MAX_READ {
            continue;
        }
        let p = e.path();
        let Some(bytes) = read_capped(p) else { continue };
        files += 1;
        c.activity(mtime(p));
        let name = e.file_name().to_string_lossy().to_string();
        let loc = p.display().to_string();

        if let Some(m) = iocs::AGENT_MARKS.iter().find(|m| contains(&bytes, m)) {
            let ev = snippet(&bytes, m).map(|s| hide_secret(&s)).into_iter().collect();
            c.add(Severity::Critical, Kind::AgentState, "악성 에이전트 상태 저장", loc, ev);
            continue;
        }

        if eq_ci(&name, "TransportSecurity") {
            if contains(&bytes, &analytics_key) {
                c.add(
                    Severity::Critical,
                    Kind::Network,
                    "에이전트 서버 접속 기록",
                    loc,
                    vec!["HSTS: analytics.insightjs.com".into()],
                );
            } else if loader_keys.iter().any(|k| contains(&bytes, k)) {
                c.add(
                    Severity::Warning,
                    Kind::Network,
                    "악성 도메인 접속 기록",
                    loc,
                    vec!["HSTS: insightjs.com".into()],
                );
            }
            continue;
        }

        if !contains(&bytes, iocs::LOADER) {
            continue;
        }
        let net = name == "Network Persistent State" || name == "Reporting and NEL";
        if contains(&bytes, "analytics.insightjs.com") && net {
            let ev = snippet(&bytes, "analytics.insightjs.com").into_iter().collect();
            c.add(Severity::Critical, Kind::Network, "에이전트 서버 접속 기록", loc, ev);
        } else if net {
            let ev = snippet(&bytes, iocs::LOADER).into_iter().collect();
            c.add(Severity::Warning, Kind::Network, "악성 도메인 접속 기록", loc, ev);
        } else if in_cache(p) {
            let ev = snippet(&bytes, iocs::LOADER).into_iter().collect();
            c.add(Severity::Warning, Kind::ScriptCache, "악성 스크립트 캐시", loc, ev);
        } else {
            let ev = snippet(&bytes, iocs::LOADER).into_iter().collect();
            c.add(Severity::Warning, Kind::ScriptCache, "악성 도메인 기록", loc, ev);
        }
    }
    c.add(
        Severity::Info,
        Kind::LauncherData,
        "런처 데이터 폴더",
        dir.display().to_string(),
        vec![format!("파일 {files}개 확인")],
    );
}

#[cfg(test)]
mod tests {
    use super::hsts_key;

    #[test]
    fn hsts_keys_match_the_infected_install() {
        assert_eq!(hsts_key("insightjs.com"), "JeFWywdZy+3jPC93e3P7ACdJ8liQHB7rH+9VHn7kswg=");
        assert_eq!(hsts_key("analytics.insightjs.com"), "wxL1BeG57AG6frvPqS7txqpE3NyN0/fSUZHCbEn9NSw=");
    }
}
