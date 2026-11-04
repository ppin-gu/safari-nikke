//! Whether the hosts file blocks the three domains. Protection only; never edited.

use std::fs;
use std::path::Path;

use crate::iocs;
use crate::model::HostsEntry;

const SINKS: [&str; 4] = ["0.0.0.0", "127.0.0.1", "::1", "::"];

pub fn check(hosts: &Path) -> Vec<HostsEntry> {
    let text = match fs::read(hosts) {
        Ok(b) => Some(String::from_utf8_lossy(&b).into_owned()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(String::new()),
        Err(_) => None,
    };
    iocs::DOMAINS
        .iter()
        .map(|d| HostsEntry {
            domain: d.to_string(),
            blocked: text.as_deref().map(|t| blocks(t, d)),
        })
        .collect()
}

fn blocks(text: &str, domain: &str) -> bool {
    text.lines().any(|raw| {
        let line = raw.split('#').next().unwrap_or("");
        let mut parts = line.split_whitespace();
        let Some(ip) = parts.next() else { return false };
        SINKS.contains(&ip) && parts.any(|h| h.eq_ignore_ascii_case(domain))
    })
}

/// Lines to add for the domains that are not blocked.
pub fn lines_to_add(entries: &[HostsEntry]) -> Vec<String> {
    entries
        .iter()
        .filter(|e| e.blocked != Some(true))
        .map(|e| format!("0.0.0.0 {}", e.domain))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::blocks;

    #[test]
    fn reads_hosts_lines() {
        let t = "# 0.0.0.0 insightjs.org\n127.0.0.1\tlocalhost\n0.0.0.0 insightjs.com analytics.insightjs.com # block\n";
        assert!(blocks(t, "insightjs.com"));
        assert!(blocks(t, "analytics.insightjs.com"));
        assert!(!blocks(t, "insightjs.org"));
    }
}
