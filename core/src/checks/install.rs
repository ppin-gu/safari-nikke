//! The NIKKE install folder: `Launcher/intl_service/debug.log` and `Launcher/log/`.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

use walkdir::WalkDir;

use super::Collector;
use crate::iocs;
use crate::model::{Kind, Severity};
use crate::util::{contains, log_time, mtime, path_ci, read_capped, snippet, MAX_READ};

const MAX_LOG_LINE: usize = 64 * 1024;

pub fn check(install: &Path, c: &mut Collector) {
    let loc = install.display().to_string();
    match path_ci(install, "Launcher/intl_service/debug.log") {
        Some(log) => {
            c.activity(mtime(&log));
            debug_log(&log, c);
        }
        None => c.notes.push(format!("debug.log 없음: {loc}")),
    }
    if let Some(dir) = path_ci(install, "Launcher/log") {
        log_dir(&dir, c);
    }
    c.add(Severity::Info, Kind::Install, "NIKKE 설치 폴더", loc, Vec::new());
}

fn run_label(line: &str) -> &'static str {
    if line.contains("lua downloaded to") {
        "에이전트 다운로드"
    } else if line.contains("adopted ") {
        "에이전트 최초 실행"
    } else if line.contains("resuming ") {
        "에이전트 재실행"
    } else if line.contains("agent started as") {
        "에이전트 시작"
    } else if line.contains("k2f_chan registered") {
        "에이전트 채널 등록"
    } else {
        "에이전트 활동"
    }
}

fn debug_log(log: &Path, c: &mut Collector) {
    let loc = log.display().to_string();
    let Ok(f) = fs::File::open(log) else {
        c.add(Severity::Info, Kind::Unreadable, "읽기 실패", loc, Vec::new());
        return;
    };
    let mut r = BufReader::new(f);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match r.read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if buf.len() > MAX_LOG_LINE {
            buf.truncate(MAX_LOG_LINE);
        }
        let line = String::from_utf8_lossy(&buf);
        let line = line.trim_end();
        if line.contains("k2f_chan") {
            c.add(
                Severity::Critical,
                Kind::AgentRan,
                "악성 에이전트 실행 기록",
                loc.clone(),
                vec![line.to_string()],
            );
        }
        let agent_line = line.contains("k2f") || line.contains("agent started as") || line.contains("lua downloaded to");
        if agent_line && iocs::RUN_LINES.iter().any(|m| line.contains(m)) {
            let t = log_time(line).unwrap_or_else(|| "시간 미기록".into());
            c.event(t, run_label(line));
        }
        if iocs::AGENT_SERVER.iter().any(|m| line.contains(m)) {
            c.add(
                Severity::Critical,
                Kind::AgentDownload,
                "에이전트 서버 접속",
                loc.clone(),
                vec![line.to_string()],
            );
            if let Some(t) = log_time(line) {
                c.event(t, "에이전트 서버 접속");
            }
        } else if line.contains(iocs::LOADER) {
            c.add(
                Severity::Warning,
                Kind::ScriptCache,
                "악성 스크립트 로드 기록",
                loc.clone(),
                vec![line.to_string()],
            );
            if let Some(t) = log_time(line) {
                c.event(t, "악성 스크립트 로드");
            }
        }
    }
}

fn log_dir(dir: &Path, c: &mut Collector) {
    for e in WalkDir::new(dir).max_depth(8).follow_links(false).into_iter().flatten() {
        if !e.file_type().is_file() {
            continue;
        }
        let p = e.path();
        let size = e.metadata().map(|m| m.len()).unwrap_or(0);
        if size > MAX_READ {
            continue;
        }
        let Some(bytes) = read_capped(p) else { continue };
        let loc = p.display().to_string();
        if bytes.starts_with(&iocs::LUAJIT_MAGIC) {
            let note = if size == iocs::AGENT_SIZE {
                " (알려진 빌드 크기)"
            } else {
                ""
            };
            c.add(
                Severity::Critical,
                Kind::AgentFile,
                "악성 에이전트 파일",
                loc.clone(),
                vec![format!("LuaJIT 바이트코드, {size} bytes{note}")],
            );
            c.activity(mtime(p));
            continue;
        }
        if contains(&bytes, "insight.bundle") || contains(&bytes, "analytics.insightjs.com") {
            let needle = if contains(&bytes, "insight.bundle") {
                "insight.bundle"
            } else {
                "analytics.insightjs.com"
            };
            let ev: Vec<String> = snippet(&bytes, needle).into_iter().collect();
            for line in String::from_utf8_lossy(&bytes).lines().filter(|l| l.contains(needle)).take(20) {
                if let Some(t) = log_time(line) {
                    c.event(t, "에이전트 다운로드 요청");
                }
            }
            c.add(Severity::Critical, Kind::AgentDownload, "에이전트 다운로드 기록", loc, ev);
            c.activity(mtime(p));
        } else if contains(&bytes, iocs::LOADER) {
            let ev: Vec<String> = snippet(&bytes, iocs::LOADER).into_iter().collect();
            c.add(Severity::Warning, Kind::ScriptCache, "악성 스크립트 로드 기록", loc, ev);
        }
    }
}
