//! Safari NIKKE Guard scan engine.
//!
//! Read-only: no check writes, moves or deletes a file, edits the registry or
//! opens a network connection. The detection rules follow
//! MotherSphere/NIKKE-Launcher-Check (GPL-3.0).

pub mod checks;
pub mod env;
pub mod iocs;
pub mod locate;
pub mod model;
pub mod report;
pub mod steps;
pub mod util;
#[cfg(windows)]
mod win;

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use checks::Collector;
pub use env::Env;
use model::{Mode, ScanResult, Severity, Verdict};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Progress for the UI: a short phase label, the entries visited so far and the current path.
pub type Progress<'a> = &'a dyn Fn(&str, u64, &Path);

pub fn scan(env: &Env, mode: Mode, folders: &[PathBuf], cancel: &AtomicBool, progress: Progress) -> ScanResult {
    let t0 = Instant::now();
    let started = util::now();

    progress("설치 경로 탐색", 0, Path::new(""));
    let found = locate::locate(env, mode, folders, cancel, &|n, p| progress("설치 경로 탐색", n, p));

    let mut c = Collector::default();
    progress("런처 기록 확인", found.entries, Path::new(""));
    for i in &found.installs {
        checks::install::check(i, &mut c);
    }
    progress("런처 데이터 확인", found.entries, Path::new(""));
    for d in &found.launcher_data {
        checks::launcher_data::check(d, &mut c);
    }
    progress("브라우저 · 임시 파일 확인", found.entries, Path::new(""));
    for p in &found.profiles {
        checks::profile::check(p, &mut c);
    }
    progress("레지스트리 · 프로세스 확인", found.entries, Path::new(""));
    checks::system::check(env, &mut c);
    let hosts = checks::hosts::check(&env.hosts);

    let exposure = if found.installs.is_empty() && found.launcher_data.is_empty() && !c.findings.iter().any(|f| f.severity > Severity::Info)
    {
        Default::default()
    } else {
        checks::exposure::collect(&found.profiles)
    };

    let worst = c.findings.iter().map(|f| f.severity).max();
    let verdict = match worst {
        Some(Severity::Critical) => Verdict::Infected,
        Some(Severity::Warning) => Verdict::Exposed,
        _ if !found.installs.is_empty() || !found.launcher_data.is_empty() => Verdict::Clean,
        _ => Verdict::NotFound,
    };

    if !found.launcher_data.is_empty() && found.installs.is_empty() {
        c.notes.push(
            "런처 데이터만 발견 · 설치 폴더 미확인: debug.log와 다운로드 로그는 검사하지 못함 → [폴더 지정]으로 설치 폴더 검사".into(),
        );
    }
    if mode == Mode::Quick {
        c.notes
            .push("빠른 검사: 드라이브 5단계 깊이까지만 탐색 · 못 찾았으면 [전체 검사]".into());
    }
    if found.limit_hit {
        c.notes.push("탐색 항목 한도 도달 · 일부 폴더 미확인".into());
    }
    if found.cancelled {
        c.notes.push("검사 중단됨 · 결과 불완전".into());
    }
    for r in &found.unreadable_roots {
        c.notes.push(format!("읽기 실패: {}", r.display()));
    }

    let mut timeline = c.timeline;
    timeline.sort_by(|a, b| a.time.cmp(&b.time));
    let used_since_agent = c.last_activity.is_some_and(|t| t >= iocs::AGENT_FROM_UNIX);

    let mut findings = c.findings;
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));

    let mut r = ScanResult {
        tool_version: VERSION.to_string(),
        mode,
        started,
        duration_ms: t0.elapsed().as_millis() as u64,
        verdict,
        findings,
        timeline,
        exposure,
        hosts,
        installs: found.installs.iter().map(|p| p.display().to_string()).collect(),
        launcher_data: found.launcher_data.iter().map(|p| p.display().to_string()).collect(),
        last_launcher_activity: c.last_activity,
        used_since_agent,
        entries_visited: found.entries,
        notes: c.notes,
        steps: Vec::new(),
    };
    r.steps = steps::build(&r);
    r
}
