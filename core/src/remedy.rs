//! Selected remediation. This is the only module that changes anything, and it
//! only runs the actions the user ticked and confirmed.
//!
//! Every target is checked again right before it is touched, against the same
//! patterns the scan uses, so a stale or edited plan cannot delete anything else.
//! Order is fixed: close the launcher, back up evidence, delete the registry key,
//! then the DLL files, then Temp files and the launcher cache. A DLL that Windows
//! keeps locked is saved as pending and deleted after a restart.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::env::Env;
use crate::iocs;
use crate::model::{Kind, ScanResult};
use crate::util::{eq_ci, fmt_utc, is_hex64, name_of, now, path_ci, read_capped};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    KillLauncher,
    DeleteRegistry,
    DeleteDllFolder,
    DeleteFile,
    DeleteTempFiles,
    DeleteCache,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    pub id: String,
    pub kind: ActionKind,
    pub label: String,
    /// Path, registry key or PID.
    pub target: String,
    pub detail: String,
    /// Needs administrator rights (UAC prompt).
    pub admin: bool,
    /// Ticked by default.
    pub recommended: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Done,
    Failed,
    PendingReboot,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outcome {
    pub id: String,
    pub label: String,
    pub status: Status,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyResult {
    pub outcomes: Vec<Outcome>,
    pub backup: Option<String>,
    /// Actions left for after a restart.
    pub pending: Vec<Action>,
}

/// The changes the app can make. Tests use a fake.
pub trait Ops: Send + Sync {
    fn kill(&self, pid: u32) -> Result<(), String>;
    fn delete_clsid(&self) -> Result<(), String>;
    /// Hosts lines and firewall rules, with administrator rights.
    fn block(&self) -> Result<Vec<String>, String>;
}

pub struct NoOps;

impl Ops for NoOps {
    fn kill(&self, _: u32) -> Result<(), String> {
        Err("Windows 전용".into())
    }
    fn delete_clsid(&self) -> Result<(), String> {
        Err("Windows 전용".into())
    }
    fn block(&self) -> Result<Vec<String>, String> {
        Err("Windows 전용".into())
    }
}

#[cfg(windows)]
pub fn system_ops() -> Box<dyn Ops> {
    Box::new(crate::win::WinOps)
}

#[cfg(not(windows))]
pub fn system_ops() -> Box<dyn Ops> {
    Box::new(NoOps)
}

fn action(kind: ActionKind, label: &str, target: impl Into<String>, detail: impl Into<String>, recommended: bool) -> Action {
    let target = target.into();
    Action {
        id: format!("{kind:?}:{target}"),
        kind,
        label: label.into(),
        target,
        detail: detail.into(),
        admin: kind == ActionKind::Block,
        recommended,
    }
}

fn pid_of(location: &str) -> Option<u32> {
    let i = location.find("PID ")?;
    location[i + 4..].trim_end_matches(')').trim().parse().ok()
}

/// The actions offered for a scan result, in the order they run.
pub fn plan(r: &ScanResult) -> Vec<Action> {
    let mut v = Vec::new();
    let push = |v: &mut Vec<Action>, a: Action| {
        if !v.iter().any(|b: &Action| b.id == a.id) {
            v.push(a);
        }
    };
    for f in &r.findings {
        match f.kind {
            Kind::LauncherRunning => {
                if let Some(pid) = pid_of(&f.location) {
                    push(
                        &mut v,
                        action(ActionKind::KillLauncher, "런처 종료", pid.to_string(), f.location.clone(), true),
                    );
                }
            }
            Kind::Registry | Kind::RegistryLeftover => {
                push(
                    &mut v,
                    action(
                        ActionKind::DeleteRegistry,
                        "레지스트리 키 삭제",
                        format!(r"HKCU\{}", iocs::CLSID_KEY),
                        "COM 등록 해제 · DLL 자동 로드 차단",
                        true,
                    ),
                );
            }
            Kind::BrowserDll => {
                let p = Path::new(&f.location);
                if is_hex64(&name_of(p)) {
                    push(
                        &mut v,
                        action(
                            ActionKind::DeleteDllFolder,
                            &format!("{} 폴더 삭제", f.title),
                            f.location.clone(),
                            "64자리 해시 폴더 전체",
                            true,
                        ),
                    );
                } else {
                    let file = f
                        .evidence
                        .iter()
                        .find(|e| e.to_ascii_lowercase().ends_with(iocs::PEH_DLL))
                        .cloned()
                        .unwrap_or(f.location.clone());
                    push(
                        &mut v,
                        action(ActionKind::DeleteFile, &format!("{} 파일 삭제", f.title), file, iocs::PEH_DLL, true),
                    );
                }
            }
            Kind::OldDll => push(
                &mut v,
                action(ActionKind::DeleteFile, "구버전 지속 파일 삭제", f.location.clone(), "", true),
            ),
            Kind::TempFile => push(
                &mut v,
                action(
                    ActionKind::DeleteTempFiles,
                    "k2f 임시 파일 삭제",
                    f.location.clone(),
                    f.evidence.join(", "),
                    true,
                ),
            ),
            _ => {}
        }
    }
    let flagged = r.findings.iter().any(|f| f.severity > crate::model::Severity::Info);
    for d in &r.launcher_data {
        if let Some(c) = path_ci(Path::new(d), "tbs_cache") {
            push(
                &mut v,
                action(
                    ActionKind::DeleteCache,
                    "런처 캐시 삭제",
                    c.display().to_string(),
                    "변조 스크립트 캐시 · 런처 로그인 유지 정보도 삭제됨",
                    flagged,
                ),
            );
        }
    }
    let unblocked = r.hosts.iter().any(|h| h.blocked != Some(true));
    push(
        &mut v,
        action(
            ActionKind::Block,
            "hosts · 방화벽 차단 등록",
            "hosts + Windows 방화벽",
            "도메인 3개 · IP 2개 · 관리자 권한 필요",
            unblocked && flagged,
        ),
    );
    v.sort_by_key(|a| a.kind);
    v
}

// ---------- Validation ----------

fn has_peh_ancestor(p: &Path) -> bool {
    p.ancestors().skip(1).take(3).any(|a| eq_ci(&name_of(a), iocs::PEH_DIR))
}

pub fn valid(a: &Action) -> Result<(), String> {
    let p = Path::new(&a.target);
    let ok = match a.kind {
        ActionKind::KillLauncher | ActionKind::Block => true,
        ActionKind::DeleteRegistry => a.target == format!(r"HKCU\{}", iocs::CLSID_KEY),
        ActionKind::DeleteDllFolder => is_hex64(&name_of(p)) && p.parent().is_some_and(|q| eq_ci(&name_of(q), iocs::PEH_DIR)),
        ActionKind::DeleteFile => {
            let n = name_of(p);
            (eq_ci(&n, iocs::PEH_DLL) || iocs::OLD_PEH_FILES.iter().any(|f| eq_ci(&n, f))) && has_peh_ancestor(p)
        }
        ActionKind::DeleteTempFiles => eq_ci(&name_of(p), "Temp"),
        ActionKind::DeleteCache => {
            eq_ci(&name_of(p), "tbs_cache")
                && p.parent()
                    .is_some_and(|q| iocs::LAUNCHER_DATA_DIRS.iter().any(|d| eq_ci(&name_of(q), d)))
        }
    };
    if ok {
        Ok(())
    } else {
        Err("대상이 검사 패턴과 다름 · 실행 안 함".into())
    }
}

// ---------- Backup ----------

fn safe_name(p: &Path) -> String {
    p.to_string_lossy()
        .replace([':', '\\', '/'], "_")
        .trim_matches('_')
        .chars()
        .rev()
        .take(150)
        .collect::<String>()
        .chars()
        .rev()
        .collect()
}

fn sha256_file(p: &Path) -> Option<String> {
    let b = read_capped(p)?;
    Some(Sha256::digest(&b).iter().map(|x| format!("{x:02x}")).collect())
}

/// Copies the report and the log evidence to `<dest>/니케점검_백업_<time>`. The DLL and the
/// collected credentials in Temp are not copied: only their names and hashes are listed.
pub fn backup(r: &ScanResult, report: &str, dest: &Path) -> Result<PathBuf, String> {
    let stamp = fmt_utc(now()).replace(['-', ':'], "").replace(' ', "-");
    let dir = dest.join(format!("니케점검_백업_{stamp}"));
    let ev = dir.join("evidence");
    fs::create_dir_all(&ev).map_err(|e| format!("백업 폴더 생성 실패: {e}"))?;
    fs::write(dir.join("report.txt"), report.replace('\n', "\r\n")).map_err(|e| format!("리포트 저장 실패: {e}"))?;
    let mut listing = String::new();
    for f in &r.findings {
        let p = Path::new(&f.location);
        match f.kind {
            Kind::AgentRan | Kind::AgentDownload | Kind::AgentState | Kind::Network | Kind::ScriptCache if p.is_file() => {
                let _ = fs::copy(p, ev.join(safe_name(p)));
            }
            Kind::AgentFile | Kind::BrowserDll | Kind::OldDll => {
                let files: Vec<PathBuf> = if p.is_dir() {
                    walkdir::WalkDir::new(p)
                        .into_iter()
                        .flatten()
                        .filter(|e| e.file_type().is_file())
                        .map(|e| e.into_path())
                        .collect()
                } else {
                    vec![p.to_path_buf()]
                };
                for file in files {
                    let size = fs::metadata(&file).map(|m| m.len()).unwrap_or(0);
                    let h = sha256_file(&file).unwrap_or_else(|| "읽기 실패".into());
                    listing.push_str(&format!("{h}  {size}  {}\r\n", file.display()));
                }
            }
            Kind::TempFile => {
                for e in &f.evidence {
                    listing.push_str(&format!("(이름만)  {}\\{e}\r\n", f.location));
                }
            }
            _ => {}
        }
    }
    let mut lf = fs::File::create(dir.join("files.txt")).map_err(|e| e.to_string())?;
    let _ = lf.write_all("SHA-256  크기  경로 (복사하지 않은 파일)\r\n".as_bytes());
    let _ = lf.write_all(listing.as_bytes());
    Ok(dir)
}

// ---------- Apply ----------

fn launcher_running(env: &Env) -> bool {
    env.system.processes().iter().any(|p| eq_ci(&p.name, iocs::LAUNCHER_EXE))
}

fn remove(p: &Path) -> std::io::Result<()> {
    if p.is_dir() {
        fs::remove_dir_all(p)
    } else {
        fs::remove_file(p)
    }
}

fn locked(e: &std::io::Error) -> bool {
    // Access denied (5) and sharing violation (32) on Windows.
    matches!(e.raw_os_error(), Some(5) | Some(32)) || e.kind() == std::io::ErrorKind::PermissionDenied
}

fn run_one(env: &Env, ops: &dyn Ops, a: &Action, dll_loaded: bool) -> (Status, String) {
    if let Err(e) = valid(a) {
        return (Status::Failed, e);
    }
    match a.kind {
        ActionKind::KillLauncher => {
            let pid: u32 = a.target.parse().unwrap_or(0);
            let still = env.system.processes().into_iter().find(|p| p.pid == pid);
            match still {
                None => (Status::Skipped, "이미 종료됨".into()),
                Some(p) if !eq_ci(&p.name, iocs::LAUNCHER_EXE) => (Status::Failed, format!("PID {pid}는 런처가 아님 · 실행 안 함")),
                Some(_) => match ops.kill(pid) {
                    Ok(()) => (Status::Done, "종료됨".into()),
                    Err(e) => (Status::Failed, e),
                },
            }
        }
        ActionKind::DeleteRegistry => {
            if env.system.clsid().is_empty() {
                return (Status::Skipped, "이미 없음".into());
            }
            match ops.delete_clsid() {
                Ok(()) if env.system.clsid().is_empty() => (Status::Done, "삭제됨".into()),
                Ok(()) => (Status::Failed, "삭제 후에도 키가 남아 있음".into()),
                Err(e) => (Status::Failed, e),
            }
        }
        ActionKind::DeleteDllFolder | ActionKind::DeleteFile => {
            let p = Path::new(&a.target);
            if !p.exists() {
                return (Status::Skipped, "이미 없음".into());
            }
            if env
                .system
                .clsid()
                .iter()
                .any(|c| c.value.as_deref().is_some_and(|v| !v.trim().is_empty()))
            {
                return (Status::Failed, "레지스트리 키가 남아 있음 · 레지스트리 먼저 삭제".into());
            }
            if dll_loaded {
                return (Status::PendingReboot, "DLL 사용 중 · 재시작 후 삭제".into());
            }
            match remove(p) {
                Ok(()) => (Status::Done, "삭제됨".into()),
                Err(e) if locked(&e) => (Status::PendingReboot, "파일 잠김 · 재시작 후 삭제".into()),
                Err(e) => (Status::Failed, format!("삭제 실패: {e}")),
            }
        }
        ActionKind::DeleteTempFiles => {
            let dir = Path::new(&a.target);
            let Ok(rd) = fs::read_dir(dir) else {
                return (Status::Skipped, "폴더 없음".into());
            };
            let (mut ok, mut bad) = (0, 0);
            for e in rd.flatten() {
                if e.file_name().to_string_lossy().to_ascii_lowercase().starts_with(iocs::TEMP_PREFIX) {
                    if remove(&e.path()).is_ok() {
                        ok += 1;
                    } else {
                        bad += 1;
                    }
                }
            }
            match (ok, bad) {
                (0, 0) => (Status::Skipped, "이미 없음".into()),
                (_, 0) => (Status::Done, format!("{ok}개 삭제")),
                _ => (Status::Failed, format!("{ok}개 삭제 · {bad}개 실패")),
            }
        }
        ActionKind::DeleteCache => {
            if launcher_running(env) {
                return (Status::Failed, "런처 실행 중 · 런처 종료 후 다시 실행".into());
            }
            let p = Path::new(&a.target);
            if !p.exists() {
                return (Status::Skipped, "이미 없음".into());
            }
            match remove(p) {
                Ok(()) => (Status::Done, "삭제됨".into()),
                Err(e) => (Status::Failed, format!("삭제 실패: {e}")),
            }
        }
        ActionKind::Block => match ops.block() {
            Ok(lines) if lines.is_empty() => (Status::Skipped, "이미 등록됨".into()),
            Ok(lines) => (Status::Done, lines.join(" · ")),
            Err(e) => (Status::Failed, e),
        },
    }
}

/// Runs the selected actions in order. `backup_to` is where the evidence folder goes
/// (the desktop); it is made before the first deletion.
pub fn apply(env: &Env, ops: &dyn Ops, r: &ScanResult, report: &str, selected: &[Action], backup_to: Option<&Path>) -> ApplyResult {
    let mut actions = selected.to_vec();
    actions.sort_by_key(|a| a.kind);
    let deletes = actions
        .iter()
        .any(|a| !matches!(a.kind, ActionKind::KillLauncher | ActionKind::Block));
    let mut out = ApplyResult {
        outcomes: Vec::new(),
        backup: None,
        pending: Vec::new(),
    };
    let dll_loaded = !env.system.peh_modules().is_empty();
    let mut backed_up = false;
    for a in &actions {
        if deletes && !backed_up && a.kind != ActionKind::KillLauncher {
            backed_up = true;
            if let Some(dest) = backup_to {
                match backup(r, report, dest) {
                    Ok(d) => out.backup = Some(d.display().to_string()),
                    Err(e) => {
                        out.outcomes.push(Outcome {
                            id: "backup".into(),
                            label: "증거 백업".into(),
                            status: Status::Failed,
                            message: format!("{e} · 삭제 중단"),
                        });
                        return out;
                    }
                }
            }
        }
        let (status, message) = run_one(env, ops, a, dll_loaded);
        if status == Status::PendingReboot {
            out.pending.push(a.clone());
        }
        out.outcomes.push(Outcome {
            id: a.id.clone(),
            label: a.label.clone(),
            status,
            message,
        });
    }
    out
}

/// Runs the actions saved before a restart. No backup: it was made the first time.
pub fn apply_pending(env: &Env, ops: &dyn Ops, pending: &[Action]) -> ApplyResult {
    let mut out = ApplyResult {
        outcomes: Vec::new(),
        backup: None,
        pending: Vec::new(),
    };
    let dll_loaded = !env.system.peh_modules().is_empty();
    for a in pending {
        let (status, message) = run_one(env, ops, a, dll_loaded);
        if status == Status::PendingReboot {
            out.pending.push(a.clone());
        }
        out.outcomes.push(Outcome {
            id: a.id.clone(),
            label: a.label.clone(),
            status,
            message,
        });
    }
    out
}

pub fn save_pending(file: &Path, pending: &[Action]) -> Result<(), String> {
    if pending.is_empty() {
        let _ = fs::remove_file(file);
        return Ok(());
    }
    if let Some(d) = file.parent() {
        fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    fs::write(file, serde_json::to_vec_pretty(pending).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

/// Saved actions that still pass validation. Anything else in the file is dropped.
pub fn load_pending(file: &Path) -> Vec<Action> {
    let Ok(b) = fs::read(file) else { return Vec::new() };
    let v: Vec<Action> = serde_json::from_slice(&b).unwrap_or_default();
    v.into_iter()
        .filter(|a| matches!(a.kind, ActionKind::DeleteDllFolder | ActionKind::DeleteFile) && valid(a).is_ok())
        .collect()
}

/// Adds `0.0.0.0 <domain>` lines for the domains the hosts file does not block yet.
/// Returns the lines added.
pub fn add_hosts_lines(hosts: &Path) -> Result<Vec<String>, String> {
    let entries = crate::checks::hosts::check(hosts);
    if entries.iter().any(|e| e.blocked.is_none()) {
        return Err("hosts 읽기 실패".into());
    }
    let lines = crate::checks::hosts::lines_to_add(&entries);
    if lines.is_empty() {
        return Ok(lines);
    }
    let existing = fs::read(hosts).unwrap_or_default();
    let mut add = String::new();
    if !existing.is_empty() && !existing.ends_with(b"\n") {
        add.push_str("\r\n");
    }
    add.push_str("# Safari NIKKE Guard: NIKKE launcher malware\r\n");
    for l in &lines {
        add.push_str(l);
        add.push_str("\r\n");
    }
    let mut f = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(hosts)
        .map_err(|e| format!("hosts 쓰기 실패: {e}"))?;
    f.write_all(add.as_bytes()).map_err(|e| format!("hosts 쓰기 실패: {e}"))?;
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_rejects_other_paths() {
        let mk = |kind, target: &str| Action {
            id: String::new(),
            kind,
            label: String::new(),
            target: target.into(),
            detail: String::new(),
            admin: false,
            recommended: true,
        };
        let hash = "a".repeat(64);
        assert!(valid(&mk(
            ActionKind::DeleteDllFolder,
            &format!("/u/Chrome/User Data/PlatformExperienceHelper/{hash}")
        ))
        .is_ok());
        assert!(valid(&mk(ActionKind::DeleteDllFolder, "/u/Chrome/User Data/PlatformExperienceHelper")).is_err());
        assert!(valid(&mk(ActionKind::DeleteDllFolder, &format!("/u/Documents/{hash}"))).is_err());
        assert!(valid(&mk(
            ActionKind::DeleteFile,
            "/u/Chrome/Application/PlatformExperienceHelper/old-clsid.txt"
        ))
        .is_ok());
        assert!(valid(&mk(
            ActionKind::DeleteFile,
            "/u/Chrome/Application/PlatformExperienceHelper/platform_experience_helper.exe"
        ))
        .is_err());
        assert!(valid(&mk(ActionKind::DeleteCache, "/u/AppData/Roaming/nikke_launcher/tbs_cache")).is_ok());
        assert!(valid(&mk(ActionKind::DeleteCache, "/u/AppData/Roaming/other/tbs_cache")).is_err());
        assert!(valid(&mk(ActionKind::DeleteTempFiles, "/u/AppData/Local/Temp")).is_ok());
        assert!(valid(&mk(ActionKind::DeleteTempFiles, "/u/Desktop")).is_err());
        assert!(valid(&mk(
            ActionKind::DeleteRegistry,
            r"HKCU\Software\Classes\CLSID\{00000000-0000-0000-0000-000000000000}"
        ))
        .is_err());
    }

    #[test]
    fn reads_pid() {
        assert_eq!(pid_of("nikke_launcher.exe (PID 4242)"), Some(4242));
    }
}
