//! The current user's registry key, %TEMP%, running programs and loaded DLLs.

use std::path::PathBuf;

use super::{profile, Collector};
use crate::env::Env;
use crate::iocs;
use crate::model::{Kind, Severity};
use crate::util::{eq_ci, path_ci};

pub fn check(env: &Env, c: &mut Collector) {
    let key = format!(r"HKCU\{}\InprocServer32", iocs::CLSID_KEY);
    for v in env.system.clsid() {
        match v.value.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(dll) => c.add(
                Severity::Critical,
                Kind::Registry,
                "레지스트리 등록",
                key.clone(),
                vec![format!("{} → {dll}", v.view)],
            ),
            None => c.add(
                Severity::Critical,
                Kind::RegistryLeftover,
                "레지스트리 잔여 키",
                key.clone(),
                vec![format!("{} → (빈 값)", v.view)],
            ),
        }
    }

    if let Some(t) = &env.temp {
        profile::temp_files(t, c);
    }
    let mut app_dirs: Vec<PathBuf> = ["ProgramW6432", "ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"]
        .iter()
        .filter_map(|k| std::env::var_os(k).map(PathBuf::from))
        .collect();
    app_dirs.dedup();
    for d in app_dirs {
        if let Some(p) = path_ci(&d, "Google/Chrome/Application/PlatformExperienceHelper") {
            profile::old_files(&p, c);
        }
    }

    for p in env.system.processes() {
        if eq_ci(&p.name, iocs::LAUNCHER_EXE) {
            c.add(
                Severity::Critical,
                Kind::LauncherRunning,
                "런처 실행 중",
                format!("{} (PID {})", p.name, p.pid),
                Vec::new(),
            );
        }
    }
    for m in env.system.peh_modules() {
        c.add(
            Severity::Critical,
            Kind::DllLoaded,
            "지속 DLL 로드됨",
            format!("{} (PID {})", m.process, m.pid),
            vec![m.path],
        );
    }
}
