//! A Windows user profile: browser DLL persistence and the agent's Temp files.

use std::fs;
use std::path::Path;

use walkdir::WalkDir;

use super::Collector;
use crate::iocs;
use crate::model::{Kind, Severity};
use crate::util::{eq_ci, is_hex64, mtime, name_of, path_ci};

pub fn check(profile: &Path, c: &mut Collector) {
    for (browser, rel) in iocs::CHROMIUM {
        if let Some(peh) = path_ci(profile, &format!("{rel}/{}", iocs::PEH_DIR)).filter(|p| p.is_dir()) {
            peh_folder(browser, &peh, c);
        }
    }
    if let Some(app) = path_ci(profile, "AppData/Local/Google/Chrome/Application/PlatformExperienceHelper") {
        old_files(&app, c);
    }
    if let Some(temp) = path_ci(profile, "AppData/Local/Temp") {
        temp_files(&temp, c);
    }
}

/// `<User Data>\PlatformExperienceHelper`: the DLL at any depth, or a 64-hex folder.
fn peh_folder(browser: &str, peh: &Path, c: &mut Collector) {
    let Ok(rd) = fs::read_dir(peh) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let name = name_of(&p);
        if p.is_dir() && is_hex64(&name) {
            let has_dll = WalkDir::new(&p)
                .into_iter()
                .flatten()
                .any(|f| eq_ci(&f.file_name().to_string_lossy(), iocs::PEH_DLL));
            let ev = if has_dll {
                vec![format!("{} 존재", iocs::PEH_DLL)]
            } else {
                vec!["DLL 없음 (이미 삭제됐을 수 있음)".into()]
            };
            c.add(
                Severity::Critical,
                Kind::BrowserDll,
                &format!("{browser} 지속 DLL"),
                p.display().to_string(),
                ev,
            );
            c.activity(mtime(&p));
        } else if p.is_file() && eq_ci(&name, iocs::PEH_DLL) {
            c.add(
                Severity::Critical,
                Kind::BrowserDll,
                &format!("{browser} 지속 DLL"),
                p.display().to_string(),
                vec![format!("{} 존재", iocs::PEH_DLL)],
            );
        } else if p.is_dir() {
            if let Some(dll) = WalkDir::new(&p)
                .into_iter()
                .flatten()
                .find(|f| eq_ci(&f.file_name().to_string_lossy(), iocs::PEH_DLL))
            {
                c.add(
                    Severity::Critical,
                    Kind::BrowserDll,
                    &format!("{browser} 지속 DLL"),
                    p.display().to_string(),
                    vec![dll.path().display().to_string()],
                );
            }
        }
    }
}

/// Files of an older persistence version. Chrome's own platform_experience_helper.exe is normal.
pub fn old_files(dir: &Path, c: &mut Collector) {
    for f in iocs::OLD_PEH_FILES {
        if let Some(p) = path_ci(dir, f).filter(|p| p.is_file()) {
            c.add(
                Severity::Critical,
                Kind::OldDll,
                "구버전 지속 파일",
                p.display().to_string(),
                Vec::new(),
            );
        }
    }
}

pub fn temp_files(temp: &Path, c: &mut Collector) {
    let Ok(rd) = fs::read_dir(temp) else { return };
    let mut hits = Vec::new();
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name.to_ascii_lowercase().starts_with(iocs::TEMP_PREFIX) {
            hits.push(name);
        }
    }
    if !hits.is_empty() {
        hits.sort();
        let n = hits.len();
        let mut ev: Vec<String> = hits.into_iter().take(4).collect();
        if n > 4 {
            ev.push(format!("외 {}개", n - 4));
        }
        c.add(
            Severity::Critical,
            Kind::TempFile,
            "악성 에이전트 임시 파일",
            temp.display().to_string(),
            ev,
        );
    }
}
