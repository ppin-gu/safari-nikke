//! Finding NIKKE installs, launcher data folders and user profiles.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use walkdir::WalkDir;

use crate::env::Env;
use crate::iocs;
use crate::model::Mode;
use crate::util::{eq_ci, name_of, path_ci};

/// A quick scan opens folders 5 levels below each root (`D:\Games\Level Infinite\NIKKE\Launcher`
/// is level 4), so it sees files down to level 6.
pub const QUICK_DEPTH: usize = 6;
pub const ENTRY_LIMIT: u64 = 50_000_000;

#[derive(Debug, Default)]
pub struct Located {
    pub installs: Vec<PathBuf>,
    pub launcher_data: Vec<PathBuf>,
    pub profiles: Vec<PathBuf>,
    pub entries: u64,
    pub limit_hit: bool,
    pub cancelled: bool,
    pub unreadable_roots: Vec<PathBuf>,
}

/// A folder that holds `Launcher/nikke_launcher.exe` or `Launcher/intl_service/debug.log`.
pub fn is_install(dir: &Path) -> bool {
    path_ci(dir, "Launcher/nikke_launcher.exe").is_some_and(|p| p.is_file())
        || path_ci(dir, "Launcher/intl_service/debug.log").is_some_and(|p| p.is_file())
}

/// A recorded path may name the install, its Launcher folder or the launcher exe.
pub fn install_from_recorded(p: &Path) -> Option<PathBuf> {
    let mut cur = Some(p);
    for _ in 0..3 {
        let c = cur?;
        if c.is_dir() && is_install(c) {
            return Some(c.to_path_buf());
        }
        cur = c.parent();
    }
    None
}

fn is_profile_name_skipped(name: &str) -> bool {
    ["public", "default", "default user", "all users"].iter().any(|s| eq_ci(name, s))
}

#[derive(Default)]
struct Set(BTreeMap<String, PathBuf>);

impl Set {
    fn add(&mut self, p: PathBuf) {
        // `C:\a/b` and `C:\a\b` are the same folder on Windows.
        let key = p
            .to_string_lossy()
            .to_lowercase()
            .replace('\\', "/")
            .trim_end_matches('/')
            .to_string();
        self.0.entry(key).or_insert(p);
    }
    fn into_vec(self) -> Vec<PathBuf> {
        self.0.into_values().collect()
    }
}

pub fn locate(env: &Env, mode: Mode, folders: &[PathBuf], cancel: &AtomicBool, progress: &dyn Fn(u64, &Path)) -> Located {
    let mut installs = Set::default();
    let mut data = Set::default();
    let mut profiles = Set::default();
    let mut out = Located::default();

    let computer = mode != Mode::Folder;
    if computer {
        if let Some(p) = &env.profile {
            profiles.add(p.clone());
        }
        if let Some(a) = &env.appdata {
            for d in iocs::LAUNCHER_DATA_DIRS {
                if let Some(p) = path_ci(a, d).filter(|p| p.is_dir()) {
                    data.add(p);
                }
            }
        }
        for r in env.system.recorded_installs() {
            if let Some(i) = install_from_recorded(&r) {
                installs.add(i);
            }
        }
    }

    let roots: Vec<PathBuf> = if computer { env.roots.clone() } else { folders.to_vec() };
    let depth = if mode == Mode::Quick { QUICK_DEPTH } else { usize::MAX };
    let norm = |p: &Path| {
        p.to_string_lossy()
            .to_lowercase()
            .replace('\\', "/")
            .trim_end_matches('/')
            .to_string()
    };
    let skip: Vec<String> = env.skip.iter().map(|p| norm(p)).collect();

    'roots: for root in &roots {
        if std::fs::read_dir(root).is_err() {
            out.unreadable_roots.push(root.clone());
            continue;
        }
        // A folder scan of an install or a launcher data folder itself.
        if is_install(root) {
            installs.add(root.clone());
        }
        let walk = WalkDir::new(root)
            .max_depth(depth)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                if !e.file_type().is_dir() || e.depth() == 0 {
                    return true;
                }
                let name = e.file_name().to_string_lossy().to_lowercase();
                if iocs::SKIP_DIRS.contains(&name.as_str()) {
                    return false;
                }
                !skip.contains(&norm(e.path()))
            });
        for entry in walk {
            if cancel.load(Ordering::Relaxed) {
                out.cancelled = true;
                break 'roots;
            }
            let Ok(e) = entry else { continue };
            out.entries += 1;
            if out.entries % 20_000 == 0 {
                progress(out.entries, e.path());
            }
            if out.entries >= ENTRY_LIMIT {
                out.limit_hit = true;
                break 'roots;
            }
            let name = e.file_name().to_string_lossy();
            let parent = e.path().parent();
            let parent_name = parent.map(name_of).unwrap_or_default();
            if e.file_type().is_file() {
                if eq_ci(&name, iocs::LAUNCHER_EXE) && eq_ci(&parent_name, "Launcher") {
                    if let Some(i) = parent.and_then(Path::parent) {
                        installs.add(i.to_path_buf());
                    }
                } else if eq_ci(&name, "debug.log") && eq_ci(&parent_name, "intl_service") {
                    if let Some(l) = parent.and_then(Path::parent) {
                        if eq_ci(&name_of(l), "Launcher") {
                            if let Some(i) = l.parent() {
                                installs.add(i.to_path_buf());
                            }
                        }
                    }
                }
            } else if e.file_type().is_dir() {
                if iocs::LAUNCHER_DATA_DIRS.iter().any(|d| eq_ci(&name, d)) && eq_ci(&parent_name, "Roaming") {
                    data.add(e.path().to_path_buf());
                } else if eq_ci(&name, "AppData") {
                    if let Some(user) = parent {
                        let has = path_ci(e.path(), "Local").is_some() || path_ci(e.path(), "Roaming").is_some();
                        if has && !is_profile_name_skipped(&name_of(user)) {
                            profiles.add(user.to_path_buf());
                        }
                    }
                }
            }
        }
    }

    out.installs = installs.into_vec();
    out.launcher_data = data.into_vec();
    out.profiles = profiles.into_vec();
    out
}
