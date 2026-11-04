//! Everything the scan reads from the system that is not a plain file: the
//! user folders, the drives, the registry and the process list. Tests build an
//! `Env` over temporary folders with fake registry and process data.

use std::path::PathBuf;

/// One value of the HKCU CLSID key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClsidValue {
    /// "64-bit" or "32-bit"
    pub view: &'static str,
    /// The key exists; `value` is its InprocServer32 default value (None or empty: leftover).
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proc {
    pub pid: u32,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedModule {
    pub pid: u32,
    pub process: String,
    pub path: String,
}

pub trait System: Send + Sync {
    /// The CLSID key in each registry view where it exists.
    fn clsid(&self) -> Vec<ClsidValue>;
    /// Install paths the launcher records in the registry.
    fn recorded_installs(&self) -> Vec<PathBuf>;
    fn processes(&self) -> Vec<Proc>;
    /// Modules of running processes whose path contains `PlatformExperienceHelper`.
    fn peh_modules(&self) -> Vec<LoadedModule>;
}

/// A system with nothing in the registry and no processes.
#[derive(Default)]
pub struct NoSystem;

impl System for NoSystem {
    fn clsid(&self) -> Vec<ClsidValue> {
        Vec::new()
    }
    fn recorded_installs(&self) -> Vec<PathBuf> {
        Vec::new()
    }
    fn processes(&self) -> Vec<Proc> {
        Vec::new()
    }
    fn peh_modules(&self) -> Vec<LoadedModule> {
        Vec::new()
    }
}

pub struct Env {
    /// The current user's profile (%USERPROFILE%).
    pub profile: Option<PathBuf>,
    /// %APPDATA%
    pub appdata: Option<PathBuf>,
    /// %TEMP%
    pub temp: Option<PathBuf>,
    /// Drive roots a computer scan walks.
    pub roots: Vec<PathBuf>,
    /// Folders under a root that a walk skips (C:\Windows).
    pub skip: Vec<PathBuf>,
    pub hosts: PathBuf,
    pub computer_name: Option<String>,
    pub user_name: Option<String>,
    pub system: Box<dyn System>,
}

impl Env {
    /// The real computer.
    pub fn current() -> Env {
        let var = |k: &str| std::env::var_os(k).map(PathBuf::from);
        let windir = var("SystemRoot")
            .or_else(|| var("windir"))
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        Env {
            profile: var("USERPROFILE").or_else(|| var("HOME")),
            appdata: var("APPDATA"),
            temp: var("TEMP").or_else(|| var("TMP")),
            roots: drives(),
            skip: vec![windir.clone()],
            hosts: if cfg!(windows) {
                windir.join(r"System32\drivers\etc\hosts")
            } else {
                PathBuf::from("/etc/hosts")
            },
            computer_name: std::env::var("COMPUTERNAME").ok(),
            user_name: std::env::var("USERNAME").or_else(|_| std::env::var("USER")).ok(),
            system: system(),
        }
    }
}

#[cfg(windows)]
fn system() -> Box<dyn System> {
    Box::new(crate::win::WinSystem)
}

#[cfg(not(windows))]
fn system() -> Box<dyn System> {
    Box::new(NoSystem)
}

#[cfg(windows)]
fn drives() -> Vec<PathBuf> {
    crate::win::local_drives()
}

#[cfg(not(windows))]
fn drives() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(h) = std::env::var_os("HOME") {
        v.push(PathBuf::from(h));
    }
    v
}
