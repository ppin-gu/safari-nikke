//! Windows: registry, process list, loaded modules and drives. Read-only.

use std::path::PathBuf;

use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY};
use winreg::RegKey;

use crate::env::{ClsidValue, LoadedModule, Proc, System};
use crate::iocs;

pub struct WinSystem;

const UNINSTALL: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\nikke_launcher";

fn open(hive: winreg::HKEY, path: &str, view: u32) -> Option<RegKey> {
    RegKey::predef(hive).open_subkey_with_flags(path, KEY_READ | view).ok()
}

impl System for WinSystem {
    fn clsid(&self) -> Vec<ClsidValue> {
        let mut out = Vec::new();
        for (view, flag) in [("64-bit", KEY_WOW64_64KEY), ("32-bit", KEY_WOW64_32KEY)] {
            if open(HKEY_CURRENT_USER, iocs::CLSID_KEY, flag).is_none() {
                continue;
            }
            let value = open(HKEY_CURRENT_USER, &format!(r"{}\InprocServer32", iocs::CLSID_KEY), flag)
                .and_then(|k| k.get_value::<String, _>("").ok());
            let v = ClsidValue { view, value };
            // Both views can map to the same key on 64-bit Windows for HKCU\Software\Classes.
            if !out.iter().any(|o: &ClsidValue| o.value == v.value) {
                out.push(v);
            }
        }
        out
    }

    fn recorded_installs(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let places = [
            (HKEY_CURRENT_USER, KEY_WOW64_64KEY),
            (HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY),
            (HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY),
        ];
        for (hive, view) in places {
            if let Some(k) = open(hive, UNINSTALL, view) {
                for name in ["GameInstallPath", "InstallLocation", "InstallPath"] {
                    if let Ok(v) = k.get_value::<String, _>(name) {
                        out.push(PathBuf::from(clean(&v)));
                    }
                }
            }
        }
        if let Some(k) = open(HKEY_CURRENT_USER, r"Software\Classes\nikkelauncher\DefaultIcon", KEY_WOW64_64KEY) {
            if let Ok(v) = k.get_value::<String, _>("") {
                out.push(PathBuf::from(clean(&v)));
            }
        }
        out
    }

    fn processes(&self) -> Vec<Proc> {
        processes()
    }

    fn peh_modules(&self) -> Vec<LoadedModule> {
        let mut out = Vec::new();
        for p in processes() {
            for path in modules(p.pid) {
                if path.to_ascii_lowercase().contains(&iocs::PEH_DIR.to_ascii_lowercase())
                    && path.to_ascii_lowercase().ends_with(iocs::PEH_DLL)
                {
                    out.push(LoadedModule {
                        pid: p.pid,
                        process: p.name.clone(),
                        path,
                    });
                }
            }
        }
        out
    }
}

/// `"C:\NIKKE\Launcher\nikke_launcher.exe",0` -> `C:\NIKKE\Launcher\nikke_launcher.exe`
fn clean(v: &str) -> String {
    let v = v.trim();
    let v = if let Some(rest) = v.strip_prefix('"') {
        rest.split('"').next().unwrap_or(rest)
    } else {
        v
    };
    let v = match v.rfind(',') {
        Some(i) if v[i + 1..].trim().parse::<i32>().is_ok() => &v[..i],
        _ => v,
    };
    v.trim().to_string()
}

fn wide_to_string(w: &[u16]) -> String {
    let n = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..n])
}

fn processes() -> Vec<Proc> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    let mut out = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut e) != 0 {
            loop {
                out.push(Proc {
                    pid: e.th32ProcessID,
                    name: wide_to_string(&e.szExeFile),
                });
                if Process32NextW(snap, &mut e) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    out
}

fn modules(pid: u32) -> Vec<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
    };
    let mut out = Vec::new();
    if pid == 0 || pid == 4 {
        return out;
    }
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut e: MODULEENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
        if Module32FirstW(snap, &mut e) != 0 {
            loop {
                out.push(wide_to_string(&e.szExePath));
                if Module32NextW(snap, &mut e) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    out
}

/// Fixed and removable drives. Network and optical drives are left out.
pub fn local_drives() -> Vec<PathBuf> {
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
    use windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode;
    const DRIVE_REMOVABLE: u32 = 2;
    const DRIVE_FIXED: u32 = 3;
    let mut out = Vec::new();
    unsafe {
        // No "There is no disk in the drive" boxes (SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX).
        SetErrorMode(0x0001 | 0x8000);
        let mask = GetLogicalDrives();
        for i in 0..26u32 {
            if mask & (1 << i) == 0 {
                continue;
            }
            let letter = (b'A' + i as u8) as char;
            let root = format!("{letter}:\\");
            let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
            let t = GetDriveTypeW(wide.as_ptr());
            if t == DRIVE_FIXED || t == DRIVE_REMOVABLE {
                out.push(PathBuf::from(root));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::clean;

    #[test]
    fn cleans_icon_values() {
        assert_eq!(
            clean(r#""C:\NIKKE\Launcher\nikke_launcher.exe",0"#),
            r"C:\NIKKE\Launcher\nikke_launcher.exe"
        );
        assert_eq!(clean(r"D:\Games\NIKKE"), r"D:\Games\NIKKE");
        assert_eq!(clean(r"D:\a,b\NIKKE"), r"D:\a,b\NIKKE");
    }
}
