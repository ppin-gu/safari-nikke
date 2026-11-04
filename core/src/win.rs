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

// ---------- Changes (remedy only) ----------

pub struct WinOps;

impl crate::remedy::Ops for WinOps {
    fn kill(&self, pid: u32) -> Result<(), String> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_TERMINATE};
        const SYNCHRONIZE: u32 = 0x0010_0000;
        unsafe {
            let h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, 0, pid);
            if h.is_null() {
                return Err(format!("프로세스 열기 실패 (오류 {})", std::io::Error::last_os_error()));
            }
            let ok = TerminateProcess(h, 1) != 0;
            if ok {
                WaitForSingleObject(h, 5000);
            }
            CloseHandle(h);
            if ok {
                Ok(())
            } else {
                Err(format!("종료 실패 ({})", std::io::Error::last_os_error()))
            }
        }
    }

    fn delete_clsid(&self) -> Result<(), String> {
        use winreg::enums::KEY_ALL_ACCESS;
        let mut err = None;
        for flag in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
            let Ok(parent) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(r"Software\Classes\CLSID", KEY_ALL_ACCESS | flag)
            else {
                continue;
            };
            if let Err(e) = parent.delete_subkey_all(iocs::CLSID) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    err = Some(format!("삭제 실패: {e}"));
                }
            }
        }
        err.map_or(Ok(()), Err)
    }

    fn block(&self) -> Result<Vec<String>, String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let out = std::env::temp_dir().join(format!("sng-block-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&out);
        let code = run_elevated(&exe, &format!("--apply-block \"{}\"", out.display()))?;
        let text = std::fs::read_to_string(&out).map_err(|_| format!("차단 작업 결과 없음 (종료 코드 {code})"))?;
        let _ = std::fs::remove_file(&out);
        let r: Result<Vec<String>, String> = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        r
    }
}

/// Starts `exe args` with a UAC prompt, waits for it and returns its exit code.
pub fn run_elevated(exe: &std::path::Path, args: &str) -> Result<u32, String> {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    let w = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let verb = w("runas");
    let file = w(&exe.display().to_string());
    let params = w(args);
    unsafe {
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = params.as_ptr();
        info.nShow = 0;
        if ShellExecuteExW(&mut info) == 0 {
            let e = GetLastError();
            return Err(if e == 1223 {
                "관리자 권한 요청 취소됨".into()
            } else {
                format!("관리자 권한 실행 실패 (오류 {e})")
            });
        }
        if info.hProcess.is_null() {
            return Err("관리자 권한 실행 실패".into());
        }
        WaitForSingleObject(info.hProcess, INFINITE);
        let mut code = 0u32;
        GetExitCodeProcess(info.hProcess, &mut code);
        CloseHandle(info.hProcess);
        Ok(code)
    }
}

/// The elevated child: hosts lines and outbound firewall rules for the attacker's IPs.
/// Writes `Ok(lines)` or `Err(message)` as JSON to `out`.
pub fn block_child(out: &std::path::Path) -> i32 {
    let hosts = std::env::var_os("SystemRoot")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"))
        .join(r"System32\drivers\etc\hosts");
    let mut done = Vec::new();
    let mut result: Result<Vec<String>, String> = match crate::remedy::add_hosts_lines(&hosts) {
        Ok(lines) => {
            done.extend(lines.into_iter().map(|l| format!("hosts: {l}")));
            Ok(Vec::new())
        }
        Err(e) => Err(e),
    };
    if result.is_ok() {
        for ip in iocs::BLOCK_IPS {
            let name = format!("Safari NIKKE Guard block {ip}");
            let exists = std::process::Command::new("netsh")
                .args(["advfirewall", "firewall", "show", "rule", &format!("name={name}")])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if exists {
                continue;
            }
            let ok = std::process::Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &format!("name={name}"),
                    "dir=out",
                    "action=block",
                    &format!("remoteip={ip}"),
                ])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if ok {
                done.push(format!("방화벽: {ip}"));
            } else {
                result = Err(format!("방화벽 규칙 등록 실패: {ip}"));
                break;
            }
        }
    }
    let result = result.map(|_| done);
    let code = if result.is_ok() { 0 } else { 1 };
    let _ = std::fs::write(out, serde_json::to_string(&result).unwrap_or_default());
    code
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
