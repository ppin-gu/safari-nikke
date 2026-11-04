//! Safari NIKKE Guard window. The scan itself is in `sng-core` and only reads.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use sng_core::model::{Mode, ScanResult};
use sng_core::{report, Env};
use tauri::{AppHandle, Emitter, State};
use tauri_plugin_dialog::DialogExt;

#[derive(Default)]
struct App {
    last: Mutex<Option<ScanResult>>,
    cancel: Arc<AtomicBool>,
}

#[derive(Clone, Serialize)]
struct Progress {
    phase: String,
    entries: u64,
    path: String,
}

#[tauri::command]
async fn scan(app: AppHandle, state: State<'_, App>, mode: String, folder: Option<String>) -> Result<ScanResult, String> {
    let mode = match mode.as_str() {
        "full" => Mode::Full,
        "folder" => Mode::Folder,
        _ => Mode::Quick,
    };
    let folders: Vec<PathBuf> = folder.into_iter().map(PathBuf::from).collect();
    if mode == Mode::Folder && folders.is_empty() {
        return Err("폴더 미선택".into());
    }
    state.cancel.store(false, Ordering::SeqCst);
    let cancel = state.cancel.clone();
    let handle = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let env = Env::current();
        sng_core::scan(&env, mode, &folders, &cancel, &|phase, entries, path| {
            let _ = handle.emit(
                "scan-progress",
                Progress {
                    phase: phase.to_string(),
                    entries,
                    path: path.display().to_string(),
                },
            );
        })
    })
    .await
    .map_err(|e| format!("검사 오류: {e}"))?;
    *state.last.lock().unwrap() = Some(result.clone());
    Ok(result)
}

#[tauri::command]
fn cancel_scan(state: State<'_, App>) {
    state.cancel.store(true, Ordering::SeqCst);
}

#[tauri::command]
async fn pick_folder(app: AppHandle) -> Option<String> {
    let picked = app.dialog().file().set_title("NIKKE 설치 폴더 선택").blocking_pick_folder()?;
    picked.into_path().ok().map(|p| p.display().to_string())
}

fn report_of(state: &State<'_, App>, redact: bool) -> Option<String> {
    let last = state.last.lock().unwrap();
    let r = last.as_ref()?;
    let text = report::text(r);
    Some(if redact {
        report::Redact::from_env(&Env::current()).apply(&text)
    } else {
        text
    })
}

#[tauri::command]
fn report_text(state: State<'_, App>, redact: bool) -> Option<String> {
    report_of(&state, redact)
}

#[tauri::command]
async fn save_report(app: AppHandle, state: State<'_, App>, redact: bool) -> Result<Option<String>, String> {
    let Some(text) = report_of(&state, redact) else { return Ok(None) };
    let name = format!(
        "니케점검결과_{}.txt",
        sng_core::util::fmt_utc(sng_core::util::now()).replace([' ', ':'], "-")
    );
    let Some(path) = app
        .dialog()
        .file()
        .set_title("리포트 저장")
        .set_file_name(name)
        .add_filter("텍스트", &["txt"])
        .blocking_save_file()
    else {
        return Ok(None);
    };
    let path = path.into_path().map_err(|e| e.to_string())?;
    // UTF-8 with BOM so Notepad on older Windows reads Korean correctly.
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(text.replace('\n', "\r\n").as_bytes());
    std::fs::write(&path, bytes).map_err(|e| format!("저장 실패: {e}"))?;
    Ok(Some(path.display().to_string()))
}

#[tauri::command]
fn qr_svg(text: String) -> Result<String, String> {
    use qrcode::render::svg;
    let code = qrcode::QrCode::new(text.as_bytes()).map_err(|e| e.to_string())?;
    Ok(code
        .render::<svg::Color>()
        .min_dimensions(148, 148)
        .dark_color(svg::Color("#17202b"))
        .light_color(svg::Color("#ffffff"))
        .build())
}

/// Show a file or folder in Explorer. Never opens or runs the file itself.
#[tauri::command]
fn reveal(path: String) -> Result<(), String> {
    let p = PathBuf::from(&path);
    if !p.exists() {
        return Err("경로 없음".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let windir = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        std::process::Command::new(windir.join("explorer.exe"))
            .raw_arg(format!("/select,\"{}\"", path))
            .spawn()
            .map(drop)
            .map_err(|e| e.to_string())
    }
    #[cfg(not(windows))]
    {
        Err("Windows 전용".into())
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(App::default())
        .invoke_handler(tauri::generate_handler![
            scan,
            cancel_scan,
            pick_folder,
            report_text,
            save_report,
            qr_svg,
            reveal
        ])
        .run(tauri::generate_context!())
        .expect("Safari NIKKE Guard 실행 실패");
}
