//! Remedy tests on a fake infected computer.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use sng_core::env::{ClsidValue, Env, LoadedModule, Proc, System};
use sng_core::model::Mode;
use sng_core::remedy::{self, ActionKind, Ops, Status};
use sng_core::{report, scan};

static N: AtomicU32 = AtomicU32::new(0);

#[derive(Default)]
struct State {
    clsid: Vec<ClsidValue>,
    procs: Vec<Proc>,
    modules: Vec<LoadedModule>,
    killed: Vec<u32>,
}

#[derive(Clone, Default)]
struct Fake(Arc<Mutex<State>>);

impl System for Fake {
    fn clsid(&self) -> Vec<ClsidValue> {
        self.0.lock().unwrap().clsid.clone()
    }
    fn recorded_installs(&self) -> Vec<PathBuf> {
        Vec::new()
    }
    fn processes(&self) -> Vec<Proc> {
        self.0.lock().unwrap().procs.clone()
    }
    fn peh_modules(&self) -> Vec<LoadedModule> {
        self.0.lock().unwrap().modules.clone()
    }
}

impl Ops for Fake {
    fn kill(&self, pid: u32) -> Result<(), String> {
        let mut s = self.0.lock().unwrap();
        s.procs.retain(|p| p.pid != pid);
        s.killed.push(pid);
        Ok(())
    }
    fn delete_clsid(&self) -> Result<(), String> {
        self.0.lock().unwrap().clsid.clear();
        Ok(())
    }
    fn block(&self) -> Result<Vec<String>, String> {
        Ok(vec!["hosts: 0.0.0.0 insightjs.com".into()])
    }
}

struct Fx {
    root: PathBuf,
    fake: Fake,
    hash: String,
}

impl Fx {
    fn new() -> Fx {
        let n = N.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("sng-remedy-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let hash = "ab".repeat(32);
        let f = |rel: &str, data: &[u8]| {
            let p = root.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, data).unwrap();
        };
        f("drive/NIKKE/Launcher/nikke_launcher.exe", b"MZ");
        f(
            "drive/NIKKE/Launcher/intl_service/debug.log",
            b"[2026-10-25 21:14:03.100][9] k2f_chan registered\n",
        );
        f(
            "drive/Users/Bob/AppData/Roaming/nikke_launcher/tbs_cache/Local Storage/leveldb/000005.log",
            b"k2f.agent.state{}",
        );
        f(
            &format!(
                "drive/Users/Bob/AppData/Local/Google/Chrome/User Data/PlatformExperienceHelper/{hash}/platform_experience_helper.dll"
            ),
            b"MZdll",
        );
        f("drive/Users/Bob/AppData/Local/Temp/k2f-bcreds-1.json", b"{}");
        f("drive/Users/Bob/AppData/Local/Temp/keep-me.txt", b"x");
        f("drive/Users/Bob/Desktop/.keep", b"");
        let fake = Fake::default();
        fake.0.lock().unwrap().clsid = vec![ClsidValue {
            view: "64-bit",
            value: Some(r"C:\x\platform_experience_helper.dll".into()),
        }];
        fake.0.lock().unwrap().procs = vec![
            Proc {
                pid: 4242,
                name: "nikke_launcher.exe".into(),
            },
            Proc {
                pid: 1,
                name: "explorer.exe".into(),
            },
        ];
        Fx { root, fake, hash }
    }
    fn env(&self) -> Env {
        let p = |r: &str| self.root.join(r);
        Env {
            profile: Some(p("drive/Users/Bob")),
            appdata: Some(p("drive/Users/Bob/AppData/Roaming")),
            temp: Some(p("drive/Users/Bob/AppData/Local/Temp")),
            roots: vec![p("drive")],
            skip: vec![],
            hosts: p("hosts"),
            computer_name: None,
            user_name: None,
            system: Box::new(self.fake.clone()),
        }
    }
    fn dll_dir(&self) -> PathBuf {
        self.root.join(format!(
            "drive/Users/Bob/AppData/Local/Google/Chrome/User Data/PlatformExperienceHelper/{}",
            self.hash
        ))
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn scan_it(env: &Env) -> sng_core::model::ScanResult {
    scan(env, Mode::Quick, &[], &AtomicBool::new(false), &|_, _, _: &Path| {})
}

#[test]
fn plan_lists_actions_in_order() {
    let fx = Fx::new();
    let env = fx.env();
    let r = scan_it(&env);
    let kinds: Vec<ActionKind> = remedy::plan(&r).iter().map(|a| a.kind).collect();
    assert_eq!(
        kinds,
        [
            ActionKind::KillLauncher,
            ActionKind::DeleteRegistry,
            ActionKind::DeleteDllFolder,
            ActionKind::DeleteTempFiles,
            ActionKind::DeleteCache,
            ActionKind::Block
        ]
    );
    assert!(remedy::plan(&r).iter().all(|a| a.recommended));
}

#[test]
fn apply_all_cleans_and_backs_up() {
    let fx = Fx::new();
    let env = fx.env();
    let r = scan_it(&env);
    let plan = remedy::plan(&r);
    let text = report::text(&r);
    let desk = fx.root.join("drive/Users/Bob/Desktop");
    let res = remedy::apply(&env, &fx.fake, &r, &text, &plan, Some(&desk));

    let st: Vec<(ActionKind, Status)> = plan.iter().map(|a| a.kind).zip(res.outcomes.iter().map(|o| o.status)).collect();
    assert!(st.iter().all(|(_, s)| *s == Status::Done), "{:#?}", res.outcomes);
    assert_eq!(fx.fake.0.lock().unwrap().killed, [4242]);
    assert!(fx.fake.0.lock().unwrap().clsid.is_empty());
    assert!(!fx.dll_dir().exists());
    assert!(!fx.root.join("drive/Users/Bob/AppData/Roaming/nikke_launcher/tbs_cache").exists());
    let temp = fx.root.join("drive/Users/Bob/AppData/Local/Temp");
    assert!(!temp.join("k2f-bcreds-1.json").exists());
    assert!(temp.join("keep-me.txt").exists(), "only k2f files are deleted");

    // Backup: report, log evidence, DLL hash listing; no DLL or credential copies.
    let b = PathBuf::from(res.backup.unwrap());
    assert!(b.join("report.txt").is_file());
    let ev: Vec<String> = fs::read_dir(b.join("evidence"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(ev.iter().any(|n| n.ends_with("debug.log")), "{ev:?}");
    assert!(ev.iter().any(|n| n.ends_with("000005.log")), "{ev:?}");
    assert!(!ev
        .iter()
        .any(|n| n.contains("platform_experience_helper") || n.contains("k2f-bcreds")));
    let files = fs::read_to_string(b.join("files.txt")).unwrap();
    assert!(files.contains("platform_experience_helper.dll"));
    assert!(res.pending.is_empty());
}

#[test]
fn loaded_dll_waits_for_restart() {
    let fx = Fx::new();
    fx.fake.0.lock().unwrap().modules = vec![LoadedModule {
        pid: 7,
        process: "chrome.exe".into(),
        path: "x".into(),
    }];
    let env = fx.env();
    let r = scan_it(&env);
    let sel: Vec<_> = remedy::plan(&r)
        .into_iter()
        .filter(|a| matches!(a.kind, ActionKind::DeleteRegistry | ActionKind::DeleteDllFolder))
        .collect();
    let res = remedy::apply(&env, &fx.fake, &r, "", &sel, None);
    assert_eq!(res.outcomes[0].status, Status::Done);
    assert_eq!(res.outcomes[1].status, Status::PendingReboot);
    assert!(fx.dll_dir().exists());

    // Saved, reloaded after the "restart", then deleted.
    let file = fx.root.join("pending.json");
    remedy::save_pending(&file, &res.pending).unwrap();
    fx.fake.0.lock().unwrap().modules.clear();
    let pending = remedy::load_pending(&file);
    assert_eq!(pending.len(), 1);
    let again = remedy::apply_pending(&env, &fx.fake, &pending);
    assert_eq!(again.outcomes[0].status, Status::Done);
    assert!(!fx.dll_dir().exists());
    remedy::save_pending(&file, &again.pending).unwrap();
    assert!(!file.exists());
}

#[test]
fn dll_refused_while_registry_points_to_it() {
    let fx = Fx::new();
    let env = fx.env();
    let r = scan_it(&env);
    let sel: Vec<_> = remedy::plan(&r)
        .into_iter()
        .filter(|a| a.kind == ActionKind::DeleteDllFolder)
        .collect();
    let res = remedy::apply(&env, &fx.fake, &r, "", &sel, None);
    assert_eq!(res.outcomes[0].status, Status::Failed);
    assert!(fx.dll_dir().exists());
}

#[test]
fn cache_refused_while_launcher_runs() {
    let fx = Fx::new();
    let env = fx.env();
    let r = scan_it(&env);
    let sel: Vec<_> = remedy::plan(&r).into_iter().filter(|a| a.kind == ActionKind::DeleteCache).collect();
    let res = remedy::apply(&env, &fx.fake, &r, "", &sel, None);
    assert_eq!(res.outcomes[0].status, Status::Failed);
}

#[test]
fn edited_targets_are_refused() {
    let fx = Fx::new();
    let env = fx.env();
    let r = scan_it(&env);
    let mut sel: Vec<_> = remedy::plan(&r).into_iter().filter(|a| a.kind == ActionKind::DeleteCache).collect();
    let victim = fx.root.join("drive/Users/Bob/Desktop");
    sel[0].target = victim.display().to_string();
    fx.fake.0.lock().unwrap().procs.clear();
    let res = remedy::apply(&env, &fx.fake, &r, "", &sel, None);
    assert_eq!(res.outcomes[0].status, Status::Failed);
    assert!(victim.exists());

    // A pending file pointing elsewhere is dropped on load.
    let file = fx.root.join("pending.json");
    let mut bad = remedy::plan(&r)
        .into_iter()
        .find(|a| a.kind == ActionKind::DeleteDllFolder)
        .unwrap();
    bad.target = victim.display().to_string();
    remedy::save_pending(&file, &[bad]).unwrap();
    assert!(remedy::load_pending(&file).is_empty());
}

#[test]
fn hosts_lines_are_appended_once() {
    let fx = Fx::new();
    let hosts = fx.root.join("hosts");
    fs::write(&hosts, "127.0.0.1 localhost\n0.0.0.0 insightjs.com").unwrap();
    let added = remedy::add_hosts_lines(&hosts).unwrap();
    assert_eq!(added, ["0.0.0.0 analytics.insightjs.com", "0.0.0.0 insightjs.org"]);
    let text = fs::read_to_string(&hosts).unwrap();
    assert!(text.starts_with("127.0.0.1 localhost\n0.0.0.0 insightjs.com\r\n# Safari NIKKE Guard"));
    assert!(remedy::add_hosts_lines(&hosts).unwrap().is_empty());
}
