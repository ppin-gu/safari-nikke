//! Fixture tests: fake installs, launcher data and profiles in a temp folder.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use sng_core::env::{ClsidValue, Env, LoadedModule, Proc, System};
use sng_core::model::{Kind, Mode, ScanResult, Severity, Verdict};
use sng_core::{report, scan};

static N: AtomicU32 = AtomicU32::new(0);

struct Fx(PathBuf);

impl Fx {
    fn new(tag: &str) -> Fx {
        let n = N.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("sng-test-{}-{tag}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        Fx(p)
    }
    fn file(&self, rel: &str, data: &[u8]) -> PathBuf {
        let p = self.0.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, data).unwrap();
        p
    }
    fn dir(&self, rel: &str) -> PathBuf {
        let p = self.0.join(rel);
        fs::create_dir_all(&p).unwrap();
        p
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct FakeSystem {
    clsid: Vec<ClsidValue>,
    procs: Vec<Proc>,
    modules: Vec<LoadedModule>,
    recorded: Vec<PathBuf>,
}

impl System for FakeSystem {
    fn clsid(&self) -> Vec<ClsidValue> {
        self.clsid.clone()
    }
    fn recorded_installs(&self) -> Vec<PathBuf> {
        self.recorded.clone()
    }
    fn processes(&self) -> Vec<Proc> {
        self.procs.clone()
    }
    fn peh_modules(&self) -> Vec<LoadedModule> {
        self.modules.clone()
    }
}

/// A computer with one drive (`drive`) and one user (`drive/Users/Bob`).
fn env(fx: &Fx, sys: FakeSystem) -> Env {
    let profile = fx.dir("drive/Users/Bob");
    fx.dir("drive/Users/Bob/AppData/Local");
    let appdata = fx.dir("drive/Users/Bob/AppData/Roaming");
    Env {
        profile: Some(profile),
        appdata: Some(appdata),
        temp: Some(fx.dir("drive/Users/Bob/AppData/Local/Temp")),
        roots: vec![fx.0.join("drive")],
        skip: vec![fx.0.join("drive/Windows")],
        hosts: fx.0.join("drive/Windows/System32/drivers/etc/hosts"),
        computer_name: Some("DESKTOP-BOB".into()),
        user_name: Some("Bob".into()),
        system: Box::new(sys),
    }
}

fn run(env: &Env, mode: Mode, folders: &[PathBuf]) -> ScanResult {
    scan(env, mode, folders, &AtomicBool::new(false), &|_, _, _: &Path| {})
}

fn kinds(r: &ScanResult) -> Vec<Kind> {
    r.findings.iter().filter(|f| f.severity > Severity::Info).map(|f| f.kind).collect()
}

const INSTALL: &str = "drive/Games/Level Infinite/NIKKE";

#[test]
fn no_nikke() {
    let fx = Fx::new("none");
    let e = env(&fx, FakeSystem::default());
    let r = run(&e, Mode::Quick, &[]);
    assert_eq!(r.verdict, Verdict::NotFound);
    assert!(r.installs.is_empty());
    assert_eq!(r.steps[0].title, "다시 검사");
}

#[test]
fn clean_install() {
    let fx = Fx::new("clean");
    fx.file(&format!("{INSTALL}/Launcher/nikke_launcher.exe"), b"MZ");
    fx.file(
        &format!("{INSTALL}/Launcher/intl_service/debug.log"),
        b"[2026-10-01 10:00:00.000][1][INFO] start\n",
    );
    fx.file(
        "drive/Users/Bob/AppData/Roaming/nikke_launcher/tbs_cache/Local Storage/leveldb/000003.log",
        b"normal",
    );
    let e = env(&fx, FakeSystem::default());
    let r = run(&e, Mode::Quick, &[]);
    assert_eq!(r.verdict, Verdict::Clean, "{:#?}", r.findings);
    assert_eq!(r.installs.len(), 1);
    assert_eq!(r.launcher_data.len(), 1);
    assert_eq!(r.steps[0].title, "런처 캐시 삭제");
}

#[test]
fn exposed_by_loader_cache() {
    let fx = Fx::new("exposed");
    fx.file(&format!("{INSTALL}/Launcher/nikke_launcher.exe"), b"MZ");
    fx.file(
        "drive/Users/Bob/AppData/Roaming/nikke_launcher/tbs_cache/Code Cache/js/aa_0",
        b"\x00\x01https://insightjs.com/l.js?f=aegis\x00",
    );
    fx.file(
        "drive/Users/Bob/AppData/Roaming/nikke_launcher/tbs_cache/Network Persistent State",
        br#"{"net":{"http_server_properties":{"servers":[{"server":"https://insightjs.com"}]}}}"#,
    );
    let e = env(&fx, FakeSystem::default());
    let r = run(&e, Mode::Quick, &[]);
    assert_eq!(r.verdict, Verdict::Exposed, "{:#?}", r.findings);
    assert!(kinds(&r).contains(&Kind::ScriptCache));
    assert!(kinds(&r).contains(&Kind::Network));
}

#[test]
fn infected_full_set() {
    let fx = Fx::new("infected");
    fx.file(&format!("{INSTALL}/Launcher/nikke_launcher.exe"), b"MZ");
    fx.file(
        &format!("{INSTALL}/Launcher/intl_service/debug.log"),
        b"[2026-10-25 21:14:02.001][9][INFO] lua downloaded to log\\tinyget\\tinyget.20261025-211401-000.log\n\
          [2026-10-25 21:14:03.100][9][INFO] k2f_chan registered\n\
          [2026-10-25 21:14:03.200][9][INFO] k2f adopted 3c4c9b75-09e5-4619-99ee-97c1dc3c0373\n\
          [2026-10-25 21:14:03.300][9][INFO] k2f agent started as DESKTOP-BOB\n",
    );
    let mut agent = vec![0x1B, 0x4C, 0x4A, 0x02];
    agent.resize(205_135, 0);
    fx.file(&format!("{INSTALL}/Launcher/log/tinyget/tinyget.20261025-211401-000.log"), &agent);
    fx.file(
        &format!("{INSTALL}/Launcher/log/tinyget/tinyget.20261025-211400-999.log"),
        b"[2026-10-25 21:14:00.999][316][ERROR][tiny_downloader.cpp(103)]AddTask\tadd task, url=https://analytics.insightjs.com/comm/assets/insight.bundle, path=x\n",
    );
    fx.file(
        "drive/Users/Bob/AppData/Roaming/nikke_launcher/tbs_cache/Local Storage/leveldb/000005.log",
        br#"_https://www.nikkelauncher.com\x00k2f.agent.state{"agent_id":"3c4c9b75-09e5-4619-99ee-97c1dc3c0373","agent_pass":"s3cret-pass"}"#,
    );
    let hash = "0f".repeat(32);
    fx.file(
        &format!("drive/Users/Bob/AppData/Local/Google/Chrome/User Data/PlatformExperienceHelper/{hash}/platform_experience_helper.dll"),
        b"MZ",
    );
    fx.file(
        &format!("drive/Users/Bob/AppData/Local/Microsoft/Edge/User Data/PlatformExperienceHelper/{hash}/platform_experience_helper.dll"),
        b"MZ",
    );
    fx.file("drive/Users/Bob/AppData/Local/Temp/k2f-bcreds-1.json", b"{}");
    fx.file("drive/Users/Bob/AppData/Local/Temp/k2f_screen_1.jpg", b"");
    // Exposure
    fx.file("drive/Users/Bob/AppData/Local/Google/Chrome/User Data/Default/Login Data", b"");
    fx.dir("drive/Users/Bob/AppData/Local/Google/Chrome/User Data/Default/Extensions/nkbihfbeogaeaoehlefnkodbefgpgknn/12.0_0");
    fx.file("drive/Users/Bob/.ssh/id_ed25519", b"key");
    fx.file("drive/Users/Bob/.ssh/id_ed25519.pub", b"pub");

    let sys = FakeSystem {
        clsid: vec![ClsidValue {
            view: "64-bit",
            value: Some(format!(
                r"C:\Users\Bob\AppData\Local\Google\Chrome\User Data\PlatformExperienceHelper\{hash}\platform_experience_helper.dll"
            )),
        }],
        procs: vec![Proc {
            pid: 4242,
            name: "nikke_launcher.exe".into(),
        }],
        modules: vec![LoadedModule {
            pid: 77,
            process: "chrome.exe".into(),
            path: format!(r"C:\...\PlatformExperienceHelper\{hash}\platform_experience_helper.dll"),
        }],
        recorded: Vec::new(),
    };
    let e = env(&fx, sys);
    let r = run(&e, Mode::Quick, &[]);
    assert_eq!(r.verdict, Verdict::Infected);
    let k = kinds(&r);
    for want in [
        Kind::AgentRan,
        Kind::AgentFile,
        Kind::AgentDownload,
        Kind::AgentState,
        Kind::BrowserDll,
        Kind::Registry,
        Kind::TempFile,
        Kind::LauncherRunning,
        Kind::DllLoaded,
    ] {
        assert!(k.contains(&want), "missing {want:?} in {k:?}");
    }
    // Chrome and Edge both reported.
    assert!(r.findings.iter().any(|f| f.title == "Chrome 지속 DLL"));
    assert!(r.findings.iter().any(|f| f.title == "Edge 지속 DLL"));
    // The saved password is never quoted.
    assert!(r.findings.iter().all(|f| f.evidence.iter().all(|e| !e.contains("s3cret"))));
    // Timeline from the log lines.
    assert_eq!(r.timeline.first().unwrap().time, "2026-10-25 21:14:00");
    assert!(r.timeline.iter().any(|e| e.what == "에이전트 최초 실행"));
    // Exposure.
    assert_eq!(r.exposure.logins, vec![("Chrome".to_string(), "Default".to_string())]);
    assert_eq!(r.exposure.wallets, vec![("MetaMask".to_string(), "Chrome".to_string())]);
    assert_eq!(r.exposure.secrets.len(), 1);
    assert!(r.exposure.secrets[0].1.ends_with("id_ed25519"));
    // Steps in order, DLL removal ordered key -> restart -> folder.
    let titles: Vec<&str> = r.steps.iter().map(|s| s.title.as_str()).collect();
    assert_eq!(
        titles,
        [
            "런처 종료 · 네트워크 차단",
            "결과 저장",
            "지속 DLL 제거",
            "임시 파일 삭제",
            "런처 캐시 삭제",
            "계정 보안",
            "차단 등록 (선택)",
            "마무리"
        ]
    );
    let dll = &r.steps[2];
    assert!(dll.items[0].starts_with("1. 레지스트리"));
    assert!(dll.items[1].starts_with("2. Windows 재시작"));
    assert!(dll.items[2].starts_with("3. DLL 폴더"));
    assert!(r.steps[5].items.iter().any(|i| i.contains("MetaMask")));

    // Report and redaction.
    let text = report::text(&r);
    assert!(text.contains("판정: 악성코드 발견"));
    let red = report::Redact::from_env(&e).apply(&text);
    assert!(!red.contains("DESKTOP-BOB"));
    assert!(!red.contains("3c4c9b75"));
    assert!(!red.contains(&e.profile.as_ref().unwrap().display().to_string()));
}

#[test]
fn registry_leftover_alone_is_infected() {
    let fx = Fx::new("leftover");
    let sys = FakeSystem {
        clsid: vec![ClsidValue {
            view: "64-bit",
            value: Some(String::new()),
        }],
        ..Default::default()
    };
    let e = env(&fx, sys);
    let r = run(&e, Mode::Quick, &[]);
    assert_eq!(r.verdict, Verdict::Infected);
    assert_eq!(kinds(&r), vec![Kind::RegistryLeftover]);
}

#[test]
fn chrome_own_helper_is_normal() {
    let fx = Fx::new("chrome-own");
    fx.file(
        "drive/Users/Bob/AppData/Local/Google/Chrome/User Data/PlatformExperienceHelper/platform_experience_helper.exe",
        b"MZ",
    );
    fx.file(
        "drive/Users/Bob/AppData/Local/Google/Chrome/User Data/PlatformExperienceHelper/LoadFeatures",
        b"",
    );
    fx.file(
        "drive/Users/Bob/AppData/Local/Google/Chrome/Application/PlatformExperienceHelper/platform_experience_helper.exe",
        b"MZ",
    );
    let e = env(&fx, FakeSystem::default());
    let r = run(&e, Mode::Quick, &[]);
    assert_eq!(r.verdict, Verdict::NotFound, "{:#?}", r.findings);
}

#[test]
fn quick_scan_depth_and_full_scan() {
    let fx = Fx::new("depth");
    // 6 folders down: too deep for a quick scan.
    let deep = "drive/a/b/c/d/e/NIKKE";
    fx.file(&format!("{deep}/Launcher/nikke_launcher.exe"), b"MZ");
    let e = env(&fx, FakeSystem::default());
    assert_eq!(run(&e, Mode::Quick, &[]).verdict, Verdict::NotFound);
    assert_eq!(run(&e, Mode::Full, &[]).verdict, Verdict::Clean);
}

#[test]
fn recorded_install_on_other_drive() {
    let fx = Fx::new("recorded");
    let other = fx.file("elsewhere/NIKKE/Launcher/nikke_launcher.exe", b"MZ");
    let sys = FakeSystem {
        recorded: vec![other],
        ..Default::default()
    };
    let e = env(&fx, sys);
    let r = run(&e, Mode::Quick, &[]);
    assert_eq!(r.verdict, Verdict::Clean);
    assert!(r.installs[0].ends_with("NIKKE"));
}

#[test]
fn folder_scan() {
    let fx = Fx::new("folder");
    fx.file(
        "pick/NIKKE/Launcher/intl_service/debug.log",
        b"[2026-11-01 01:00:00.000][1] k2f_chan registered\n",
    );
    let e = env(&fx, FakeSystem::default());
    let r = run(&e, Mode::Folder, &[fx.0.join("pick")]);
    assert_eq!(r.verdict, Verdict::Infected);
    assert!(kinds(&r).contains(&Kind::AgentRan));
}

#[test]
fn hosts_blocked() {
    let fx = Fx::new("hosts");
    fx.file(&format!("{INSTALL}/Launcher/nikke_launcher.exe"), b"MZ");
    fx.file(
        "drive/Windows/System32/drivers/etc/hosts",
        b"0.0.0.0 insightjs.com\n0.0.0.0 analytics.insightjs.com\n",
    );
    let e = env(&fx, FakeSystem::default());
    let r = run(&e, Mode::Quick, &[]);
    let blocked: Vec<Option<bool>> = r.hosts.iter().map(|h| h.blocked).collect();
    assert_eq!(blocked, [Some(true), Some(true), Some(false)]);
    let block = r.steps.iter().find(|s| s.title.starts_with("차단 등록")).unwrap();
    assert_eq!(block.commands[0], "0.0.0.0 insightjs.org");
    assert_eq!(block.commands.len(), 3);
}

#[test]
fn result_serializes() {
    let fx = Fx::new("json");
    let e = env(&fx, FakeSystem::default());
    let r = run(&e, Mode::Quick, &[]);
    let j = serde_json::to_string(&r).unwrap();
    assert!(j.contains("\"verdict\":\"not_found\""));
}
