//! Data the scan returns. Serialized to JSON for the UI.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "치명",
            Severity::Warning => "경고",
            Severity::Info => "정보",
        }
    }
}

/// What a finding is about. Drives the steps and the UI icons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// debug.log: the agent ran.
    AgentRan,
    /// The launcher asked the agent server or downloaded insight.bundle.
    AgentDownload,
    /// The saved agent (LuaJIT bytecode) on disk.
    AgentFile,
    /// k2f.agent.state / k2f_chan in launcher data.
    AgentState,
    /// The malicious loader script in the launcher cache.
    ScriptCache,
    /// Launcher network state names insightjs.
    Network,
    /// Browser DLL persistence folder.
    BrowserDll,
    /// Older persistence files in Chrome's Application folder.
    OldDll,
    /// HKCU CLSID key with a DLL path.
    Registry,
    /// HKCU CLSID key left empty by the agent's uninstall.
    RegistryLeftover,
    /// k2f* files in Temp.
    TempFile,
    /// The launcher is running now.
    LauncherRunning,
    /// A running program has the persistence DLL loaded.
    DllLoaded,
    /// A NIKKE install folder.
    Install,
    /// A launcher data folder.
    LauncherData,
    /// A location that could not be read.
    Unreadable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub kind: Kind,
    /// Short Korean label, e.g. "악성 에이전트 실행 기록".
    pub title: String,
    /// File or folder, or registry key.
    pub location: String,
    /// At most 5 lines, each cut to 240 characters.
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Install or launcher data found, nothing suspicious.
    Clean,
    /// Loader traces only.
    Exposed,
    /// At least one critical finding.
    Infected,
    /// No NIKKE install or launcher data.
    NotFound,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Clean => "흔적 없음",
            Verdict::Exposed => "노출",
            Verdict::Infected => "악성코드 발견",
            Verdict::NotFound => "NIKKE 미설치",
        }
    }
    pub fn sub(self) -> &'static str {
        match self {
            Verdict::Clean => "미탐지 ≠ 안전 보장",
            Verdict::Exposed => "악성 스크립트 수신, 실행 흔적 없음",
            Verdict::Infected => "실행 흔적 확인, 즉시 조치 필요",
            Verdict::NotFound => "설치 경로를 찾지 못함",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// As written in the log, e.g. "2026-11-03 01:47:35" or "11-03 01:47:35 (연도 미기록)".
    pub time: String,
    pub what: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Exposure {
    /// (browser, profile)
    pub logins: Vec<(String, String)>,
    /// (wallet, browser)
    pub wallets: Vec<(String, String)>,
    /// (what, path)
    pub secrets: Vec<(String, String)>,
}

impl Exposure {
    pub fn is_empty(&self) -> bool {
        self.logins.is_empty() && self.wallets.is_empty() && self.secrets.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostsEntry {
    pub domain: String,
    /// None: the hosts file could not be read.
    pub blocked: Option<bool>,
}

/// One step of the "조치" list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub title: String,
    pub body: String,
    /// Checklist lines.
    pub items: Vec<String>,
    /// Paths or keys the user acts on; the UI gives them copy / open buttons.
    pub targets: Vec<Target>,
    /// Links to open on another device; the UI shows them as QR codes.
    pub links: Vec<(String, String)>,
    /// Command lines to copy (hosts lines, firewall rules).
    pub commands: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub label: String,
    pub value: String,
    /// "folder" | "file" | "registry"
    pub kind: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Quick,
    Full,
    Folder,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub tool_version: String,
    pub mode: Mode,
    /// Unix seconds.
    pub started: u64,
    pub duration_ms: u64,
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
    pub timeline: Vec<Event>,
    pub exposure: Exposure,
    pub hosts: Vec<HostsEntry>,
    pub installs: Vec<String>,
    pub launcher_data: Vec<String>,
    /// Latest modification time (Unix seconds) of debug.log or launcher data.
    pub last_launcher_activity: Option<u64>,
    /// The launcher ran on or after 2026-10-23.
    pub used_since_agent: bool,
    pub entries_visited: u64,
    pub notes: Vec<String>,
    pub steps: Vec<Step>,
}

impl ScanResult {
    pub fn count(&self, s: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == s).count()
    }
}
