//! The "조치" list: only the steps that match what the scan found, in order.

use std::path::Path;

use crate::checks::hosts;
use crate::iocs;
use crate::model::{Kind, ScanResult, Step, Target, Verdict};
use crate::util::path_ci;

fn step(title: &str, body: &str) -> Step {
    Step {
        title: title.into(),
        body: body.into(),
        items: Vec::new(),
        targets: Vec::new(),
        links: Vec::new(),
        commands: Vec::new(),
    }
}

fn target(label: &str, value: impl Into<String>, kind: &str) -> Target {
    Target {
        label: label.into(),
        value: value.into(),
        kind: kind.into(),
    }
}

fn has(r: &ScanResult, kinds: &[Kind]) -> bool {
    r.findings.iter().any(|f| kinds.contains(&f.kind))
}

fn locations(r: &ScanResult, kinds: &[Kind]) -> Vec<String> {
    let mut v: Vec<String> = r
        .findings
        .iter()
        .filter(|f| kinds.contains(&f.kind))
        .map(|f| f.location.clone())
        .collect();
    v.dedup();
    v
}

fn cache_step(r: &ScanResult) -> Option<Step> {
    let caches: Vec<String> = r
        .launcher_data
        .iter()
        .filter_map(|d| path_ci(Path::new(d), "tbs_cache"))
        .map(|p| p.display().to_string())
        .collect();
    if caches.is_empty() {
        return None;
    }
    let mut s = step("런처 캐시 삭제", "변조 스크립트가 캐시에 남아 있을 수 있음 · 런처 재실행 전 삭제");
    s.items.push("런처 완전 종료 후 tbs_cache 폴더 삭제".into());
    for c in caches {
        s.targets.push(target("tbs_cache", c, "folder"));
    }
    Some(s)
}

fn account_step(r: &ScanResult, required: bool) -> Step {
    let body = if required {
        "이 PC 말고 휴대폰 등 다른 기기에서 진행"
    } else {
        "권장 · 다른 기기에서 진행"
    };
    let mut s = step("계정 보안", body);
    s.items.push("NIKKE / Level Infinite 비밀번호 변경".into());
    if required {
        s.items.push("Google 비밀번호 변경 · 모든 기기 로그아웃".into());
        s.items.push("Discord 비밀번호 변경 · 다른 기기 로그아웃".into());
        s.items.push("Steam 비밀번호 변경 · 다른 기기 인증 해제".into());
        let mut browsers: Vec<String> = r.exposure.logins.iter().map(|(b, p)| format!("{b}({p})")).collect();
        browsers.dedup();
        if !browsers.is_empty() {
            s.items.push(format!("브라우저 저장 비밀번호 전체 변경: {}", browsers.join(", ")));
        }
        s.items.push("은행 · 카드 앱 로그인 기록 확인".into());
        for (w, b) in &r.exposure.wallets {
            s.items.push(format!("지갑 자산 이동 (새 시드로 만든 지갑): {w} [{b}]"));
        }
        let mut secrets: Vec<&str> = r.exposure.secrets.iter().map(|(w, _)| w.as_str()).collect();
        secrets.dedup();
        if !secrets.is_empty() {
            s.items.push(format!("키 · 토큰 폐기 후 재발급: {}", secrets.join(", ")));
        }
        s.links.push(("Google 보안".into(), "https://myaccount.google.com/security".into()));
        s.links
            .push(("Steam 계정".into(), "https://store.steampowered.com/account/".into()));
    }
    s
}

fn block_step(r: &ScanResult) -> Step {
    let mut s = step("차단 등록 (선택)", "관리자 권한 필요 · 감염 여부와 무관하게 적용 가능");
    let lines = hosts::lines_to_add(&r.hosts);
    if lines.is_empty() {
        s.items.push("hosts: 3개 도메인 차단됨".into());
    } else {
        s.items
            .push(r"hosts 파일에 추가: C:\Windows\System32\drivers\etc\hosts (메모장을 관리자 권한으로 실행)".into());
        s.commands.extend(lines);
    }
    s.items.push("방화벽: 관리자 PowerShell에서 실행".into());
    for ip in iocs::BLOCK_IPS {
        s.commands.push(format!(
            "netsh advfirewall firewall add rule name=\"SNG block {ip}\" dir=out action=block remoteip={ip}"
        ));
    }
    s
}

fn final_step(reinstall: bool) -> Step {
    let mut s = step("마무리", "");
    if reinstall {
        s.items.push("권장: Windows 재설치 (원격 명령 실행 가능했음)".into());
    }
    s.items.push("공식 공지 전 NIKKE PC 런처 실행 금지".into());
    s.items.push("재검사로 결과 확인".into());
    s
}

pub fn build(r: &ScanResult) -> Vec<Step> {
    let mut v = Vec::new();
    match r.verdict {
        Verdict::Infected => {
            let mut s = step("런처 종료 · 네트워크 차단", "");
            if has(r, &[Kind::LauncherRunning]) {
                s.items.push("작업 관리자(Ctrl+Shift+Esc) → nikke_launcher.exe 작업 끝내기".into());
            }
            s.items.push("Wi-Fi 끄기 또는 LAN 케이블 분리".into());
            v.push(s);

            let mut s = step("결과 저장", "삭제 전에 저장 · 캐시를 지우면 흔적도 사라짐");
            s.items.push("[리포트 저장] 실행".into());
            v.push(s);

            let reg = has(r, &[Kind::Registry, Kind::RegistryLeftover]);
            let dll = locations(r, &[Kind::BrowserDll, Kind::OldDll]);
            if reg || !dll.is_empty() || has(r, &[Kind::DllLoaded]) {
                let mut s = step("지속 DLL 제거", "순서 고정: 레지스트리 → 재시작 → DLL 폴더");
                if reg {
                    s.items.push("1. 레지스트리 키 삭제".into());
                    s.targets
                        .push(target("레지스트리 키", format!(r"HKCU\{}", iocs::CLSID_KEY), "registry"));
                    s.commands.push(format!("reg delete \"HKCU\\{}\" /f", iocs::CLSID_KEY));
                }
                s.items.push(format!("{}. Windows 재시작 (DLL 잠금 해제)", if reg { 2 } else { 1 }));
                if !dll.is_empty() {
                    s.items.push(format!("{}. DLL 폴더 삭제", if reg { 3 } else { 2 }));
                    for d in dll {
                        s.targets.push(target("DLL 폴더", d, "folder"));
                    }
                }
                v.push(s);
            }

            let temps = locations(r, &[Kind::TempFile]);
            if !temps.is_empty() {
                let mut s = step("임시 파일 삭제", "k2f로 시작하는 파일 (수집된 자격 증명 · 화면 캡처)");
                for t in temps {
                    s.targets.push(target("Temp 폴더", t, "folder"));
                }
                v.push(s);
            }
            if let Some(s) = cache_step(r) {
                v.push(s);
            }
            v.push(account_step(r, true));
            v.push(block_step(r));
            v.push(final_step(true));
        }
        Verdict::Exposed => {
            let mut s = step("결과 저장", "삭제 전에 저장");
            s.items.push("[리포트 저장] 실행".into());
            v.push(s);
            if let Some(s) = cache_step(r) {
                v.push(s);
            }
            v.push(account_step(r, r.used_since_agent));
            v.push(block_step(r));
            v.push(final_step(false));
        }
        Verdict::Clean => {
            if let Some(s) = cache_step(r) {
                v.push(s);
            }
            if r.used_since_agent {
                v.push(account_step(r, false));
            }
            v.push(block_step(r));
            v.push(final_step(false));
        }
        Verdict::NotFound => {
            let mut s = step("다시 검사", "설치 위치가 특이한 경우");
            s.items.push("[전체 검사]: 모든 드라이브 전체 탐색".into());
            s.items.push("[폴더 지정]: NIKKE 설치 폴더 직접 선택".into());
            v.push(s);
            v.push(block_step(r));
        }
    }
    v
}
