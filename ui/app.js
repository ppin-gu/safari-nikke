"use strict";

// Tauri bridge. A preview page can set window.SNG_MOCK = { invoke, listen } before this script.
const bridge = window.SNG_MOCK || {
  invoke: (cmd, args) => window.__TAURI__.core.invoke(cmd, args),
  listen: (ev, cb) => window.__TAURI__.event.listen(ev, cb),
};

const $ = (id) => document.getElementById(id);
const PHASES = ["설치 경로 탐색", "런처 기록 확인", "런처 데이터 확인", "브라우저 · 임시 파일 확인", "레지스트리 · 프로세스 확인"];
const SEV = { critical: "치명", warning: "경고", info: "정보" };
const VERDICT = {
  infected: ["악성코드 발견", "실행 흔적 확인 · 즉시 조치 필요"],
  exposed: ["노출", "악성 스크립트 수신 · 실행 흔적 없음"],
  clean: ["흔적 없음", "미탐지 ≠ 안전 보장"],
  not_found: ["NIKKE 미설치", "설치 경로를 찾지 못함"],
};
let last = null;
let scanning = false;

function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) {
    if (k == null || k === false) continue;
    n.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return n;
}

function show(view) {
  for (const v of ["start", "scan", "result"]) $("v-" + v).hidden = v !== view;
  $("actions").hidden = view !== "result";
}

let toastTimer;
function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.add("on");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("on"), 1800);
}

async function copy(text, what) {
  try {
    await navigator.clipboard.writeText(text);
    toast(`${what} 복사됨`);
  } catch {
    toast("복사 실패");
  }
}

// ---------- Scan ----------

function renderPhases(current) {
  const i = PHASES.indexOf(current);
  $("phases").replaceChildren(
    ...PHASES.map((p, k) => el("li", { class: k < i ? "done" : k === i ? "now" : "" }, p)),
  );
}

async function startScan(mode, folder) {
  if (scanning) return;
  scanning = true;
  show("scan");
  renderPhases(PHASES[0]);
  $("scan-count").textContent = "0";
  $("scan-path").textContent = " ";
  try {
    const r = await bridge.invoke("scan", { mode, folder: folder || null });
    last = r;
    renderResult(r);
    show("result");
  } catch (e) {
    show("start");
checkPending();
    toast(`검사 실패: ${e}`);
  } finally {
    scanning = false;
  }
}

bridge.listen("scan-progress", (ev) => {
  const p = ev.payload;
  renderPhases(p.phase);
  $("scan-count").textContent = Number(p.entries).toLocaleString("ko-KR");
  if (p.path) $("scan-path").textContent = p.path;
});

// ---------- Result ----------

function hasKind(r, kinds) {
  return r.findings.some((f) => kinds.includes(f.kind));
}

function renderResult(r) {
  const [label, sub] = VERDICT[r.verdict];
  const box = $("verdict");
  box.className = "verdict is-" + r.verdict;
  const crit = r.findings.filter((f) => f.severity === "critical").length;
  const warn = r.findings.filter((f) => f.severity === "warning").length;
  $("v-label").textContent = r.verdict === "infected" ? `${label} (${crit})` : label;
  const subEl = $("v-sub");
  subEl.replaceChildren(sub);
  if (r.used_since_agent && r.verdict !== "infected") {
    subEl.append(el("small", {}, "10/23 이후 런처 사용 기록 있음 · 비밀번호 변경 권장"));
  }

  const answers = [
    ["악성코드 실행", hasKind(r, ["agent_ran", "agent_file", "agent_state", "agent_download"]), true],
    ["현재 활성", hasKind(r, ["launcher_running", "dll_loaded", "registry"]), true],
    ["정리 대상", crit + warn > 0, true],
    ["hosts 차단", r.hosts.every((h) => h.blocked === true), false],
  ];
  $("answers").replaceChildren(
    ...answers.map(([k, yes, badWhenYes]) =>
      el("div", {}, el("dt", {}, k), el("dd", { class: yes === badWhenYes ? "bad" : "good" }, yes ? "예" : "아니오")),
    ),
  );

  const shown = r.findings.filter((f) => f.severity !== "info");
  $("n-findings").textContent = shown.length;
  renderSteps(r);
  renderFindings(r);
  renderDetails(r);
  selectTab("steps");
}

function renderSteps(r) {
  const list = el("ol", { class: "steps" });
  for (const s of r.steps) {
    const li = el("li", { class: "step" });
    const checks = el("ul", { class: "checks" });
    const boxes = [];
    for (const it of s.items) {
      const cb = el("input", { type: "checkbox" });
      boxes.push(cb);
      cb.addEventListener("change", () => li.classList.toggle("done", boxes.every((b) => b.checked)));
      checks.append(el("li", {}, el("label", {}, cb, el("span", {}, it))));
    }
    const other = s.title === "계정 보안";
    li.append(
      el("div", {},
        el("h3", {}, s.title, other ? el("span", { class: "note-other" }, "다른 기기") : null),
        s.body ? el("p", { class: "body" }, s.body) : null,
        s.items.length ? checks : null,
        ...s.targets.map((t) =>
          el("div", { class: "tgt" },
            el("span", { class: "k" }, t.label),
            el("code", {}, t.value),
            el("button", { class: "ghost small", onclick: () => copy(t.value, "경로") }, "복사"),
            t.kind !== "registry" ? el("button", { class: "ghost small", onclick: () => reveal(t.value) }, "위치 열기") : null,
          ),
        ),
        ...s.commands.map((c) =>
          el("div", { class: "cmd" }, el("code", {}, c), el("button", { class: "ghost small", onclick: () => copy(c, "명령") }, "복사")),
        ),
        s.links.length ? el("div", { class: "qrs" }, ...s.links.map(([name, url]) => qr(name, url))) : null,
      ),
    );
    list.append(li);
  }
  const holder = el("div", { class: "remedy", id: "remedy" }, el("p", { class: "empty" }, "조치 항목 불러오는 중"));
  $("p-steps").replaceChildren(holder, list);
  bridge.invoke("remedy_plan").then(renderRemedy).catch((e) => holder.replaceChildren(el("p", { class: "empty" }, `조치 항목 오류: ${e}`)));
}

// ---------- Selected remedy ----------

const DLL_KINDS = ["delete_dll_folder", "delete_file"];

function renderRemedy(plan) {
  const box = $("remedy");
  if (!box) return;
  if (!plan.length) {
    box.remove();
    return;
  }
  const boxes = new Map();
  const count = el("span", { class: "sel" });
  const run = el("button", { class: "danger" }, "선택 항목 조치");
  const refresh = () => {
    const n = [...boxes.values()].filter((b) => b.checked).length;
    count.textContent = `${n}개 선택`;
    run.disabled = n === 0;
  };
  const items = plan.map((a) => {
    const cb = el("input", { type: "checkbox" });
    cb.checked = a.recommended;
    boxes.set(a.id, cb);
    cb.addEventListener("change", () => {
      // The registry key goes first, or the DLL cannot be deleted.
      const reg = plan.find((x) => x.kind === "delete_registry");
      if (cb.checked && DLL_KINDS.includes(a.kind) && reg && !boxes.get(reg.id).checked) {
        boxes.get(reg.id).checked = true;
        toast("레지스트리 키 삭제도 선택됨 (DLL보다 먼저 필요)");
      }
      if (!cb.checked && a.kind === "delete_registry") {
        for (const x of plan) if (DLL_KINDS.includes(x.kind)) boxes.get(x.id).checked = false;
      }
      refresh();
    });
    return el("li", { class: "act" },
      el("label", {},
        cb,
        el("span", { class: "name" }, a.label),
        a.admin ? el("span", { class: "badge admin" }, "관리자 권한") : el("span"),
        el("span", { class: "what" }, a.kind === "kill_launcher" ? a.detail : a.target),
        a.detail && a.kind !== "kill_launcher" ? el("span", { class: "why" }, a.detail) : null,
      ),
    );
  });
  run.addEventListener("click", () => confirmRemedy(plan.filter((a) => boxes.get(a.id).checked)));
  box.replaceChildren(
    el("div", { class: "remedy-head" }, el("h3", {}, "선택 조치"), el("p", {}, "체크한 항목만 실행 · 삭제 전 바탕화면에 증거 백업")),
    el("ul", { class: "acts" }, ...items),
    el("div", { class: "remedy-foot" }, run, count),
  );
  refresh();
}

function confirmRemedy(selected) {
  const dlg = $("confirm");
  $("confirm-list").replaceChildren(...selected.map((a) => el("li", {}, a.label, el("small", {}, a.kind === "kill_launcher" ? a.detail : a.target))));
  const notes = ["삭제한 파일은 휴지통에 남지 않음."];
  if (selected.some((a) => a.kind !== "kill_launcher" && a.kind !== "block")) notes.unshift("실행 전 바탕화면에 증거 백업 폴더 생성.");
  if (selected.some((a) => a.admin)) notes.push("차단 등록은 관리자 권한 요청 창이 뜸.");
  $("confirm-note").textContent = notes.join(" ");
  const ok = $("confirm-ok");
  const go = async () => {
    dlg.close();
    await runRemedy(selected.map((a) => a.id));
  };
  ok.onclick = go;
  $("confirm-cancel").onclick = () => dlg.close();
  dlg.showModal();
}

const STATUS = { done: "완료", failed: "실패", pending_reboot: "재시작 후", skipped: "건너뜀" };

function renderOutcome(box, res, again) {
  const parts = [el("div", { class: "remedy-head" }, el("h3", {}, "조치 결과"))];
  if (res.backup) {
    parts.push(el("div", { class: "backup" }, el("span", {}, "백업"), el("code", {}, res.backup), el("button", { class: "ghost small", onclick: () => reveal(res.backup) }, "위치 열기")));
  }
  parts.push(el("ul", { class: "outs" }, ...res.outcomes.map((o) =>
    el("li", {}, el("span", { class: "st " + o.status }, STATUS[o.status]), el("span", {}, o.label), el("span", { class: "msg" }, o.message)),
  )));
  if (res.pending.length) {
    parts.push(el("p", { class: "reboot" }, `Windows 재시작 후 이 프로그램을 다시 실행 → 남은 조치 ${res.pending.length}건 실행`));
  }
  parts.push(el("div", { class: "remedy-foot" }, el("button", { class: "ghost", onclick: again }, "재검사로 확인")));
  box.replaceChildren(...parts);
}

async function runRemedy(ids) {
  const box = $("remedy");
  box.replaceChildren(el("p", { class: "empty" }, "조치 실행 중"));
  try {
    const res = await bridge.invoke("remedy_apply", { ids });
    renderOutcome(box, res, () => startScan(last ? last.mode : "quick"));
  } catch (e) {
    box.replaceChildren(el("p", { class: "empty" }, `조치 실패: ${e}`));
  }
}

async function checkPending() {
  let list = [];
  try {
    list = await bridge.invoke("pending_list");
  } catch {
    return;
  }
  const b = $("pending");
  b.hidden = !list.length;
  if (!list.length) return;
  $("pending-n").textContent = list.length;
  $("pending-list").textContent = list.map((a) => a.target).join(", ");
}

$("btn-pending").addEventListener("click", async () => {
  try {
    const res = await bridge.invoke("pending_apply");
    const failed = res.outcomes.filter((o) => o.status !== "done" && o.status !== "skipped");
    toast(failed.length ? `남은 조치 ${failed.length}건 미완료: ${failed[0].message}` : "남은 조치 완료 · 재검사 권장");
    checkPending();
  } catch (e) {
    toast(`실패: ${e}`);
  }
});

function qr(name, url) {
  const box = el("div", { class: "svg", role: "img", "aria-label": `${name} QR 코드` });
  bridge.invoke("qr_svg", { text: url }).then((svg) => { box.innerHTML = svg; }).catch(() => { box.textContent = url; });
  return el("div", { class: "qr" }, box, el("div", {}, name));
}

async function reveal(path) {
  try {
    await bridge.invoke("reveal", { path });
  } catch (e) {
    toast(`열기 실패: ${e}`);
  }
}

function renderFindings(r) {
  const groups = [["critical", "치명"], ["warning", "경고"], ["info", "정보"]];
  const out = [];
  for (const [sev, name] of groups) {
    const fs = r.findings.filter((f) => f.severity === sev);
    if (!fs.length) continue;
    out.push(
      el("div", { class: "group" },
        el("h3", {}, `${name} ${fs.length}`),
        ...fs.map((f) =>
          el("details", { class: "finding", open: sev === "critical" && f.evidence.length ? true : null },
            el("summary", {},
              el("span", { class: "sev " + sev }, SEV[sev]),
              el("span", { class: "t" }, f.title),
              el("span", { class: "loc" }, f.location),
            ),
            f.evidence.length ? el("div", { class: "ev" }, ...f.evidence.map((e) => el("code", {}, e))) : null,
          ),
        ),
      ),
    );
  }
  $("p-findings").replaceChildren(...(out.length ? out : [el("p", { class: "empty" }, "발견 항목 없음")]));
}

function fmtTime(secs) {
  if (!secs) return "-";
  const d = new Date(secs * 1000);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function kvList(rows) {
  return el("ul", { class: "kv" }, ...rows.map(([k, v, cls]) => el("li", {}, el("span", {}, k), el("span", { class: "v " + (cls || "") }, v))));
}

function renderDetails(r) {
  const x = r.exposure;
  const exposure = [
    ...x.logins.map(([b, p]) => [`저장 로그인 · ${b}`, p]),
    ...x.wallets.map(([w, b]) => [`지갑 확장 · ${b}`, w, "bad"]),
    ...x.secrets.map(([w, p]) => [w, p.split(/[\\/]/).pop(), "bad"]),
  ];
  const mode = { quick: "빠른 검사", full: "전체 검사", folder: "폴더 지정" }[r.mode];
  const sections = [
    el("section", {},
      el("h3", {}, "검사 정보"),
      kvList([
        ["검사 시각", fmtTime(r.started)],
        ["방식", mode],
        ["탐색 항목", Number(r.entries_visited).toLocaleString("ko-KR")],
        ["소요", `${(r.duration_ms / 1000).toFixed(1)}초`],
        ["런처 최근 활동", fmtTime(r.last_launcher_activity), r.used_since_agent ? "bad" : ""],
      ]),
    ),
    el("section", {},
      el("h3", {}, "hosts 차단"),
      kvList(r.hosts.map((h) => [h.domain, h.blocked === true ? "차단됨" : h.blocked === false ? "미차단" : "확인 불가", h.blocked ? "good" : "bad"])),
    ),
    el("section", { class: "wide" },
      el("h3", {}, "타임라인"),
      r.timeline.length
        ? el("ol", { class: "timeline" }, ...r.timeline.map((e) => el("li", {}, el("time", {}, e.time), el("span", {}, e.what))))
        : el("p", { class: "empty" }, "기록 없음"),
    ),
    el("section", { class: "wide" },
      el("h3", {}, "유출 가능 정보"),
      exposure.length ? kvList(exposure) : el("p", { class: "empty" }, "확인된 항목 없음"),
    ),
    el("section", {},
      el("h3", {}, "NIKKE 설치 폴더"),
      r.installs.length ? el("ul", { class: "paths" }, ...r.installs.map((p) => el("li", {}, p))) : el("p", { class: "empty" }, "없음"),
    ),
    el("section", {},
      el("h3", {}, "런처 데이터"),
      r.launcher_data.length ? el("ul", { class: "paths" }, ...r.launcher_data.map((p) => el("li", {}, p))) : el("p", { class: "empty" }, "없음"),
    ),
    r.notes.length
      ? el("section", { class: "wide" }, el("h3", {}, "참고"), el("ul", { class: "paths" }, ...r.notes.map((n) => el("li", {}, n))))
      : null,
  ];
  $("p-details").replaceChildren(el("div", { class: "details" }, ...sections));
}

function selectTab(name) {
  for (const b of document.querySelectorAll(".tabs button")) b.setAttribute("aria-selected", String(b.dataset.tab === name));
  for (const p of ["steps", "findings", "details"]) $("p-" + p).hidden = p !== name;
}

// ---------- Wiring ----------

$("btn-quick").addEventListener("click", () => startScan("quick"));
$("btn-full").addEventListener("click", () => startScan("full"));
$("btn-folder").addEventListener("click", async () => {
  const f = await bridge.invoke("pick_folder");
  if (f) startScan("folder", f);
});
$("btn-cancel").addEventListener("click", () => bridge.invoke("cancel_scan"));
$("btn-rescan").addEventListener("click", () => startScan(last ? last.mode : "quick"));
for (const b of document.querySelectorAll(".tabs button")) b.addEventListener("click", () => selectTab(b.dataset.tab));

$("btn-copy").addEventListener("click", async () => {
  const t = await bridge.invoke("report_text", { redact: $("redact").checked });
  if (t) copy(t, "리포트");
});
$("btn-save").addEventListener("click", async () => {
  try {
    const p = await bridge.invoke("save_report", { redact: $("redact").checked });
    if (p) toast("리포트 저장됨");
  } catch (e) {
    toast(String(e));
  }
});

show("start");
checkPending();
