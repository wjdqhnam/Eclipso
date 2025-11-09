// ===== helpers / config =====
const API_BASE = window.API_BASE || "http://127.0.0.1:8000";
const HWPX_VIEWER_URL = window.HWPX_VIEWER_URL || "";
const $ = (id) => document.getElementById(id);

const PREVIEW_ONLY_MATCHES = true;

function extOf(name) {
  const m = (name || "").match(/\.([^.]+)$/);
  return (m ? m[1] : "").toLowerCase();
}
function escapeHtml(s) {
  return (s || "").replace(/[&<>"']/g, (m) =>
    ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[m])
  );
}
function downloadBlob(blob, filenameFromHeader) {
  const a = document.createElement("a");
  const url = URL.createObjectURL(blob);
  a.href = url;
  if (filenameFromHeader) a.download = filenameFromHeader;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 800);
}
function setSaveVisible(show) {
  const b = $("btn-save-redacted");
  if (!b) return;
  if (show) {
    b.classList.remove("hidden");
    b.disabled = false;
  } else {
    b.classList.add("hidden");
    b.disabled = true;
  }
}

// ===== tones (칩 색상) =====
const RULE_TONE = {
  rrn: "background:#ede9fe;color:#4c1d95;",
  fgn: "background:#ede9fe;color:#4c1d95;",
  email: "background:#e0f2fe;color:#075985;",
  phone_mobile: "background:#d1fae5;color:#065f46;",
  phone_city: "background:#d1fae5;color:#065f46;",
  card: "background:#ffedd5;color:#9a3412;",
  passport: "background:#e0e7ff;color:#3730a3;",
  driver_license: "background:#fce7f3;color:#9d174d;",
  default: "background:#f3f4f6;color:#374151;",
};
const toneStyle = (rule) => RULE_TONE[rule] || RULE_TONE.default;

// ===== masking =====
const KEEP = new Set(["-", "_", " "]);
function maskPreview(val, rule) {
  if ((rule || "").toLowerCase() === "email") {
    let out = "";
    for (const ch of val || "") {
      if (ch === "@") out += "@";
      else if (/[A-Za-z0-9.]/.test(ch)) out += "*";
      else out += ch;
    }
    return out;
  }
  let out = "";
  for (const ch of val || "") {
    if (/[A-Za-z0-9]/.test(ch)) out += "*";
    else if (KEEP.has(ch)) out += ch;
    else out += ch;
  }
  return out;
}

// ===== normalize & filter =====
function normalizeMatchesText(fullText, matches) {
  return (matches || []).map((m) => ({
    ...m,
    value:
      (m.value && String(m.value).trim()) ||
      (m.location &&
        Number.isFinite(m.location.start) &&
        Number.isFinite(m.location.end)
        ? fullText.slice(m.location.start, m.location.end).trim()
        : ""),
  }));
}
function keepMeaningful(v) {
  if (!v) return false;
  return ((v.match(/[A-Za-z0-9]/g) || []).length >= 2);
}

// ===== group by rule =====
function groupByRule(fullText, matches, { valid, masked }) {
  // valid: 'ok' | 'ng' | 'all'
  const groups = new Map();
  const seen = new Set();

  for (const m of matches || []) {
    if (valid === "ok" && m.valid !== true) continue;
    if (valid === "ng" && m.valid !== false) continue;

    const rule = m.rule || "unknown";
    let v = (m.value || "").trim();

    if (
      !v &&
      m.location &&
      Number.isFinite(m.location.start) &&
      Number.isFinite(m.location.end)
    ) {
      v = fullText.slice(m.location.start, m.location.end).trim();
    }
    if (!keepMeaningful(v)) continue;

    const show = masked ? maskPreview(v, rule) : v;
    const key = `${rule}:${show}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const arr = groups.get(rule) || [];
    arr.push(show);
    groups.set(rule, arr);
  }

  return new Map(
    [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]))
  );
}

// ===== tight preview (한 줄 = 한 카테고리) =====
function buildPreviewHtml_Grouped(fullText, matches) {
  const grouped = groupByRule(fullText, matches, {
    valid: "ok",
    masked: true,
  });
  if (!grouped.size)
    return `<div style="font-size:12px;color:#9ca3af">감지된 항목 없음</div>`;

  let html =
    '<div style="font-size:13px;line-height:1.15;margin:0;padding:0">';
  grouped.forEach((vals, rule) => {
    const chips = vals
      .map(
        (v) =>
          `<span style="display:inline-block;padding:1px 6px;border-radius:8px;${toneStyle(
            rule
          )};margin:0 4px 0 0;font-size:12px;">${escapeHtml(v)}</span>`
      )
      .join("");
    html += `
      <div style="margin:2px 0;padding:0;white-space:normal;">
        <span style="display:inline-block;min-width:110px;color:#6b7280;font-size:12px;margin:0 6px 0 0;vertical-align:middle;">${escapeHtml(
          rule
        )}</span>
        <span style="display:inline-block;vertical-align:middle;">${chips}</span>
      </div>`;
  });
  html += "</div>";
  return html;
}

// ===== chips list (하단 위젯) =====
function renderDetectedLists(matches) {
  const ok = (matches || []).filter((m) => m.valid === true);
  const ng = (matches || []).filter((m) => m.valid === false);
  renderRuleChips($("by-rule-ok"), ok, false);
  renderRuleChips($("by-rule-ng"), ng, true);
}
function renderRuleChips(container, list, isNG = false) {
  const by = new Map();
  (list || []).forEach((m) => {
    const k = m.rule || "unknown";
    const arr = by.get(k) || [];
    arr.push(m);
    by.set(k, arr);
  });
  if (!list.length) {
    container.innerHTML =
      '<div style="font-size:12px;color:#6b7280">없음</div>';
    return;
  }
  const sections = [];
  by.forEach((arr, rule) => {
    const seen = new Set();
    const chips = [];
    arr.forEach((m) => {
      const raw = (m.value || "").trim();
      if (!raw) return;
      const key = `${rule}:${raw}`;
      if (seen.has(key)) return;
      seen.add(key);
      const extra = isNG ? "outline:1px solid #fca5a5;" : "";
      chips.push(
        `<span style="display:inline-block;padding:2px 8px;border-radius:9999px;${toneStyle(
          rule
        )};${extra}margin:2px 6px 2px 0;font-size:12px;">${escapeHtml(
          raw
        )}</span>`
      );
    });
    sections.push(`
      <div style="margin:4px 0 6px 0;line-height:1.15;">
        <div style="font-size:12px;color:#6b7280;margin:0 0 2px 0;">${escapeHtml(
          rule
        )}</div>
        <div style="display:flex;flex-wrap:wrap;align-items:flex-start;">${chips.join(
          ""
        )}</div>
      </div>
    `);
  });
  container.innerHTML = sections.join("");
}

// ===== state =====
let __lastRedactedBlob = null;
let __lastRedactedName = "redacted.bin";

// ===== rules UI =====
function selectedRuleNames() {
  return Array.from(
    document.querySelectorAll('input[name="rule"]:checked')
  ).map((el) => el.value);
}

// ===== init =====
init();
function init() {
  bindUI();
  setSaveVisible(false);
}
function bindUI() {
  $("file").addEventListener("change", onFileChange);
  $("btn-scan").addEventListener("click", onScanClick);
  $("btn-save-redacted").addEventListener("click", onSaveClick);
}

// ===== file change =====
function onFileChange() {
  const f = $("file").files?.[0] || null;

  $("redacted-preview").innerHTML = "";
  $("txt-raw").value = "";
  $("by-rule-ok").innerHTML = "";
  $("by-rule-ng").innerHTML = "";
  $("summary").textContent = "";
  $("status").textContent = "";
  $("file-info").textContent = "";
  setSaveVisible(false);

  if (!f) return;
  $("file-info").textContent = `${f.name} · ${(
    f.size / 1024
  ).toFixed(1)} KB · ${extOf(f.name).toUpperCase()}`;
}

// ===== actions =====
async function onScanClick() {
  const f = $("file").files?.[0];
  if (!f) return alert("파일을 선택하세요.");

  setSaveVisible(false);

  const ext = extOf(f.name);
  const safeBase = f.name.replace(/\.[^.]+$/, "") || "redacted";
  __lastRedactedName = `${safeBase}.${ext || "bin"}`;

  setStatus("텍스트 추출 및 매칭 중...");

  const fd = new FormData();
  fd.append("file", f);

  try {
    // 1) 텍스트 추출
    const extResp = await fetch(`${API_BASE}/text/extract`, {
      method: "POST",
      body: fd,
    });
    if (!extResp.ok) {
      const msg = await extResp.text();
      throw new Error(`텍스트 추출 실패 (${extResp.status})\n${msg}`);
    }
    const extData = await extResp.json();
    const fullText = extData.full_text || "";

    // 2) 매칭
    const rules = selectedRuleNames();
    const matchResp = await fetch(`${API_BASE}/text/match`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: fullText, rules, normalize: true }),
    });
    if (!matchResp.ok) {
      const msg = await matchResp.text();
      throw new Error(`매칭 실패 (${matchResp.status})\n${msg}`);
    }
    const res = await matchResp.json();

    const matches = normalizeMatchesText(
      fullText,
      Array.isArray(res.items) ? res.items : []
    );

    // ── 상단 미리보기 (칩 그룹) ─────────────────────
    const html = PREVIEW_ONLY_MATCHES
      ? buildPreviewHtml_Grouped(fullText, matches)
      : "";
    $("redacted-preview").innerHTML = html;
    const rp = $("redacted-preview");
    rp.style.lineHeight = "1.15";
    rp.style.padding = "4px 0";
    rp.style.margin = "0";

    // ── 하단 원본 텍스트: rule + 값 모아 보여주기 ─────
    const allGrouped = groupByRule(fullText, matches, {
      valid: "all",
      masked: false,
    });
    const lines = [];
    allGrouped.forEach((vals, rule) => {
      lines.push(`${rule}`);
      vals.forEach((v) => lines.push(`  ${v}`));
      lines.push("");
    });
    while (lines.length && lines[lines.length - 1] === "") lines.pop();
    $("txt-raw").value = lines.join("\n") || fullText;

    // ── OK/FAIL 칩 리스트 ────────────────────────────
    renderDetectedLists(matches);

    // ── 요약: /text/match 가 준 counts 그대로 사용 ────
    const counts = res.counts || {};
    const summary =
      Object.keys(counts).length === 0
        ? "검출: 없음"
        : "검출: " +
          Object.entries(counts)
            .map(([k, v]) => `${k}=${v}`)
            .join(", ");
    $("summary").textContent = summary;

    setStatus(`스캔 완료 (${ext.toUpperCase()} 처리)`);

    // 3) 레닥션 파일 생성 (/redact/file 그대로 사용)
    setStatus("레닥션 파일 생성 중...");
    const { blob, filename } = await applyAndGetBlob(f);
    __lastRedactedBlob = blob;
    __lastRedactedName = filename;

    setSaveVisible(true);
    setStatus("레닥션 완료 — 다운로드 가능");
  } catch (err) {
    console.error(err);
    setStatus(`오류: ${err.message || err}`);
  }
}

async function applyAndGetBlob(file) {
  const fd = new FormData();
  fd.append("file", file);

  const res = await fetch(`${API_BASE}/redact/file`, {
    method: "POST",
    body: fd,
  });
  if (!res.ok) {
    const msg = await res.text();
    throw new Error(`레닥션 실패 (${res.status})\n${msg}`);
  }

  const blob = await res.blob();
  const originalName = file.name || "";
  const ex = extOf(originalName) || "bin";
  const safeBase = originalName.replace(/\.[^.]+$/, "") || "redacted";
  const filename = `${safeBase}.${ex}`;
  return { blob, filename };
}

// 다운로드 버튼
function onSaveClick() {
  if (!__lastRedactedBlob)
    return alert("레닥션된 파일이 없습니다. 먼저 스캔/레닥션을 수행하세요.");
  downloadBlob(__lastRedactedBlob, __lastRedactedName);
}

// ===== status =====
function setStatus(msg) {
  $("status").textContent = msg || "";
}
