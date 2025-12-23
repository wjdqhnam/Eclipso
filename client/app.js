const API_BASE = () => window.API_BASE || 'http://127.0.0.1:8000'

const $ = (sel) => document.querySelector(sel)
const $$ = (sel) => Array.from(document.querySelectorAll(sel))

/** ---------- State ---------- */
let state = {
  file: null,
  ext: '',
  t0: null,
  timings: null,

  extractedText: '',
  markdown: '',
  normalizedText: '',
  pages: [],
  pageIndex: 0,

  rules: [],
  nerLabels: [],

  matchData: null,
  nerItems: [],

  detections: [],
  detectionById: new Map(),

  selectedGroup: 'ALL',
  selectedId: null,

  redactReady: false,
  lastRedactedBlob: null,
  lastRedactedName: 'redacted.bin',

  filters: {
    src: 'all', // all | regex | ner
    val: 'all', // all | ok | fail
    q: '',
  },

  ui: {
    busy: false,
    uploadCollapsed: false,
    uploadToggleEnabled: false,
  },
}

/** ---------- Utils ---------- */
const escHtml = (s) =>
  String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')

function setStatus(msg) {
  const el = $('#status')
  if (el) el.textContent = msg || ''
}

function showLoading(msg) {
  // 파일 업로드 전(또는 파일 없는 상태)에는 로딩 오버레이를 띄우지 않음
  const hasFile = !!state?.file || !!$('#file')?.files?.[0]
  if (!hasFile) return

  const ov = $('#loading-overlay')
  const txt = $('#loading-text')
  if (txt) txt.textContent = String(msg || '동작 중...')
  if (ov) ov.classList.remove('hidden')

  state.ui.busy = true

  // 동작 중엔 입력 잠금(업로드/옵션 변경 방지)
  $('#btn-scan') && ($('#btn-scan').disabled = true)
  $('#file') && ($('#file').disabled = true)
  $$('input[name="rule"]').forEach((el) => (el.disabled = true))
  ;['#ner-show-ps', '#ner-show-lc', '#ner-show-og'].forEach((sel) => {
    const el = $(sel)
    if (el) el.disabled = true
  })
}

function hideLoading() {
  const ov = $('#loading-overlay')
  if (ov) ov.classList.add('hidden')
  state.ui.busy = false

  // 입력 잠금 해제
  $('#btn-scan') && ($('#btn-scan').disabled = false)
  $('#file') && ($('#file').disabled = false)
  $$('input[name="rule"]').forEach((el) => (el.disabled = false))
  ;['#ner-show-ps', '#ner-show-lc', '#ner-show-og'].forEach((sel) => {
    const el = $(sel)
    if (el) el.disabled = false
  })
}

function setPages(pages) {
  const arr = Array.isArray(pages)
    ? pages.filter((x) => typeof x === 'string')
    : []
  state.pages = arr.length ? arr : ['']
  state.pageIndex = 0
  updatePageControls()
}

function updatePageControls() {
  const total = Math.max(1, state.pages.length || 1)
  const idx = Math.max(0, Math.min(total - 1, state.pageIndex || 0))
  state.pageIndex = idx

  const ind = $('#doc-page-indicator')
  if (ind) ind.textContent = `${idx + 1} / ${total}`

  const prev = $('#btn-page-prev')
  const next = $('#btn-page-next')
  if (prev) prev.disabled = idx <= 0
  if (next) next.disabled = idx >= total - 1
}

function renderCurrentPage() {
  updatePageControls()
  const md = state.pages[state.pageIndex] ?? ''
  renderMarkdownToViewer(md, state.detections)
  clearViewerSelection()
}

function setUploadCollapsed(on) {
  const grid = $('#layout-grid')
  if (!grid) return
  const next = !!on
  state.ui.uploadCollapsed = next
  grid.classList.toggle('upload-collapsed', next)

  const btn = $('#btn-toggle-upload')
  if (btn) btn.textContent = next ? '업로드 패널 보이기' : '업로드 패널 숨기기'
}

function enableUploadToggle(on) {
  state.ui.uploadToggleEnabled = !!on
  const btn = $('#btn-toggle-upload')
  if (!btn) return
  btn.classList.toggle('hidden', !on)
}

function badge(sel, n) {
  const el = $(sel)
  if (el) el.textContent = String(n ?? 0)
}

function onlyDigits(s) {
  return String(s || '').replace(/\D+/g, '')
}

function pad2(n) {
  return String(n).padStart(2, '0')
}

function nowIso() {
  return new Date().toISOString()
}

function formatIsoToLocalKorean(iso) {
  if (!iso) return '-'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return String(iso)
  const y = d.getFullYear()
  const m = pad2(d.getMonth() + 1)
  const day = pad2(d.getDate())
  const hh = pad2(d.getHours())
  const mm = pad2(d.getMinutes())
  return `${y}-${m}-${day} (${hh}:${mm})`
}

const JOIN_NEWLINE_RE = /([\w\uAC00-\uD7A3.%+\-/])\n([\w\uAC00-\uD7A3.%+\-/])/g
function joinBrokenLines(text) {
  if (!text) return ''
  let t = String(text).replace(/\r\n/g, '\n')
  let prev = null
  while (prev !== t) {
    prev = t
    t = t.replace(JOIN_NEWLINE_RE, '$1$2')
  }
  return t
}

/** ---------- UI Reset ---------- */
function resetUiAll() {
  hideLoading()
  enableUploadToggle(false)
  setUploadCollapsed(false)
  setPages([''])

  // blocks
  $('#doc-viewer-block')?.classList.add('hidden')
  $('#detect-block')?.classList.add('hidden')
  $('#inspector-block')?.classList.add('hidden')
  $('#stats-report-block')?.classList.add('hidden')

  // viewer
  const viewer = $('#doc-viewer')
  if (viewer) viewer.innerHTML = ''
  $('#doc-meta') && ($('#doc-meta').textContent = '-')
  $('#doc-detect-count') && ($('#doc-detect-count').textContent = '0')

  // detect
  const rail = $('#bookmark-rail')
  if (rail) rail.innerHTML = ''
  const items = $('#bookmark-items')
  if (items) items.innerHTML = ''
  $('#detect-sub') && ($('#detect-sub').textContent = '-')
  $('#detect-badge') && ($('#detect-badge').textContent = '0')
  $('#detect-search') && ($('#detect-search').value = '')

  // inspector
  $('#inspector-empty')?.classList.remove('hidden')
  $('#inspector-body')?.classList.add('hidden')
  $('#btn-jump') && ($('#btn-jump').disabled = true)

  // buttons
  const applyBtn = $('#btn-apply-redact')
  if (applyBtn) applyBtn.disabled = true
  const saveBtn = $('#btn-save-redacted')
  if (saveBtn) {
    saveBtn.disabled = true
    saveBtn.classList.add('hidden')
  }

  // stats JSON
  $('#stats-json')?.classList.add('hidden')
  if ($('#stats-json')) $('#stats-json').textContent = ''

  // state
  state = {
    ...state,
    t0: null,
    timings: null,
    extractedText: '',
    markdown: '',
    normalizedText: '',
    matchData: null,
    nerItems: [],
    detections: [],
    detectionById: new Map(),
    selectedGroup: 'ALL',
    selectedId: null,
    redactReady: false,
    lastRedactedBlob: null,
    filters: { src: 'all', val: 'all', q: '' },
  }

  setStatus('대기 중')
}

/** ---------- Rules & Policies ---------- */
async function loadRules() {
  try {
    const r = await fetch(`${API_BASE()}/text/rules`)
    if (!r.ok) throw 0
    const rules = await r.json()
    const box = $('#rules-container')
    if (!box) return
    box.innerHTML = ''
    for (const rule of rules) {
      const el = document.createElement('label')
      el.className = 'flex items-center gap-2'
      el.innerHTML = `<input type="checkbox" name="rule" value="${escHtml(
        rule
      )}" checked><span>${escHtml(rule)}</span>`
      box.appendChild(el)
    }
  } catch {
    // 기본값 유지
  }
}

function selectedRuleNames() {
  return $$('input[name="rule"]:checked').map((el) => el.value)
}

function selectedNerLabels() {
  const labels = []
  $('#ner-show-ps')?.checked !== false && labels.push('PS')
  $('#ner-show-lc')?.checked !== false && labels.push('LC')
  $('#ner-show-og')?.checked !== false && labels.push('OG')
  return labels
}

function selectedMaskingPolicy() {
  const ps = $('#mask-ps')?.value || 'full'
  return { ps }
}

/** ---------- Dropzone ---------- */
function setupDropZone() {
  const dz = $('#dropzone'),
    input = $('#file'),
    nameEl = $('#file-name')
  if (!dz || !input) return

  let depth = 0

  const setActive = (on) => {
    dz.classList.toggle('ring-2', on)
    dz.style.setProperty('--tw-ring-color', on ? '#4f46e5' : '')
    dz.style.backgroundColor = on ? '#fafafa' : ''
  }

  const showName = (f) => {
    if (nameEl) nameEl.textContent = f ? f.name : ''
  }

  ;['dragover', 'drop'].forEach((ev) =>
    window.addEventListener(ev, (e) => e.preventDefault())
  )

  dz.addEventListener('dragenter', (e) => {
    e.preventDefault()
    depth++
    setActive(true)
    e.dataTransfer && (e.dataTransfer.dropEffect = 'copy')
  })
  dz.addEventListener('dragover', (e) => {
    e.preventDefault()
    e.dataTransfer && (e.dataTransfer.dropEffect = 'copy')
  })
  ;['dragleave', 'dragend'].forEach((ev) =>
    dz.addEventListener(ev, (e) => {
      e.preventDefault()
      depth = Math.max(0, depth - 1)
      if (!depth) setActive(false)
    })
  )

  dz.addEventListener('drop', (e) => {
    e.preventDefault()
    depth = 0
    setActive(false)
    const dt = e.dataTransfer
    let file = (dt.files && dt.files[0]) || null
    if (!file && dt.items) {
      for (const it of dt.items) {
        if (it.kind === 'file') {
          const f = it.getAsFile()
          if (f) {
            file = f
            break
          }
        }
      }
    }
    if (!file) return
    const repl = new DataTransfer()
    repl.items.add(file)
    input.files = repl.files
    input.dispatchEvent(new Event('change', { bubbles: true }))
    showName(file)
    setStatus('파일 선택됨 · 탐지 실행')
  })

  input.addEventListener('change', (e) => showName(e.target.files?.[0] || null))
}

/** ---------- Markdown fetch + normalize ---------- */
function normalizeMarkdownResponse(mdData) {
  let markdown = ''
  if (!mdData) return ''
  if (typeof mdData.markdown === 'string') markdown = mdData.markdown
  else if (Array.isArray(mdData.pages_md))
    markdown = mdData.pages_md.join('\n\n')
  else if (Array.isArray(mdData.pages))
    markdown = mdData.pages.map((p) => p.markdown || '').join('\n\n')
  return String(markdown || '')
}

async function fetchMarkdown(file) {
  try {
    const fd = new FormData()
    fd.append('file', file)
    const r = await fetch(`${API_BASE()}/text/markdown`, {
      method: 'POST',
      body: fd,
    })
    if (!r.ok) return null
    const mdData = await r.json()
    const md = normalizeMarkdownResponse(mdData)
    return md && md.trim() ? md : null
  } catch {
    return null
  }
}

function fallbackMarkdownFromText(text) {
  // 코드펜스(``` )는 HTML span 삽입(하이라이트)을 "글자 그대로" 출력시키므로 사용하지 않는다.
  // 텍스트는 안전하게 escape하고, 줄바꿈은 <br>로 유지한다.
  const safe = escHtml(String(text || ''))
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .replace(/\n/g, '<br/>')
  return `<div class="doc-text">${safe}</div>`
}

/** ---------- Match / NER ---------- */
function normalizeNerItems(raw) {
  if (!raw) return { items: [] }
  if (Array.isArray(raw.entities)) return { items: raw.entities }
  if (Array.isArray(raw.items)) return { items: raw.items }
  if (Array.isArray(raw)) return { items: raw }
  return { items: [] }
}

async function requestNerSmart(text, exclude_spans, labels_override = null) {
  const labels =
    Array.isArray(labels_override) && labels_override.length
      ? labels_override
      : selectedNerLabels()

  const bodyObj = {
    text: String(text || ''),
    labels,
    exclude_spans: Array.isArray(exclude_spans) ? exclude_spans : [],
    debug: false,
  }

  try {
    const r2 = await fetch(`${API_BASE()}/ner/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(bodyObj),
    })
    if (!r2.ok) return { items: [] }
    const j2 = await r2.json()
    return normalizeNerItems(j2)
  } catch {
    return { items: [] }
  }
}

function filterMatchByRules(matchData, rules) {
  const allow = new Set((rules || []).map((r) => String(r).toLowerCase()))
  const items = Array.isArray(matchData?.items) ? matchData.items : []
  const kept = allow.size
    ? items.filter((it) => allow.has(String(it.rule || '').toLowerCase()))
    : items
  const counts = {}
  for (const it of kept) {
    if (it?.valid) counts[it.rule] = (counts[it.rule] || 0) + 1
  }
  return { ...matchData, items: kept, counts }
}

function buildExcludeSpansFromMatch(matchData) {
  const items = Array.isArray(matchData?.items) ? matchData.items : []
  const spans = []
  for (const it of items) {
    if (it?.valid === false) continue
    const s = Number(it.start ?? -1)
    const e = Number(it.end ?? -1)
    if (!(e > s)) continue
    spans.push({ start: s, end: e })
  }
  return spans
}

/** ---------- Kind mapping ---------- */
function ruleToKind(rule) {
  const r = String(rule || '').toLowerCase()
  if (!r) return 'UNKNOWN'
  if (r.includes('rrn')) return '주민등록번호'
  if (r.includes('fgn')) return '외국인등록번호'
  if (r.includes('card')) return '카드번호'
  if (r.includes('email')) return '이메일'
  if (r.includes('passport')) return '여권번호'
  if (r.includes('driver')) return '운전면허번호'
  if (r.includes('account') || r.includes('bank')) return '계좌번호'
  if (r.includes('phone') || r.includes('tel') || r.includes('mobile'))
    return '전화번호'
  return String(rule)
}

/** ---------- Detections: build + render ---------- */
function makeId() {
  return (
    'd_' + Math.random().toString(16).slice(2) + '_' + Date.now().toString(16)
  )
}

function buildDetections(matchData, nerItems, nerAllowLabels) {
  const out = []
  const allow = new Set(
    (nerAllowLabels || []).map((x) => String(x).toUpperCase())
  )
  const mdItems = Array.isArray(matchData?.items) ? matchData.items : []
  const ner = Array.isArray(nerItems) ? nerItems : []

  // regex
  for (const it of mdItems) {
    const id = makeId()
    const kind = ruleToKind(it?.rule)
    const val = String(it?.value ?? '')
    out.push({
      id,
      source: 'regex',
      kind,
      label: null,
      rule: it?.rule ?? null,
      text: val,
      start: Number.isFinite(+it?.start) ? +it.start : null,
      end: Number.isFinite(+it?.end) ? +it.end : null,
      valid: it?.valid !== false,
      score: null,
    })
  }

  // ner
  for (const it of ner) {
    const lab = String(it?.label || '').toUpperCase()
    if (!allow.has(lab)) continue
    const id = makeId()
    out.push({
      id,
      source: 'ner',
      kind: null,
      label: lab,
      rule: null,
      text: String(it?.text ?? ''),
      start: Number.isFinite(+it?.start) ? +it.start : null,
      end: Number.isFinite(+it?.end) ? +it.end : null,
      valid: true,
      score: typeof it?.score === 'number' ? it.score : null,
    })
  }

  // 정렬(문서 내 순서 우선)
  out.sort((a, b) => {
    const as = a.start ?? 1e18
    const bs = b.start ?? 1e18
    if (as !== bs) return as - bs
    const ae = a.end ?? 1e18
    const be = b.end ?? 1e18
    return ae - be
  })

  return out
}

/**
 * bbox 없으니, MD 문자열에 inline HTML span을 삽입해서 "텍스트 박스"로 표시.
 * start/end 기반 정확 위치 매핑은 MD 변환 과정에서 깨질 수 있어(정확하지 않음),
 * 여기서는 “순서 기반 substring 탐색”으로 넣는다.
 */
function injectBoxesIntoMarkdown(md, detections) {
  let s = String(md || '')
  if (!s.trim() || !detections?.length) return s

  // 이미 삽입된 경우 중복 방지
  if (s.includes('class="pii-box"')) return s

  let cursor = 0

  for (const d of detections) {
    const needle = String(d.text || '').trim()
    if (!needle) continue
    // 너무 짧은 토큰(예: "s")은 문서 전체에서 과도하게 매칭되어 박스가 폭발하므로 스킵
    if (needle.length < 2) continue
    if (/^[A-Za-z]$/.test(needle)) continue

    // 순서 기반 탐색
    let idx = s.indexOf(needle, cursor)
    if (idx < 0) idx = s.indexOf(needle, 0)
    if (idx < 0) continue

    const before = s.slice(0, idx)
    const after = s.slice(idx + needle.length)

    const tag =
      d.source === 'regex'
        ? `REGEX·${d.kind || 'UNKNOWN'}`
        : `NER·${d.label || 'UNK'}`

    const attrs = [
      `class="pii-box${d.valid ? '' : ' pii-fail'}"`,
      `data-id="${escHtml(d.id)}"`,
      `data-source="${escHtml(d.source)}"`,
      d.kind ? `data-kind="${escHtml(d.kind)}"` : '',
      d.label ? `data-label="${escHtml(d.label)}"` : '',
      `data-valid="${d.valid ? '1' : '0'}"`,
      `data-tag="${escHtml(tag)}"`,
    ]
      .filter(Boolean)
      .join(' ')

    const wrapped = `<span ${attrs}>${escHtml(needle)}</span>`

    s = before + wrapped + after
    cursor = (before + wrapped).length
  }

  return s
}

function renderMarkdownToViewer(md, detections) {
  const viewer = $('#doc-viewer')
  if (!viewer) return

  const md2 = injectBoxesIntoMarkdown(md, detections)

  // Marked: GFM tables on
  let html = ''
  try {
    // 줄바꿈 보존: 문서(특히 표/셀 내 줄바꿈)에서 개행을 그대로 렌더링
    marked.setOptions({ gfm: true, breaks: true })
    html = marked.parse(md2)
  } catch {
    html = `<pre>${escHtml(md2)}</pre>`
  }

  // DOMPurify: span + data-* 허용
  const clean = DOMPurify.sanitize(html, {
    ADD_TAGS: ['span'],
    ADD_ATTR: [
      'class',
      'data-id',
      'data-source',
      'data-kind',
      'data-label',
      'data-valid',
      'data-tag',
    ],
  })

  // A4 비율 “페이지” 컨테이너로 렌더링
  viewer.innerHTML = `<div class="doc-page"><div class="doc-page-inner">${clean}</div></div>`
}

/** ---------- Bookmarks UI ---------- */
function groupKeyOf(d) {
  if (!d) return 'OTHER'
  if (d.source === 'regex') return d.kind || 'UNKNOWN'
  if (d.source === 'ner') return d.label || 'NER'
  return 'OTHER'
}

function groupTitleOf(key) {
  if (key === 'ALL') return '전체'
  return String(key)
}

function groupOrderScore(key) {
  const k = String(key)
  const order = {
    ALL: 0,
    주민등록번호: 1,
    외국인등록번호: 2,
    카드번호: 3,
    계좌번호: 4,
    전화번호: 5,
    이메일: 6,
    여권번호: 7,
    운전면허번호: 8,
    PS: 20,
    LC: 21,
    OG: 22,
    UNKNOWN: 99,
  }
  return order[k] ?? 50
}

function renderBookmarks(detections) {
  const rail = $('#bookmark-rail')
  if (!rail) return

  const groups = new Map()
  groups.set('ALL', { key: 'ALL', count: detections.length })

  for (const d of detections) {
    const key = groupKeyOf(d)
    const prev = groups.get(key) || { key, count: 0 }
    prev.count++
    groups.set(key, prev)
  }

  const list = Array.from(groups.values()).sort(
    (a, b) =>
      groupOrderScore(a.key) - groupOrderScore(b.key) || b.count - a.count
  )

  rail.innerHTML = ''
  for (const g of list) {
    const btn = document.createElement('button')
    btn.type = 'button'
    btn.className = 'bm'
    btn.dataset.key = g.key
    btn.dataset.active = g.key === state.selectedGroup ? '1' : '0'
    btn.innerHTML = `${escHtml(groupTitleOf(g.key))} <small>(${
      g.count
    })</small>`
    btn.addEventListener('click', () => {
      state.selectedGroup = g.key
      rail.querySelectorAll('.bm').forEach((x) => (x.dataset.active = '0'))
      btn.dataset.active = '1'
      renderBookmarkItems()
    })
    rail.appendChild(btn)
  }
}

function applyFilterButtons(kind, value) {
  if (kind === 'src') {
    state.filters.src = value
    ;['flt-src-all', 'flt-src-regex', 'flt-src-ner'].forEach((id) => {
      const b = $('#' + id)
      if (!b) return
      const active = b.dataset.value === value
      b.classList.toggle('bg-zinc-900', active)
      b.classList.toggle('text-white', active)
      b.classList.toggle('hover:bg-zinc-50', !active)
    })
  } else if (kind === 'val') {
    state.filters.val = value
    ;['flt-val-all', 'flt-val-ok', 'flt-val-fail'].forEach((id) => {
      const b = $('#' + id)
      if (!b) return
      const active = b.dataset.value === value
      b.classList.toggle('bg-zinc-900', active)
      b.classList.toggle('text-white', active)
      b.classList.toggle('hover:bg-zinc-50', !active)
    })
  }
  renderBookmarkItems()
}

function detectionPassesFilters(d) {
  if (state.selectedGroup !== 'ALL') {
    if (groupKeyOf(d) !== state.selectedGroup) return false
  }

  if (state.filters.src !== 'all' && d.source !== state.filters.src)
    return false

  if (state.filters.val === 'ok' && !d.valid) return false
  if (state.filters.val === 'fail' && d.valid) return false

  const q = String(state.filters.q || '')
    .trim()
    .toLowerCase()
  if (q) {
    const hay = `${d.text} ${d.kind || ''} ${d.label || ''} ${
      d.rule || ''
    }`.toLowerCase()
    if (!hay.includes(q)) return false
  }

  return true
}

function renderBookmarkItems() {
  const wrap = $('#bookmark-items')
  if (!wrap) return
  wrap.innerHTML = ''

  const filtered = state.detections.filter(detectionPassesFilters)

  if (!filtered.length) {
    wrap.innerHTML =
      '<div class="text-sm text-zinc-500 border border-zinc-200 rounded-2xl p-4">표시할 항목이 없습니다.</div>'
    return
  }

  for (const d of filtered) {
    const card = document.createElement('button')
    card.type = 'button'
    card.className =
      'w-full text-left border border-zinc-200 rounded-2xl p-3 hover:bg-zinc-50 transition'
    card.dataset.id = d.id

    const leftTag =
      d.source === 'regex'
        ? `REGEX · ${d.kind || 'UNKNOWN'}`
        : `NER · ${d.label || 'UNK'}`
    const pos = d.start != null && d.end != null ? `${d.start}-${d.end}` : '-'
    const okFail = d.valid ? 'OK' : 'FAIL'

    card.innerHTML = `
      <div class="flex items-start justify-between gap-3">
        <div class="min-w-0">
          <div class="flex flex-wrap items-center gap-2">
            <span class="pill" data-source="${escHtml(d.source)}">${escHtml(
      leftTag
    )}</span>
            <span class="text-[11px] font-extrabold ${
              d.valid ? 'text-emerald-700' : 'text-rose-700'
            }">${okFail}</span>
            <span class="text-[11px] text-zinc-500 font-mono">${escHtml(
              pos
            )}</span>
          </div>
          <div class="mt-2 text-sm font-mono break-all text-zinc-950">${escHtml(
            d.text
          )}</div>
        </div>
        <div class="shrink-0 text-xs text-zinc-400 font-extrabold">클릭</div>
      </div>
    `

    card.addEventListener('click', () => {
      selectDetection(d.id, true)
    })

    wrap.appendChild(card)
  }
}

/** ---------- Inspector + Selection ---------- */
function clearViewerSelection() {
  const viewer = $('#doc-viewer')
  if (!viewer) return
  viewer.querySelectorAll('.pii-box.pii-selected').forEach((el) => {
    el.classList.remove('pii-selected')
  })
}

function applyViewerSelection(id) {
  const viewer = $('#doc-viewer')
  if (!viewer) return
  const spans = viewer.querySelectorAll(`.pii-box[data-id="${CSS.escape(id)}"]`)
  spans.forEach((el) => el.classList.add('pii-selected'))
  const first = spans[0]
  if (first && typeof first.scrollIntoView === 'function') {
    first.scrollIntoView({
      block: 'center',
      inline: 'nearest',
      behavior: 'auto',
    })
  }
}

function renderInspector(d) {
  $('#inspector-block')?.classList.remove('hidden')

  const empty = $('#inspector-empty')
  const body = $('#inspector-body')
  if (!d) {
    empty?.classList.remove('hidden')
    body?.classList.add('hidden')
    $('#btn-jump') && ($('#btn-jump').disabled = true)
    return
  }

  empty?.classList.add('hidden')
  body?.classList.remove('hidden')

  const title =
    d.source === 'regex'
      ? `${d.kind || 'UNKNOWN'} (정규식)`
      : `${d.label || 'UNK'} (NER)`

  const sub =
    d.source === 'regex'
      ? `rule=${d.rule || '-'} · valid=${d.valid}`
      : `score=${d.score ?? '-'}`
  const pos = d.start != null && d.end != null ? `${d.start}-${d.end}` : '-'
  const scoreLine =
    d.source === 'regex'
      ? `valid=${d.valid ? 'true' : 'false'}`
      : `score=${typeof d.score === 'number' ? d.score.toFixed(4) : '-'}`

  $('#insp-title') && ($('#insp-title').textContent = title)
  $('#insp-sub') && ($('#insp-sub').textContent = sub)
  const pill = $('#insp-pill')
  if (pill) {
    pill.dataset.source = d.source
    pill.textContent =
      d.source === 'regex'
        ? `REGEX · ${d.kind || 'UNKNOWN'}`
        : `NER · ${d.label || 'UNK'}`
  }
  $('#insp-text') && ($('#insp-text').textContent = d.text || '-')
  $('#insp-pos') && ($('#insp-pos').textContent = pos)
  $('#insp-score') && ($('#insp-score').textContent = scoreLine)

  const jumpBtn = $('#btn-jump')
  if (jumpBtn) {
    jumpBtn.disabled = false
    jumpBtn.onclick = () => applyViewerSelection(d.id)
  }
}

function selectDetection(id, alsoJump = false) {
  const d = state.detectionById.get(id)
  if (!d) return
  state.selectedId = id

  clearViewerSelection()
  applyViewerSelection(id)

  $('#bookmark-items')
    ?.querySelectorAll('button[data-id]')
    .forEach((b) => {
      const on = b.dataset.id === id
      b.classList.toggle('ring-2', on)
      b.style.setProperty('--tw-ring-color', on ? '#4f46e5' : '')
    })

  renderInspector(d)

  if (alsoJump) applyViewerSelection(id)
}

/** ---------- Click: viewer span -> inspector ---------- */
function wireViewerClick() {
  const viewer = $('#doc-viewer')
  if (!viewer) return
  viewer.addEventListener('click', (e) => {
    const sp = e.target.closest('.pii-box')
    if (!sp) return
    const id = sp.getAttribute('data-id')
    if (!id) return
    selectDetection(id, false)
  })
}

/** ---------- Masking segmented UI ---------- */
function wireMaskButtons() {
  $$('.mask-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.target
      const value = btn.dataset.value
      const input = document.getElementById(target)
      if (input) input.value = value

      const group = btn.parentElement
      if (!group) return
      group.querySelectorAll('.mask-btn').forEach((b) => {
        const active = b.dataset.value === value
        b.classList.toggle('bg-zinc-900', active)
        b.classList.toggle('text-white', active)
      })
    })
  })
}

/** ---------- Stats (기존 로직 유지: 최소 수정) ---------- */
function riskWeights() {
  return {
    주민등록번호: 30,
    외국인등록번호: 30,
    카드번호: 25,
    계좌번호: 20,
    운전면허번호: 18,
    여권번호: 18,
    전화번호: 10,
    이메일: 8,
    PS: 2,
    LC: 5,
    OG: 3,
  }
}

function Score(v) {
  if (typeof v !== 'number' || !Number.isFinite(v)) return '-'
  const t = Math.floor(v * 100) / 100
  return t.toFixed(2)
}

function overlapRatio(a, b) {
  const a0 = Number(a?.start ?? -1)
  const a1 = Number(a?.end ?? -1)
  const b0 = Number(b?.start ?? -1)
  const b1 = Number(b?.end ?? -1)
  if (!(a1 > a0 && b1 > b0)) return 0
  const inter = Math.max(0, Math.min(a1, b1) - Math.max(a0, b0))
  const denom = Math.min(a1 - a0, b1 - b0)
  if (denom <= 0) return 0
  return inter / denom
}

function computeScanStats({
  file,
  ext,
  rules,
  nerLabels,
  matchData,
  nerItems,
  timings,
}) {
  const weights = riskWeights()
  const mdItems = Array.isArray(matchData?.items) ? matchData.items : []
  const ner = Array.isArray(nerItems) ? nerItems : []

  // regex ok/fail
  let regex_ok = 0
  let regex_fail = 0
  const fail_reason_counts = {}

  function luhnValid(numStr) {
    const s = onlyDigits(numStr)
    if (s.length < 12) return false
    let sum = 0
    let alt = false
    for (let i = s.length - 1; i >= 0; i--) {
      let n = s.charCodeAt(i) - 48
      if (n < 0 || n > 9) return false
      if (alt) {
        n *= 2
        if (n > 9) n -= 9
      }
      sum += n
      alt = !alt
    }
    return sum % 10 === 0
  }

  function emailLooksValid(v) {
    const s = String(v || '').trim()
    if (!s.includes('@')) return false
    const parts = s.split('@')
    if (parts.length !== 2) return false
    const [local, domain] = parts
    if (!local || !domain) return false
    if (domain.startsWith('.') || domain.endsWith('.')) return false
    if (!domain.includes('.')) return false
    return true
  }

  function rrnLooksValidFormat(v) {
    const d = onlyDigits(v)
    return d.length === 13
  }

  function phoneLooksValid(v) {
    const d = onlyDigits(v)
    return d.length >= 9 && d.length <= 11
  }

  function inferFailReason(rule, value) {
    const r = String(rule || '').toLowerCase()
    const v = String(value || '')

    if (r.includes('card')) {
      if (!onlyDigits(v)) return '숫자 외 문자 포함'
      if (!luhnValid(v)) return 'Luhn 불일치'
      return '검증 로직 불일치'
    }
    if (r.includes('email')) {
      if (!emailLooksValid(v)) return '이메일 형식 불일치'
      return '검증 로직 불일치'
    }
    if (r.includes('rrn')) {
      if (!rrnLooksValidFormat(v)) return '자리수/형식 불일치'
      return '체크섬 불일치'
    }
    if (r.includes('fgn')) {
      const d = onlyDigits(v)
      if (d.length !== 13) return '자리수/형식 불일치'
      return '체크섬 불일치'
    }
    if (r.includes('phone') || r.includes('tel') || r.includes('mobile')) {
      if (!phoneLooksValid(v)) return '전화번호 자리수/형식 불일치'
      return '검증 로직 불일치'
    }
    if (r.includes('passport')) return '여권번호 형식/국가규칙 불일치'
    if (r.includes('driver')) return '면허번호 형식/지역규칙 불일치'
    return '검증 실패(원인 미분류)'
  }

  for (const it of mdItems) {
    if (it?.valid === true) regex_ok++
    else if (it?.valid === false) {
      regex_fail++
      const reason = inferFailReason(it?.rule, it?.value)
      fail_reason_counts[reason] = (fail_reason_counts[reason] || 0) + 1
    }
  }

  const fail_top3 =
    Object.entries(fail_reason_counts)
      .sort((a, b) => (b[1] || 0) - (a[1] || 0))
      .slice(0, 3)
      .map(([k, v]) => `${k} ${v}`)
      .join(' / ') || '-'

  // by_kind (valid=true 기준)
  const by_kind = {}
  for (const it of mdItems) {
    if (it?.valid === false) continue
    const k = ruleToKind(it?.rule)
    by_kind[k] = (by_kind[k] || 0) + 1
  }

  // by_label (선택 라벨)
  const allow = new Set((nerLabels || []).map((x) => String(x).toUpperCase()))
  const by_label = {}
  const scoreAgg = {}
  for (const it of ner) {
    const lab = String(it?.label || '').toUpperCase()
    if (!allow.has(lab)) continue
    by_label[lab] = (by_label[lab] || 0) + 1
    if (typeof it?.score === 'number' && Number.isFinite(it.score)) {
      ;(scoreAgg[lab] ??= []).push(it.score)
    }
  }

  const nerAvg = {}
  for (const lab of ['PS', 'LC', 'OG']) {
    const arr = scoreAgg[lab] || []
    if (!arr.length) nerAvg[lab] = '-'
    else {
      const avg = arr.reduce((a, b) => a + b, 0) / arr.length
      nerAvg[lab] = Score(avg)
    }
  }

  // Unique 병합(대략)
  const spans = []
  for (const it of mdItems) {
    if (it?.valid === false) continue
    const s = Number(it?.start ?? -1)
    const e = Number(it?.end ?? -1)
    if (!(e > s)) continue
    spans.push({ start: s, end: e, source: 'regex' })
  }
  for (const it of ner) {
    const lab = String(it?.label || '').toUpperCase()
    if (!allow.has(lab)) continue
    const s = Number(it?.start ?? -1)
    const e = Number(it?.end ?? -1)
    if (!(e > s)) continue
    spans.push({ start: s, end: e, source: 'ner' })
  }
  spans.sort((a, b) => a.start - b.start || a.end - b.end)

  const clusters = []
  for (const sp of spans) {
    const last = clusters.length ? clusters[clusters.length - 1] : null
    if (!last) {
      clusters.push({
        start: sp.start,
        end: sp.end,
        has_regex: sp.source === 'regex',
        has_ner: sp.source === 'ner',
      })
      continue
    }
    const ratio = overlapRatio(last, sp)
    if (ratio >= 0.8 || sp.start <= last.end) {
      last.start = Math.min(last.start, sp.start)
      last.end = Math.max(last.end, sp.end)
      if (sp.source === 'regex') last.has_regex = true
      if (sp.source === 'ner') last.has_ner = true
    } else {
      clusters.push({
        start: sp.start,
        end: sp.end,
        has_regex: sp.source === 'regex',
        has_ner: sp.source === 'ner',
      })
    }
  }

  const total_raw = spans.length
  const total_unique = clusters.length
  const overlap_count = clusters.filter((c) => c.has_regex && c.has_ner).length
  const overlap_rate = total_unique ? overlap_count / total_unique : 0
  const regex_unique = clusters.filter((c) => c.has_regex).length
  const ner_unique = clusters.filter((c) => c.has_ner).length

  let raw = 0
  for (const [k, v] of Object.entries(by_kind))
    raw += (weights[k] || 0) * (v || 0)
  for (const [lab, v] of Object.entries(by_label))
    raw += (weights[lab] || 0) * (v || 0)
  const risk_score_0_100 = Math.max(0, Math.min(100, Math.round(raw)))

  // 탐지된 규칙/라벨
  const detectedRules = new Set()
  for (const it of mdItems) {
    if (it?.valid !== false && it?.rule)
      detectedRules.add(String(it.rule).toLowerCase())
  }
  const detectedLabels = new Set(
    Object.keys(by_label || {}).map((l) => l.toUpperCase())
  )

  return {
    version: 'scan-report-v1',
    created_at: nowIso(),
    document: {
      name: file?.name || '-',
      ext: String(ext || '').toLowerCase(),
      size_bytes: typeof file?.size === 'number' ? file.size : null,
    },
    policy: {
      rules: Array.isArray(rules) ? rules : [],
      ner_labels: Array.isArray(nerLabels) ? nerLabels : [],
    },
    timings: { ...(timings || {}) },
    stats: {
      risk_score_0_100,
      total_raw,
      total_unique,
      regex_unique,
      ner_unique,
      overlap_count,
      overlap_rate,
      by_kind,
      by_label,
      ner_avg: nerAvg,
      regex_ok,
      regex_fail,
      fail_top3,
      fail_reason_counts,
      detected_rules: Array.from(detectedRules),
      detected_labels: Array.from(detectedLabels),
    },
  }
}

function fmtMs(v) {
  if (typeof v !== 'number' || !Number.isFinite(v)) return '-'
  return `${Math.round(v)}ms`
}

function renderChips(containerEl, list, detectedSet = null) {
  if (!containerEl) return
  containerEl.innerHTML = ''
  const arr = Array.isArray(list) ? list : []
  if (!arr.length) {
    containerEl.innerHTML = `<span class="text-[12px] text-zinc-500">-</span>`
    return
  }
  for (const v of arr) {
    const span = document.createElement('span')
    const vLower = String(v).toLowerCase()
    const vUpper = String(v).toUpperCase()
    const isDetected =
      detectedSet && (detectedSet.has(vLower) || detectedSet.has(vUpper))
    if (isDetected) {
      span.className =
        'text-[11px] px-2 py-1 rounded-full border font-extrabold'
      span.style.borderColor = 'rgba(14,165,233,0.35)'
      span.style.backgroundColor = 'rgba(14,165,233,0.12)'
      span.style.color = '#0f172a'
    } else {
      span.className =
        'text-[11px] px-2 py-1 rounded-full border border-zinc-200 bg-zinc-50 text-zinc-800'
    }
    span.textContent = String(v)
    containerEl.appendChild(span)
  }
}

function renderScanReport(report) {
  if (!report) return
  $('#stats-report-block')?.classList.remove('hidden')

  const doc = report.document || {}
  const s = report.stats || {}
  const t = report.timings || {}
  const pol = report.policy || {}

  const created = formatIsoToLocalKorean(report.created_at)
  const subtitle = `${doc.name || '-'} · ${String(
    doc.ext || ''
  ).toUpperCase()} · ${
    typeof doc.size_bytes === 'number' ? `${doc.size_bytes} bytes` : '-'
  } · ${created}`
  $('#stats-subtitle') && ($('#stats-subtitle').textContent = subtitle)

  const risk = Number(s.risk_score_0_100 ?? 0)
  $('#stats-risk-score') && ($('#stats-risk-score').textContent = String(risk))
  const meter = $('#stats-risk-meter')
  if (meter) meter.style.width = `${Math.max(0, Math.min(100, risk))}%`

  $('#stats-total-unique') &&
    ($('#stats-total-unique').textContent = String(s.total_unique ?? 0))
  $('#stats-total-raw') &&
    ($('#stats-total-raw').textContent = String(s.total_raw ?? 0))
  $('#stats-overlap-rate') &&
    ($('#stats-overlap-rate').textContent = `${Math.round(
      (s.overlap_rate || 0) * 100
    )}%`)

  $('#stats-regex-unique') &&
    ($('#stats-regex-unique').textContent = String(s.regex_unique ?? 0))
  $('#stats-ner-unique') &&
    ($('#stats-ner-unique').textContent = String(s.ner_unique ?? 0))

  const nerAvg = s.ner_avg || {}
  $('#stats-ner-avg') &&
    ($('#stats-ner-avg').textContent = `PS ${nerAvg.PS || '-'} / LC ${
      nerAvg.LC || '-'
    } / OG ${nerAvg.OG || '-'}`)

  $('#stats-regex-ok') &&
    ($('#stats-regex-ok').textContent = String(s.regex_ok ?? 0))
  $('#stats-regex-fail') &&
    ($('#stats-regex-fail').textContent = String(s.regex_fail ?? 0))
  $('#stats-fail-top') &&
    ($('#stats-fail-top').textContent = s.fail_top3 || '-')

  const detectedRules = new Set(
    (s.detected_rules || []).map((r) => String(r).toLowerCase())
  )
  const detectedLabels = new Set(
    (s.detected_labels || []).map((l) => String(l).toUpperCase())
  )
  renderChips($('#stats-policy-rules'), pol.rules, detectedRules)
  renderChips($('#stats-policy-nerlabels'), pol.ner_labels, detectedLabels)

  $('#t-extract') && ($('#t-extract').textContent = fmtMs(t.extract_ms))
  $('#t-match') && ($('#t-match').textContent = fmtMs(t.match_ms))
  $('#t-ner') && ($('#t-ner').textContent = fmtMs(t.ner_ms))
  $('#t-redact') && ($('#t-redact').textContent = fmtMs(t.redact_ms))
  $('#t-total') && ($('#t-total').textContent = fmtMs(t.total_ms))

  const kindRows = $('#stats-by-kind-rows')
  if (kindRows) {
    kindRows.innerHTML = ''
    const entries = Object.entries(s.by_kind || {}).sort(
      (a, b) => (b[1] || 0) - (a[1] || 0)
    )
    if (!entries.length) {
      const tr = document.createElement('tr')
      tr.innerHTML = `<td class="py-2 px-3 text-zinc-500" colspan="2">없음</td>`
      kindRows.appendChild(tr)
    } else {
      for (const [k, v] of entries) {
        const tr = document.createElement('tr')
        tr.className = 'border-b'
        tr.innerHTML = `<td class="py-2 px-3">${escHtml(
          k
        )}</td><td class="py-2 px-3 text-right font-mono">${v}</td>`
        kindRows.appendChild(tr)
      }
    }
  }

  const labelRows = $('#stats-by-label-rows')
  if (labelRows) {
    labelRows.innerHTML = ''
    const entries = Object.entries(s.by_label || {}).sort(
      (a, b) => (b[1] || 0) - (a[1] || 0)
    )
    if (!entries.length) {
      const tr = document.createElement('tr')
      tr.innerHTML = `<td class="py-2 px-3 text-zinc-500" colspan="2">없음</td>`
      labelRows.appendChild(tr)
    } else {
      for (const [k, v] of entries) {
        const tr = document.createElement('tr')
        tr.className = 'border-b'
        tr.innerHTML = `<td class="py-2 px-3">${escHtml(
          k
        )}</td><td class="py-2 px-3 text-right font-mono">${v}</td>`
        labelRows.appendChild(tr)
      }
    }
  }

  const jsonEl = $('#stats-json')
  if (jsonEl && !jsonEl.classList.contains('hidden')) {
    jsonEl.textContent = JSON.stringify(report, null, 2)
  }
}

/** ---------- Main: Scan / Redact ---------- */
async function doScan() {
  const f = $('#file')?.files?.[0]
  if (!f) return alert('파일을 선택하세요.')

  resetUiAll()

  state.file = f
  state.ext = (f.name.split('.').pop() || '').toLowerCase()
  state.rules = selectedRuleNames()
  state.nerLabels = selectedNerLabels()

  const ext = state.ext

  state.lastRedactedName = f.name
    ? f.name.replace(/\.[^.]+$/, `_redacted.${ext}`)
    : `redacted.${ext}`

  state.t0 = performance.now()
  state.timings = {
    extract_ms: null,
    match_ms: null,
    ner_ms: null,
    redact_ms: null,
    total_ms: null,
  }

  setStatus('텍스트 변환중...')
  showLoading('텍스트 변환중...')
  const fd = new FormData()
  fd.append('file', f)

  const tExtract = performance.now()
  try {
    const r1 = await fetch(`${API_BASE()}/text/extract`, {
      method: 'POST',
      body: fd,
    })
    if (!r1.ok)
      throw new Error(`텍스트 추출 실패 (${r1.status})\n${await r1.text()}`)
    const extractData = await r1.json()
    state.timings.extract_ms = performance.now() - tExtract

    const fullText = String(extractData.full_text || '')
    state.extractedText = fullText

    // 페이지 기반 markdown 구성(PDF는 pages_md 우선)
    const pagesMd = Array.isArray(extractData?.pages_md)
      ? extractData.pages_md
          .map((p) => (p && typeof p.markdown === 'string' ? p.markdown : ''))
          .filter((x) => x && x.trim())
      : []

    const pagesText = Array.isArray(extractData?.pages)
      ? extractData.pages
          .map((p) => (p && typeof p.text === 'string' ? p.text : ''))
          .filter((x) => x && x.trim())
      : []

    const mdSingle =
      typeof extractData?.markdown === 'string' && extractData.markdown.trim()
        ? extractData.markdown
        : ''

    const splitByFormFeed = (s) =>
      String(s || '')
        .split('\f')
        .map((x) => x.trim())
        .filter(Boolean)

    const pages = pagesMd.length
      ? pagesMd
      : pagesText.length
      ? pagesText.map((t) => fallbackMarkdownFromText(t))
      : splitByFormFeed(mdSingle).length
      ? splitByFormFeed(mdSingle)
      : [mdSingle || fallbackMarkdownFromText(fullText)]

    setPages(pages)
    state.markdown = pages.join('\n\n')

    const isLayoutPreserved = [
      'pdf',
      'hwpx',
      'hwp',
      'docx',
      'doc',
      'pptx',
      'ppt',
      'xlsx',
      'xls',
      'docm',
      'pptm',
      'xlsm',
      'xml',
      'txt',
    ].includes(ext)
    state.normalizedText = isLayoutPreserved
      ? fullText
      : joinBrokenLines(fullText)

    setStatus('정규식 탐지중...')
    showLoading('정규식 탐지중...')
    const tMatch = performance.now()
    const r2 = await fetch(`${API_BASE()}/text/match`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: state.normalizedText,
        rules: state.rules,
        normalize: true,
      }),
    })
    if (!r2.ok) throw new Error(`매칭 실패 (${r2.status})\n${await r2.text()}`)
    const rawMatchData = await r2.json()
    state.timings.match_ms = performance.now() - tMatch
    state.matchData = filterMatchByRules(rawMatchData, state.rules)

    setStatus('NER 탐지중...')
    showLoading('NER 탐지중...')
    const tNer = performance.now()
    const excludeSpans = buildExcludeSpansFromMatch(state.matchData)
    const nerResp = state.normalizedText.trim()
      ? await requestNerSmart(
          state.normalizedText,
          excludeSpans,
          state.nerLabels
        )
      : { items: [] }
    state.timings.ner_ms = performance.now() - tNer
    state.nerItems = Array.isArray(nerResp?.items) ? nerResp.items : []

    state.detections = buildDetections(
      state.matchData,
      state.nerItems,
      state.nerLabels
    )
    state.detectionById = new Map(state.detections.map((d) => [d.id, d]))

    $('#doc-viewer-block')?.classList.remove('hidden')
    $('#doc-meta') &&
      ($('#doc-meta').textContent = `${
        f.name
      } · ${ext.toUpperCase()} · ${Math.max(1, Math.round(f.size / 1024))} KB`)

    renderCurrentPage()
    wireViewerClick()

    $('#doc-detect-count') &&
      ($('#doc-detect-count').textContent = String(state.detections.length))
    $('#doc-detect-count')?.classList.toggle('hidden', false)

    $('#detect-block')?.classList.remove('hidden')
    $('#detect-sub') &&
      ($(
        '#detect-sub'
      ).textContent = `탐지 ${state.detections.length}건 · 클릭하면 문서에서 하이라이트로 이동`)
    $('#detect-badge') &&
      ($('#detect-badge').textContent = String(state.detections.length))

    state.selectedGroup = 'ALL'
    renderBookmarks(state.detections)
    renderBookmarkItems()

    state.timings.total_ms = performance.now() - state.t0
    const report = computeScanStats({
      file: state.file,
      ext: state.ext,
      rules: state.rules,
      nerLabels: state.nerLabels,
      matchData: state.matchData,
      nerItems: state.nerItems,
      timings: state.timings,
    })
    renderScanReport(report)

    state.redactReady = true
    $('#btn-apply-redact') && ($('#btn-apply-redact').disabled = false)

    setStatus('탐지 완료')

    // 탐지 완료 후에만 “업로드 패널 숨기기/보이기” 버튼 활성화
    enableUploadToggle(true)
  } finally {
    hideLoading()
  }
}

async function doApplyRedact() {
  if (!state.file || !state.redactReady) return

  setStatus('레닥션 파일 생성 중...')
  const tRedact = performance.now()

  const fd = new FormData()
  fd.append('file', state.file)

  if (Array.isArray(state.rules) && state.rules.length) {
    fd.append('rules_json', JSON.stringify(state.rules))
  }
  if (Array.isArray(state.nerLabels) && state.nerLabels.length) {
    fd.append('ner_labels_json', JSON.stringify(state.nerLabels))
  }
  if (Array.isArray(state.nerItems) && state.nerItems.length) {
    fd.append('ner_entities_json', JSON.stringify(state.nerItems))
  }
  fd.append('masking_json', JSON.stringify(selectedMaskingPolicy()))

  const r = await fetch(`${API_BASE()}/redact/file`, {
    method: 'POST',
    body: fd,
  })
  if (!r.ok) throw new Error(`레닥션 실패 (${r.status})\n${await r.text()}`)

  const blob = await r.blob()
  const ctype = r.headers.get('Content-Type') || 'application/octet-stream'
  state.lastRedactedBlob = new Blob([blob], { type: ctype })

  state.timings.redact_ms = performance.now() - tRedact
  state.timings.total_ms = performance.now() - state.t0

  const report = computeScanStats({
    file: state.file,
    ext: state.ext,
    rules: state.rules,
    nerLabels: state.nerLabels,
    matchData: state.matchData,
    nerItems: state.nerItems,
    timings: state.timings,
  })
  renderScanReport(report)

  const btn = $('#btn-save-redacted')
  if (btn) {
    btn.classList.remove('hidden')
    btn.disabled = false
  }

  setStatus('레닥션 완료 — 다운로드 가능')
}

/** ---------- Download ---------- */
function downloadRedacted() {
  if (!state.lastRedactedBlob) return alert('레닥션된 파일이 없습니다.')
  const url = URL.createObjectURL(state.lastRedactedBlob)
  const a = document.createElement('a')
  a.href = url
  a.download = state.lastRedactedName || 'redacted_file'
  a.click()
  URL.revokeObjectURL(url)
}

/** ---------- Wire up ---------- */
function wireDetectControls() {
  $('#detect-search')?.addEventListener('input', (e) => {
    state.filters.q = String(e.target.value || '')
    renderBookmarkItems()
  })
  ;['flt-src-all', 'flt-src-regex', 'flt-src-ner'].forEach((id) => {
    $('#' + id)?.addEventListener('click', (e) => {
      applyFilterButtons('src', e.currentTarget.dataset.value)
    })
  })
  ;['flt-val-all', 'flt-val-ok', 'flt-val-fail'].forEach((id) => {
    $('#' + id)?.addEventListener('click', (e) => {
      applyFilterButtons('val', e.currentTarget.dataset.value)
    })
  })
}

document.addEventListener('DOMContentLoaded', () => {
  loadRules()
  setupDropZone()
  wireMaskButtons()
  wireDetectControls()
  setPages([''])

  // 업로드 패널 토글(탐지 완료 후 활성화)
  $('#btn-toggle-upload')?.addEventListener('click', () => {
    if (!state.ui.uploadToggleEnabled) return
    setUploadCollapsed(!state.ui.uploadCollapsed)
  })

  // 페이지 이동
  $('#btn-page-prev')?.addEventListener('click', () => {
    if (state.pageIndex > 0) {
      state.pageIndex -= 1
      renderCurrentPage()
    }
  })
  $('#btn-page-next')?.addEventListener('click', () => {
    const total = Math.max(1, state.pages.length || 1)
    if (state.pageIndex < total - 1) {
      state.pageIndex += 1
      renderCurrentPage()
    }
  })

  $('#btn-scan')?.addEventListener('click', async () => {
    try {
      await doScan()
    } catch (e) {
      console.error(e)
      setStatus(`오류: ${e.message || e}`)
      hideLoading()
    }
  })

  $('#btn-apply-redact')?.addEventListener('click', async () => {
    try {
      await doApplyRedact()
    } catch (e) {
      console.error(e)
      setStatus(`오류: ${e.message || e}`)
    }
  })

  $('#btn-save-redacted')?.addEventListener('click', downloadRedacted)

  $('#btn-stats-json-toggle')?.addEventListener('click', () => {
    const pre = $('#stats-json')
    if (!pre) return
    const nextHidden = !pre.classList.contains('hidden')
    pre.classList.toggle('hidden', nextHidden)
  })

  $('#btn-stats-download')?.addEventListener('click', () => {
    if (!state.file) return alert('리포트가 없습니다. 먼저 탐지를 실행하세요.')

    const report = computeScanStats({
      file: state.file,
      ext: state.ext,
      rules: state.rules,
      nerLabels: state.nerLabels,
      matchData: state.matchData,
      nerItems: state.nerItems,
      timings: state.timings,
    })

    const name0 = (report?.document?.name || 'report')
      .replace(/\.[^.]+$/, '')
      .slice(0, 120)
    const outName = `${name0}_risk_report.json`

    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: 'application/json',
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = outName
    a.click()
    URL.revokeObjectURL(url)
  })
  ;['#ner-show-ps', '#ner-show-lc', '#ner-show-og'].forEach((sel) => {
    $(sel)?.addEventListener('change', () => {
      setStatus('NER 선택이 변경되었습니다. 다시 “탐지 실행”을 누르세요.')
    })
  })
})
