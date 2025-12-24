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

  selectedId: null,

  filters: { q: '', seg: 'all' },

  ui: {},
}

/** ---------- Safe DOM helpers (핵심: null 방지) ---------- */
const byId = (id) => document.getElementById(id)

function safeText(id, v) {
  const el = byId(id)
  if (!el) return
  el.textContent = String(v ?? '')
}

function safeHtml(id, html) {
  const el = byId(id)
  if (!el) return
  el.innerHTML = String(html ?? '')
}

function safeShow(id, show = true) {
  const el = byId(id)
  if (!el) return
  el.classList.toggle('hidden', !show)
}

function safeClassRemove(id, cls) {
  const el = byId(id)
  if (!el) return
  el.classList.remove(cls)
}

function safeWidthPct(id, pct) {
  const el = byId(id)
  if (!el) return
  el.style.width = pct
}

function safeToggleHidden(id) {
  const el = byId(id)
  if (!el) return
  el.classList.toggle('hidden')
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

function safeJson(v) {
  try {
    return JSON.stringify(v ?? null)
  } catch {
    return null
  }
}

function parseContentDispositionFilename(cd) {
  // supports: filename="a.pdf" / filename*=UTF-8''%E3%85...
  if (!cd) return null
  const s = String(cd)
  const mStar = s.match(/filename\*\s*=\s*([^;]+)/i)
  if (mStar) {
    const v = mStar[1].trim()
    const m = v.match(/utf-8''(.+)/i)
    if (m) {
      try {
        return decodeURIComponent(m[1].replace(/^"|"$/g, ''))
      } catch {
        return m[1].replace(/^"|"$/g, '')
      }
    }
    return v.replace(/^"|"$/g, '')
  }
  const m = s.match(/filename\s*=\s*([^;]+)/i)
  if (!m) return null
  return m[1].trim().replace(/^"|"$/g, '')
}

function buildRedactedFallbackName(original) {
  const name = String(original || 'redacted')
  const dot = name.lastIndexOf('.')
  if (dot <= 0) return `${name}_redacted`
  return `${name.slice(0, dot)}_redacted${name.slice(dot)}`
}

function lockInputs(on) {
  $('#btn-scan') && ($('#btn-scan').disabled = !!on)
  $('#file') && ($('#file').disabled = !!on)
  $$('input[name="rule"]').forEach((el) => (el.disabled = !!on))
  ;['#ner-show-ps', '#ner-show-lc', '#ner-show-og'].forEach((sel) => {
    const el = $(sel)
    if (el) el.disabled = !!on
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

function clearViewerSelection() {
  const viewer = $('#doc-viewer')
  if (!viewer) return
  viewer.querySelectorAll('.pii-box[data-selected="1"]').forEach((el) => {
    el.removeAttribute('data-selected')
    el.classList.remove(
      'ring-4',
      'ring-indigo-500/20',
      'ring-offset-2',
      'ring-offset-white'
    )
  })
}

function applyViewerSelection(id) {
  const viewer = $('#doc-viewer')
  if (!viewer) return
  const spans = viewer.querySelectorAll(`.pii-box[data-id="${CSS.escape(id)}"]`)
  spans.forEach((el) => {
    el.setAttribute('data-selected', '1')
    el.classList.add(
      'ring-4',
      'ring-indigo-500/20',
      'ring-offset-2',
      'ring-offset-white'
    )
    el.scrollIntoView({ behavior: 'smooth', block: 'center' })
  })
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
      el.className =
        'flex items-center gap-2 cursor-pointer hover:text-indigo-600 transition'
      el.innerHTML = `<input type="checkbox" name="rule" value="${escHtml(
        rule
      )}" checked class="rounded border-zinc-300 text-indigo-600 focus:ring-indigo-500"><span>${escHtml(
        rule
      )}</span>`
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

/** ---------- Markdown fallback ---------- */
function fallbackMarkdownFromText(text) {
  return escHtml(String(text || ''))
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
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

function injectBoxesIntoMarkdown(md, detections) {
  let s = String(md || '')
  if (!s.trim() || !detections?.length) return s
  if (s.includes('class="pii-box"')) return s

  const tags = []
  s = s.replace(/<[^>]+>/g, (match) => {
    const placeholder = `__TAG_${tags.length}__`
    tags.push(match)
    return placeholder
  })

  let cursor = 0
  for (const d of detections) {
    const needle = String(d.text || '').trim()
    if (!needle || needle.length < 2) continue
    if (/^[A-Za-z]$/.test(needle)) continue

    let idx = s.indexOf(needle, cursor)
    if (idx < 0) idx = s.indexOf(needle, 0)
    if (idx < 0) continue

    const before = s.slice(0, idx)
    const after = s.slice(idx + needle.length)

    const tag =
      d.source === 'regex'
        ? `REGEX·${d.kind || 'UNK'}`
        : `NER·${d.label || 'UNK'}`

    const baseCls =
      'pii-box inline px-[2px] rounded-md cursor-pointer align-baseline'
    const clsOk =
      'bg-indigo-500/10 shadow-[inset_0_0_0_2px_rgba(79,70,229,0.95)]'
    const clsFail =
      'bg-gray-500/10 shadow-[inset_0_0_0_2px_rgba(107,114,128,0.95)] opacity-70'
    const cls = `${baseCls} ${d.valid ? clsOk : clsFail}`

    const attrs = [
      `class="${cls}"`,
      `data-id="${escHtml(d.id)}"`,
      `data-source="${escHtml(d.source)}"`,
      d.kind ? `data-kind="${escHtml(d.kind)}"` : '',
      d.label ? `data-label="${escHtml(d.label)}"` : '',
      `data-valid="${d.valid ? '1' : '0'}"`,
      `data-tag="${escHtml(tag)}"`,
    ]
      .filter(Boolean)
      .join(' ')

    const pill = `<span class="ml-1 inline-block px-1.5 py-0.5 rounded-full text-[10px] font-bold align-[2px] bg-gray-900/5 text-gray-900">${escHtml(
      tag
    )}</span>`
    const wrapped = `<span ${attrs}>${escHtml(needle)}${pill}</span>`
    s = before + wrapped + after
    cursor = (before + wrapped).length
  }

  tags.forEach((tag, i) => {
    s = s.replace(`__TAG_${i}__`, tag)
  })

  return s
}

function renderMarkdownToViewer(md, detections) {
  const viewer = $('#doc-viewer')
  if (!viewer) return

  const md2 = injectBoxesIntoMarkdown(
    normalizeTsvTablesToMarkdown(md),
    detections
  )

  let html = ''
  try {
    marked.setOptions({ gfm: true, breaks: true })
    html = marked.parse(md2)
  } catch {
    html = `<pre>${escHtml(md2)}</pre>`
  }

  const clean = DOMPurify.sanitize(html, {
    ADD_TAGS: [
      'span',
      'table',
      'thead',
      'tbody',
      'tr',
      'th',
      'td',
      'colgroup',
      'col',
    ],
    ADD_ATTR: [
      'class',
      'data-id',
      'data-source',
      'data-kind',
      'data-label',
      'data-valid',
      'data-tag',
      'colspan',
      'rowspan',
    ],
  })

  viewer.innerHTML = clean
  applyMarkdownTailwind(viewer)
}

function applyMarkdownTailwind(viewer) {
  if (!viewer) return

  const add = (sel, classes) => {
    const cls = String(classes).split(/\s+/).filter(Boolean)
    viewer.querySelectorAll(sel).forEach((el) => el.classList.add(...cls))
  }

  add('h1', 'text-2xl font-semibold mt-6 mb-3 tracking-tight')
  add('h2', 'text-xl font-semibold mt-5 mb-2 tracking-tight')
  add('h3', 'text-lg font-semibold mt-4 mb-2')
  add('p', 'my-2')
  add('ul', 'my-2 pl-5 list-disc')
  add('ol', 'my-2 pl-5 list-decimal')
  add('li', 'my-1')
  add('blockquote', 'my-3 pl-4 border-l-4 border-gray-200 text-gray-600')
  add('a', 'text-blue-600 underline break-words')
  add('hr', 'my-4 border-gray-200')

  add(
    'pre',
    'my-3 bg-[#0b1220] text-gray-200 p-3 rounded-xl overflow-visible whitespace-pre-wrap break-words border border-white/10'
  )
  add('code', 'font-mono text-[12px]')

  add('table', 'w-full border-collapse my-2 text-[12px]')
  add('th', 'border border-gray-200 px-2 py-1 text-left bg-gray-50 align-top')
  add('td', 'border border-gray-200 px-2 py-1 align-top')
}

function normalizeTsvTablesToMarkdown(md) {
  const src = String(md || '')
  if (!src) return src
  if (src.includes('<table')) return src

  const lines = src.split('\n')
  const out = []
  let inFence = false

  const escCell = (s) => String(s ?? '').replace(/\|/g, '\\|')
  const toPipeRow = (cells) => `| ${cells.map(escCell).join(' | ')} |`

  const emitTable = (rows) => {
    if (!rows || rows.length < 2) return false
    const hasSeparator = rows.some(
      (row) => row.length >= 2 && row.every((cell) => /^[ \-\:]+$/.test(cell))
    )
    if (hasSeparator) return false

    const colCount = Math.max(...rows.map((r) => r.length))
    if (colCount < 2) return false
    const norm = rows.map((r) => {
      const rr = r.slice(0, colCount)
      while (rr.length < colCount) rr.push('')
      return rr
    })
    const header = norm[0]
    const body = norm.slice(1)
    const sep = Array.from({ length: colCount }, () => '---')
    out.push('', toPipeRow(header), toPipeRow(sep))
    for (const r of body) out.push(toPipeRow(r))
    out.push('')
    return true
  }

  const splitBySpaces = (line) =>
    line
      .trimEnd()
      .split(/\s{2,}/)
      .map((c) => c.trim())
  const splitByPipe = (line) => {
    const s = String(line || '').trim()
    const core = s.replace(/^\|/, '').replace(/\|$/, '')
    return core.split('|').map((c) => c.trim())
  }

  let i = 0
  while (i < lines.length) {
    const line = lines[i]
    const fence = line.trim().startsWith('```')
    if (fence) {
      inFence = !inFence
      out.push(line)
      i++
      continue
    }
    if (inFence) {
      out.push(line)
      i++
      continue
    }

    if (line.includes('\t')) {
      const run = []
      while (
        i < lines.length &&
        lines[i].includes('\t') &&
        lines[i].trim() !== ''
      ) {
        run.push(lines[i])
        i++
      }
      if (run.length >= 2) {
        if (emitTable(run.map((l) => l.split('\t').map((c) => c.trim()))))
          continue
      }
      out.push(...run)
      continue
    }

    if (
      line.includes('|') &&
      line.trim() !== '' &&
      splitByPipe(line).length >= 2
    ) {
      const run = []
      while (
        i < lines.length &&
        lines[i].trim() !== '' &&
        lines[i].includes('|') &&
        splitByPipe(lines[i]).length >= 2
      ) {
        run.push(lines[i])
        i++
      }
      if (run.length >= 2) {
        if (emitTable(run.map(splitByPipe))) continue
      }
      out.push(...run)
      continue
    }

    const looksSpaceTableRow =
      /\s{2,}/.test(line) &&
      splitBySpaces(line).length >= 2 &&
      line.trim() !== ''
    if (looksSpaceTableRow) {
      const run = []
      while (
        i < lines.length &&
        lines[i].trim() !== '' &&
        /\s{2,}/.test(lines[i]) &&
        splitBySpaces(lines[i]).length >= 2
      ) {
        run.push(lines[i])
        i++
      }
      if (run.length >= 3) {
        if (emitTable(run.map(splitBySpaces))) continue
      }
      out.push(...run)
      continue
    }

    out.push(line)
    i++
  }
  return out.join('\n')
}

function applyDocOrientationHint(md, viewerEl = null) {
  const pageEl = document.getElementById('doc-page')
  if (!pageEl) return
  let orient = 'portrait'
  const src = String(md || '')
  if (src.includes('<table')) orient = 'landscape'
  else {
    for (const line of src.split('\n')) {
      if (line.includes('|')) {
        const cols = line.split('|').filter(Boolean).length
        if (cols >= 4) {
          orient = 'landscape'
          break
        }
      }
    }
  }
  const v = viewerEl || document.getElementById('doc-viewer')
  if (v && v.querySelectorAll('table').length > 0) orient = 'landscape'
  pageEl.classList.toggle('max-w-[1018px]', orient === 'landscape')
  pageEl.classList.toggle('max-w-[680px]', orient !== 'landscape')
}

/** ---------- Match / NER Results (right panel) ---------- */
function setActiveResultItem(id) {
  $$('.hit-btn').forEach((el) => {
    el.classList.remove('border-gray-900', 'ring-2', 'ring-gray-900/20')
  })
  $$('.ner-row').forEach((el) => {
    el.classList.remove('bg-indigo-50')
  })
  if (!id) return
  const btn = $(`.hit-btn[data-id="${CSS.escape(id)}"]`)
  if (btn) {
    btn.classList.add('border-gray-900', 'ring-2', 'ring-gray-900/20')
    btn.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
  }
  const row = $(`.ner-row[data-id="${CSS.escape(id)}"]`)
  if (row) {
    row.classList.add('bg-indigo-50')
    row.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
  }
}

function updateSegButtons(seg) {
  const all = document.getElementById('seg-all')
  const ok = document.getElementById('seg-ok')
  const fail = document.getElementById('seg-fail')
  if (!all || !ok || !fail) return

  all.className =
    'px-3 py-1.5 text-xs ' +
    (seg === 'all'
      ? 'bg-gray-900 text-white'
      : 'text-gray-700 hover:bg-gray-50')
  ok.className =
    'px-3 py-1.5 text-xs ' +
    (seg === 'ok'
      ? 'bg-gray-900 text-white'
      : 'text-emerald-700 hover:bg-emerald-50')
  fail.className =
    'px-3 py-1.5 text-xs ' +
    (seg === 'fail'
      ? 'bg-gray-900 text-white'
      : 'text-rose-700 hover:bg-rose-50')
}

function renderMatchResults() {
  const groups = $('#match-groups')
  if (!groups) return

  const seg = state.filters.seg || 'all'
  const q = String(state.filters.q || '')
    .trim()
    .toLowerCase()

  let items = state.detections.filter((d) => d.source === 'regex')
  if (seg === 'ok') items = items.filter((d) => d.valid)
  if (seg === 'fail') items = items.filter((d) => !d.valid)
  if (q) {
    items = items.filter((d) =>
      `${d.text} ${d.kind || ''} ${d.rule || ''}`.toLowerCase().includes(q)
    )
  }

  const total = state.detections.filter((d) => d.source === 'regex').length
  const ok = state.detections.filter(
    (d) => d.source === 'regex' && d.valid
  ).length
  const fail = total - ok

  const summary = $('#summary')
  if (summary) summary.textContent = `총 ${total} · OK ${ok} · FAIL ${fail}`

  groups.innerHTML = ''
  if (!items.length) {
    groups.innerHTML =
      '<div class="text-[12px] text-gray-400 p-3 text-center">표시할 항목이 없습니다.</div>'
    return
  }

  const byKind = new Map()
  for (const d of items) {
    const k = d.kind || 'UNKNOWN'
    if (!byKind.has(k)) byKind.set(k, [])
    byKind.get(k).push(d)
  }

  for (const [k, arr] of byKind.entries()) {
    const card = document.createElement('div')
    card.className = 'rounded-xl border border-gray-200 overflow-hidden'
    card.innerHTML = `<div class="px-3 py-2 text-xs font-semibold bg-gray-50">${escHtml(
      k
    )} <span class="ml-1 text-gray-400 font-normal">${arr.length}</span></div>`

    const body = document.createElement('div')
    body.className = 'p-2 space-y-2'
    for (const d of arr) {
      const btn = document.createElement('button')
      btn.type = 'button'
      btn.className =
        'hit-btn w-full text-left border border-gray-200 rounded-xl px-3 py-2 bg-white hover:bg-gray-50 transition'
      btn.dataset.id = d.id

      const badge = d.valid
        ? '<span class="text-[10px] font-semibold text-emerald-700">OK</span>'
        : '<span class="text-[10px] font-semibold text-rose-700">FAIL</span>'
      btn.innerHTML = `
        <div class="flex items-start justify-between gap-2">
          <div class="min-w-0">
            <div class="text-[10px] opacity-50">${escHtml(d.rule || '')}</div>
            <div class="truncate text-sm">${escHtml(d.text)}</div>
          </div>
          <div class="shrink-0">${badge}</div>
        </div>
      `
      btn.addEventListener('click', () => {
        state.selectedId = d.id
        setActiveResultItem(d.id)
        clearViewerSelection()
        applyViewerSelection(d.id)
      })
      body.appendChild(btn)
    }
    card.appendChild(body)
    groups.appendChild(card)
  }
}

function renderNerResults() {
  const rows = $('#ner-rows')
  if (!rows) return

  const items = state.detections.filter((d) => d.source === 'ner')

  const scores = items
    .map((d) => (typeof d.score === 'number' ? d.score : null))
    .filter((x) => x != null)
  const avg = scores.length
    ? scores.reduce((a, b) => a + b, 0) / scores.length
    : null
  const sum = $('#ner-summary')
  if (sum) sum.textContent = `총 ${items.length} · 평균 score ${Score(avg)}`

  rows.innerHTML = ''
  for (const d of items) {
    const tr = document.createElement('tr')
    tr.className = 'ner-row border-b hover:bg-gray-50 cursor-pointer'
    tr.dataset.id = d.id
    tr.innerHTML = `
      <td class="py-2 px-2 font-semibold">${escHtml(d.label || '')}</td>
      <td class="py-2 px-2">${escHtml(d.text)}</td>
      <td class="py-2 px-2 font-mono">${escHtml(Score(d.score))}</td>
      <td class="py-2 px-2 font-mono text-[12px] opacity-70">${escHtml(
        `${d.start ?? '-'}-${d.end ?? '-'}`
      )}</td>
    `
    tr.addEventListener('click', () => {
      state.selectedId = d.id
      setActiveResultItem(d.id)
      clearViewerSelection()
      applyViewerSelection(d.id)
    })
    rows.appendChild(tr)
  }
}

function setMatchTab(tab) {
  const t = tab === 'ner' ? 'ner' : 'regex'
  state.ui = state.ui || {}
  state.ui.matchTab = t

  const paneRegex = $('#match-pane-regex')
  const paneNer = $('#match-pane-ner')
  paneRegex && paneRegex.classList.toggle('hidden', t !== 'regex')
  paneNer && paneNer.classList.toggle('hidden', t !== 'ner')

  const label = $('#match-tab-label')
  if (label) label.textContent = t === 'regex' ? '정규식' : 'NER'

  const badge = $('#match-badge')
  if (badge) {
    const n =
      t === 'regex'
        ? state.detections.filter((d) => d.source === 'regex').length
        : state.detections.filter((d) => d.source === 'ner').length
    badge.textContent = String(n)
  }
}

function wireMatchTabs() {
  const prev = $('#btn-match-prev')
  const next = $('#btn-match-next')
  if (prev)
    prev.addEventListener('click', () =>
      setMatchTab((state.ui?.matchTab || 'regex') === 'regex' ? 'ner' : 'regex')
    )
  if (next)
    next.addEventListener('click', () =>
      setMatchTab((state.ui?.matchTab || 'regex') === 'regex' ? 'ner' : 'regex')
    )
}

function wireViewerClick() {
  const viewer = $('#doc-viewer')
  if (!viewer) return
  viewer.addEventListener('click', (e) => {
    const sp = e.target.closest('.pii-box')
    if (!sp) return
    const id = sp.getAttribute('data-id')
    if (!id) return
    state.selectedId = id
    clearViewerSelection()
    applyViewerSelection(id)
    setActiveResultItem(id)
    const d = state.detectionById?.get(id)
    if (d?.source === 'ner') setMatchTab('ner')
    else setMatchTab('regex')
  })
}

/** ---------- Stats & Report ---------- */
function pad2(n) {
  return String(n).padStart(2, '0')
}
function formatIsoToLocalKorean(iso) {
  if (!iso) return '-'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return String(iso)
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(
    d.getDate()
  )} (${pad2(d.getHours())}:${pad2(d.getMinutes())})`
}
function Score(v) {
  if (typeof v !== 'number' || !Number.isFinite(v)) return '-'
  return v.toFixed(2)
}

function computeScanStats({ matchData, nerItems, nerLabels, timings }) {
  const mdItems = Array.isArray(matchData?.items) ? matchData.items : []
  const ner = Array.isArray(nerItems) ? nerItems : []
  const allow = new Set((nerLabels || []).map((x) => String(x).toUpperCase()))

  let regex_ok = 0,
    regex_fail = 0
  const by_kind = {}
  for (const it of mdItems) {
    if (it?.valid) {
      regex_ok++
      const k = ruleToKind(it.rule)
      by_kind[k] = (by_kind[k] || 0) + 1
    } else regex_fail++
  }

  const by_label = {}
  const scores = []
  let nerAllowedCount = 0
  for (const it of ner) {
    const lab = String(it?.label || '').toUpperCase()
    if (!allow.has(lab)) continue
    nerAllowedCount++
    by_label[lab] = (by_label[lab] || 0) + 1
    if (typeof it?.score === 'number') scores.push(it.score)
  }

  // (기존 로직 유지) 점수는 지표일 뿐이니 대충: 정규식 OK 가중 + NER 허용 라벨 수 가중
  const risk = Math.min(100, Math.round(regex_ok * 10 + nerAllowedCount * 2))
  const nerAvg = scores.length
    ? scores.reduce((a, b) => a + b, 0) / scores.length
    : null

  return {
    risk_score: risk,
    total_raw: mdItems.length + nerAllowedCount,
    total_unique: Array.isArray(state.detections) ? state.detections.length : 0,
    regex_ok,
    regex_fail,
    by_kind,
    by_label,
    ner_avg: Score(nerAvg),
    timings: timings || {},
  }
}

function renderScanReport(stats) {
  if (!stats) return

  // stats 블록은 있어도 되고 없어도 됨(없으면 그냥 스킵)
  safeShow('stats-report-block', true)

  safeText('stats-risk-score', stats.risk_score)
  safeWidthPct('stats-risk-meter', `${stats.risk_score}%`)
  safeText('stats-total-unique', stats.total_unique)
  safeText('stats-total-raw', stats.total_raw)
  safeText('stats-regex-ok', stats.regex_ok)
  safeText('stats-regex-fail', stats.regex_fail)
  safeText('stats-ner-avg', stats.ner_avg)

  const kindBody = byId('stats-by-kind-rows')
  if (kindBody) {
    kindBody.innerHTML = Object.entries(stats.by_kind || {})
      .sort((a, b) => b[1] - a[1])
      .map(
        ([k, v]) =>
          `<tr>
            <td class="py-2 pl-4 pr-2 font-medium text-zinc-900">${escHtml(
              k
            )}</td>
            <td class="py-2 pr-5 text-right font-bold text-zinc-500">${escHtml(
              v
            )}</td>
          </tr>`
      )
      .join('')
  }

  const labelBody = byId('stats-by-label-rows')
  if (labelBody) {
    labelBody.innerHTML = Object.entries(stats.by_label || {})
      .sort((a, b) => b[1] - a[1])
      .map(
        ([k, v]) =>
          `<tr>
            <td class="py-2 pl-4 pr-2 font-medium text-zinc-900">${escHtml(
              k
            )}</td>
            <td class="py-2 pr-5 text-right font-bold text-zinc-500">${escHtml(
              v
            )}</td>
          </tr>`
      )
      .join('')
  }

  safeText('t-extract', Math.round(stats.timings.extract_ms || 0) + 'ms')
  safeText('t-match', Math.round(stats.timings.match_ms || 0) + 'ms')
  safeText('t-ner', Math.round(stats.timings.ner_ms || 0) + 'ms')
  safeText('t-redact', Math.round(stats.timings.redact_ms || 0) + 'ms')
  safeText('t-total', Math.round(stats.timings.total_ms || 0) + 'ms')

  // 정책(선택한 규칙/라벨 표시)
  const selectedRules = Array.isArray(state.rules) ? state.rules : []
  const selectedNer = Array.isArray(state.nerLabels) ? state.nerLabels : []

  const detectedRuleSet = new Set()
  const mdItems = Array.isArray(state.matchData?.items)
    ? state.matchData.items
    : []
  for (const it of mdItems) {
    if (it?.valid === false) continue
    if (!it?.rule) continue
    detectedRuleSet.add(String(it.rule))
  }

  const rulesBox = byId('stats-policy-rules')
  if (rulesBox) {
    rulesBox.innerHTML = selectedRules
      .map((r) => {
        const isHit = detectedRuleSet.has(String(r))
        const label = ruleToKind(r)
        const cls = isHit
          ? 'border-indigo-200 bg-indigo-50 text-indigo-700'
          : 'border-gray-200 bg-gray-50 text-gray-600'
        return `<span class="inline-flex items-center gap-1 px-2 py-1 rounded-full border text-[11px] ${cls}">${escHtml(
          label
        )}</span>`
      })
      .join('')
  }

  const nerBox = byId('stats-policy-nerlabels')
  if (nerBox) {
    nerBox.innerHTML = selectedNer
      .map(
        (lab) =>
          `<span class="inline-flex items-center px-2 py-1 rounded-full border border-gray-200 bg-gray-50 text-gray-600 text-[11px]">${escHtml(
            String(lab).toUpperCase()
          )}</span>`
      )
      .join('')
  }

  safeText('stats-json', JSON.stringify(stats, null, 2))
}

/** ---------- Main: Scan ---------- */
async function doScan() {
  const f = $('#file')?.files?.[0]
  if (!f) return alert('파일을 선택하세요.')

  state.file = f
  state.ext = (f.name.split('.').pop() || '').toLowerCase()
  state.rules = selectedRuleNames()
  state.nerLabels = selectedNerLabels()
  state.t0 = performance.now()

  setStatus('분석 시작...')
  lockInputs(true)

  try {
    const fd = new FormData()
    fd.append('file', f)

    const t1 = performance.now()
    const r1 = await fetch(`${API_BASE()}/text/extract`, {
      method: 'POST',
      body: fd,
    })
    if (!r1.ok) throw new Error('추출 실패')
    const extractData = await r1.json()
    state.timings = { extract_ms: performance.now() - t1 }

    const fullText = String(extractData.full_text || '')
    state.extractedText = fullText

    const md = extractData.markdown || fallbackMarkdownFromText(fullText)
    state.markdown = md
    setPages([md])

    const t2 = performance.now()
    setStatus('패턴 탐색...')
    const r2 = await fetch(`${API_BASE()}/text/match`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: fullText,
        rules: state.rules,
        normalize: true,
      }),
    })
    const rawMatchData = await r2.json()
    state.timings.match_ms = performance.now() - t2
    state.matchData = filterMatchByRules(rawMatchData, state.rules)

    const t3 = performance.now()
    setStatus('NER 탐지...')
    const nerResp = await requestNerSmart(
      fullText,
      buildExcludeSpansFromMatch(state.matchData),
      state.nerLabels
    )
    state.timings.ner_ms = performance.now() - t3
    state.nerItems = nerResp.items

    state.detections = buildDetections(
      state.matchData,
      state.nerItems,
      state.nerLabels
    )
    state.detectionById = new Map(state.detections.map((d) => [d.id, d]))

    safeClassRemove('doc-viewer-block', 'hidden')
    safeClassRemove('match-tabs-block', 'hidden')
    safeText(
      'doc-meta',
      `${f.name} · ${state.ext.toUpperCase()} · ${Math.round(f.size / 1024)}KB`
    )
    safeText('doc-detect-count', state.detections.length)

    // 오른쪽 badge(현재 탭은 setMatchTab에서 갱신)
    const mb = byId('match-badge')
    if (mb) {
      mb.textContent = String(
        state.detections.filter((d) => d.source === 'regex').length
      )
    }

    renderCurrentPage()
    wireViewerClick()
    renderMatchResults()
    renderNerResults()
    setMatchTab('regex')

    state.timings.total_ms = performance.now() - state.t0
    renderScanReport(
      computeScanStats({
        matchData: state.matchData,
        nerItems: state.nerItems,
        nerLabels: state.nerLabels,
        timings: state.timings,
      })
    )

    setStatus('완료')

    const btn = $('#btn-save-redacted')
    if (btn) {
      btn.classList.remove('hidden')
      btn.disabled = false
    }
  } catch (e) {
    console.error(e)
    setStatus('오류 발생')
  } finally {
    lockInputs(false)
  }
}

/** ---------- Redact + Download ---------- */
async function doRedactAndDownload() {
  const f = $('#file')?.files?.[0]
  if (!f) return alert('파일을 선택하세요.')

  if (!state.file || state.file !== f || !state.extractedText) {
    await doScan()
  }
  if (!state.file) return

  const btn = $('#btn-save-redacted')
  btn && (btn.disabled = true)

  setStatus('레닥션 실행 중...')
  lockInputs(true)

  const t0 = performance.now()
  try {
    const fd = new FormData()
    fd.append('file', state.file)

    const rulesJson = safeJson(state.rules || [])
    const labelsJson = safeJson(state.nerLabels || [])
    const entsJson = safeJson(state.nerItems || [])

    rulesJson && fd.append('rules_json', rulesJson)
    labelsJson && fd.append('ner_labels_json', labelsJson)
    entsJson && fd.append('ner_entities_json', entsJson)

    const r = await fetch(`${API_BASE()}/redact/file`, {
      method: 'POST',
      body: fd,
    })
    if (!r.ok) {
      const msg = await r.text().catch(() => '')
      throw new Error(msg || '레닥션 실패')
    }

    const blob = await r.blob()
    const cd = r.headers.get('Content-Disposition')
    const filename =
      parseContentDispositionFilename(cd) ||
      buildRedactedFallbackName(state.file?.name)

    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    a.remove()
    setTimeout(() => URL.revokeObjectURL(url), 1500)

    state.timings = state.timings || {}
    state.timings.redact_ms = performance.now() - t0
    safeText('t-redact', Math.round(state.timings.redact_ms) + 'ms')

    if (state.t0) {
      state.timings.total_ms = performance.now() - state.t0
      safeText('t-total', Math.round(state.timings.total_ms) + 'ms')
    }

    setStatus('레닥션 완료 · 다운로드 시작')
  } catch (e) {
    console.error(e)
    alert(`레닥션 실패: ${e?.message || e}`)
    setStatus('레닥션 오류')
  } finally {
    btn && (btn.disabled = false)
    lockInputs(false)
  }
}

function renderCurrentPage() {
  updatePageControls()
  renderMarkdownToViewer(state.markdown, state.detections)
  applyDocOrientationHint(state.markdown, $('#doc-viewer'))
}

/** ---------- Init ---------- */
document.addEventListener('DOMContentLoaded', () => {
  loadRules()
  setupDropZone()
  wireMatchTabs()
  updateSegButtons(state.filters.seg || 'all')

  $('#file')?.addEventListener('change', () => {
    const btn = $('#btn-save-redacted')
    if (btn) {
      btn.classList.add('hidden')
      btn.disabled = true
    }
    state.file = $('#file')?.files?.[0] || null
    state.extractedText = ''
    state.markdown = ''
    state.matchData = null
    state.nerItems = []
    state.detections = []
    state.detectionById = new Map()
    state.timings = null
    state.t0 = null
    setStatus('파일 선택됨 · 스캔 실행')
  })

  $('#filter-search')?.addEventListener('input', (e) => {
    state.filters.q = e.target.value
    renderMatchResults()
  })
  ;['seg-all', 'seg-ok', 'seg-fail'].forEach((id) => {
    const el = document.getElementById(id)
    if (!el) return
    el.addEventListener('click', () => {
      state.filters.seg = el.dataset.seg || 'all'
      updateSegButtons(state.filters.seg)
      renderMatchResults()
    })
  })

  $('#btn-scan')?.addEventListener('click', doScan)
  $('#btn-save-redacted')?.addEventListener('click', doRedactAndDownload)
  $('#btn-stats-json-toggle')?.addEventListener('click', () =>
    safeToggleHidden('stats-json')
  )
})
