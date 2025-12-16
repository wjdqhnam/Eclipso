const API_BASE = () => window.API_BASE || 'http://127.0.0.1:8000'
const HWPX_VIEWER_URL = window.HWPX_VIEWER_URL || ''

const $ = (sel) => document.querySelector(sel)
const $$ = (sel) => Array.from(document.querySelectorAll(sel))

let __lastRedactedBlob = null
let __lastRedactedName = 'redacted.bin'

const esc = (s) =>
  (s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

const badge = (sel, n) => {
  const el = $(sel)
  if (el) el.textContent = String(n ?? 0)
}

const setOpen = (name, open) => {
  const cont =
    name === 'pdf' ? $('#pdf-preview-block') : $(`#${name}-result-block`)
  const body = $(`#${name}-body`)
  const chev = document.querySelector(`[data-chevron="${name}"]`)
  cont && cont.classList.remove('hidden')
  body && body.classList.toggle('hidden', !open)
  chev && chev.classList.toggle('rotate-180', !open)
}
document.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-toggle]')
  if (!btn) return
  const name = btn.getAttribute('data-toggle')
  const body = document.getElementById(`${name}-body`)
  setOpen(name, body ? body.classList.contains('hidden') : true)
})

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
      el.innerHTML = `<input type="checkbox" name="rule" value="${rule}" checked><span>${esc(
        rule
      )}</span>`
      box.appendChild(el)
    }
  } catch {
    console.warn('규칙 불러오기 실패')
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

function setupDropZone() {
  const dz = $('#dropzone'),
    input = $('#file'),
    nameEl = $('#file-name'),
    statusEl = $('#status')
  if (!dz || !input) return

  let depth = 0
  const setActive = (on) => {
    dz.classList.toggle('ring-2', on)
    dz.classList.toggle('ring-blue-400', on)
    dz.classList.toggle('bg-blue-50', on)
  }
  const showName = (f) => {
    if (nameEl) nameEl.textContent = f ? `선택됨: ${f.name}` : ''
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
    if (!file) {
      statusEl && (statusEl.textContent = '드래그한 항목이 파일이 아닙니다.')
      return
    }
    const repl = new DataTransfer()
    repl.items.add(file)
    input.files = repl.files
    input.dispatchEvent(new Event('change', { bubbles: true }))
    showName(file)
    statusEl &&
      (statusEl.textContent = '파일 선택 완료 — 스캔 실행을 눌러주세요.')
  })
  input.addEventListener('change', (e) => showName(e.target.files?.[0] || null))
}

async function renderRedactedPdfPreview(blob) {
  const cv = $('#pdf-preview')
  if (!cv) return
  const g = cv.getContext('2d')
  if (!blob) return g.clearRect(0, 0, cv.width, cv.height)
  const pdf = await pdfjsLib.getDocument({ data: await blob.arrayBuffer() })
    .promise
  const page = await pdf.getPage(1)
  const vp = page.getViewport({ scale: 1.2 })
  cv.width = vp.width
  cv.height = vp.height
  await page.render({ canvasContext: g, viewport: vp }).promise
}

function highlightFrag(ctx, val) {
  const src = ctx || ''
  const needle = val || ''

  const i = src.indexOf(needle)
  if (i < 0) return esc(src)

  const pre = esc(src.slice(0, i))
  const mid = esc(needle)
  const post = esc(src.slice(i + needle.length))

  return pre + `<mark class="bg-yellow-200 rounded px-1">${mid}</mark>` + post
}

let __segFilter = 'all'
function applySegmentFilter(root) {
  root.querySelectorAll('[data-valid]').forEach((el) => {
    const ok = el.getAttribute('data-valid') === '1'
    let show = true
    if (__segFilter === 'ok') show = ok
    else if (__segFilter === 'fail') show = !ok
    el.style.display = show ? '' : 'none'
  })
}
function wireSegmentButtons(root) {
  const setActive = (which) => {
    __segFilter = which
    ;['all', 'ok', 'fail'].forEach((k) => {
      const btn = $(`#seg-${k}`)
      if (!btn) return
      btn.classList.remove(
        'bg-gray-900',
        'text-white',
        'bg-emerald-600',
        'bg-rose-600'
      )
      if (k === 'all' && which === 'all')
        btn.classList.add('bg-gray-900', 'text-white')
      if (k === 'ok' && which === 'ok')
        btn.classList.add('bg-emerald-600', 'text-white')
      if (k === 'fail' && which === 'fail')
        btn.classList.add('bg-rose-600', 'text-white')
    })
    applySegmentFilter(root)
  }
  $('#seg-all')?.addEventListener('click', () => setActive('all'))
  $('#seg-ok')?.addEventListener('click', () => setActive('ok'))
  $('#seg-fail')?.addEventListener('click', () => setActive('fail'))
  setActive(__segFilter)
}

function renderRegexResults(res) {
  const items = Array.isArray(res?.items) ? res.items : []
  badge('#match-badge', items.length)

  const summary = $('#summary')
  if (summary) {
    const counts = res?.counts || {}
    summary.textContent = `검출: ${
      Object.keys(counts).length
        ? Object.entries(counts)
            .map(([k, v]) => `${k}=${v}`)
            .join(', ')
        : '없음'
    }`
  }

  const wrap = $('#match-groups')
  if (!wrap) return
  wrap.innerHTML = ''

  const groups = {}
  for (const it of items) (groups[it.rule || 'UNKNOWN'] ??= []).push(it)

  for (const [rule, arr] of Object.entries(groups).sort(
    (a, b) => b[1].length - a[1].length
  )) {
    const ok = arr.filter((x) => x.valid).length
    const fail = arr.length - ok

    const container = document.createElement('div')
    container.className = 'rounded-2xl border border-gray-200'
    container.innerHTML = `
      <button class="w-full flex items-center justify-between px-4 py-2.5 bg-gray-50 hover:bg-gray-100 rounded-t-2xl">
        <div class="flex items-center gap-2">
          <span class="text-sm font-semibold">${esc(rule)}</span>
          <span class="text-xs text-gray-500">총 ${arr.length}건</span>
          <span class="text-[10px] px-1.5 py-0.5 rounded bg-emerald-100 text-emerald-700">OK ${ok}</span>
          ${
            fail
              ? `<span class="text-[10px] px-1.5 py-0.5 rounded bg-rose-100 text-rose-700">FAIL ${fail}</span>`
              : ''
          }
        </div>
        <svg class="h-4 w-4 text-gray-500 transition-transform" viewBox="0 0 20 20" fill="currentColor">
          <path fill-rule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 10.94l3.71-3.7a.75.75 0 111.06 1.06l-4.24 4.24a.75.75 0 01-1.06 0L5.21 8.29a.75.75 0 01.02-1.08z" clip-rule="evenodd"/>
        </svg>
      </button>
      <div class="p-3 grid gap-2 rounded-b-2xl"></div>
    `
    const body = container.querySelector('.p-3')

    for (const r of arr) {
      const isOk = !!r.valid
      const ctx = r.context || ''
      const val = r.value || ''
      const card = document.createElement('div')
      card.dataset.valid = isOk ? '1' : '0'
      card.className =
        'border rounded-xl p-3 bg-white hover:shadow-sm transition ' +
        (isOk ? 'border-emerald-200' : 'border-rose-200')

      card.innerHTML = `
        <div class="flex items-start justify-between gap-3">
          <div class="min-w-0">
            <div class="text-sm font-mono break-all">${esc(val)}</div>
            <div class="text-[12px] text-gray-600 mt-1 leading-relaxed break-words">
              ${highlightFrag(ctx, val)}
            </div>
          </div>
          <div class="shrink-0">
            <span class="inline-block text-[11px] px-1.5 py-0.5 rounded border ${
              isOk
                ? 'border-emerald-300 text-emerald-700'
                : 'border-rose-300 text-rose-700'
            }">${isOk ? 'OK' : 'FAIL'}</span>
          </div>
        </div>
      `
      body.appendChild(card)
    }

    let open = arr.length <= 10
    body.style.display = open ? '' : 'none'
    container.querySelector('button')?.addEventListener('click', () => {
      open = !open
      body.style.display = open ? '' : 'none'
      container.querySelector('svg')?.classList.toggle('rotate-180', !open)
    })

    wrap.appendChild(container)
  }

  wireSegmentButtons(wrap)

  $('#filter-search')?.addEventListener('input', (e) => {
    const q = (e.target.value || '').toLowerCase()
    wrap.querySelectorAll('[data-valid]').forEach((el) => {
      const txt = el.textContent.toLowerCase()
      const match = !q || txt.includes(q)
      el.style.display = match ? '' : 'none'
    })
    applySegmentFilter(wrap)
  })

  applySegmentFilter(wrap)
}

function parseMarkdownTables(markdown) {
  const lines = (markdown || '').split(/\r?\n/)
  const tables = []
  let current = []

  for (const raw of lines) {
    const line = raw.trim()
    if (/^\s*\|.*\|\s*$/.test(line)) {
      current.push(line)
    } else {
      if (current.length >= 2) tables.push(current.slice())
      current = []
    }
  }
  if (current.length >= 2) tables.push(current.slice())
  return tables
}

function tableBlockToHtml(block) {
  if (!block || block.length < 2) return ''
  const headerLine = block[0]
  const headerCells = headerLine
    .split('|')
    .slice(1, -1)
    .map((s) => s.trim())
  const bodyLines = block.slice(2)

  let html =
    '<table class="min-w-full border border-gray-300 text-[11px] text-left border-collapse">'
  html += '<thead><tr>'
  for (const h of headerCells) {
    html += `<th class="border border-gray-300 px-2 py-1 bg-gray-50">${esc(
      h
    )}</th>`
  }
  html += '</tr></thead><tbody>'

  for (const line of bodyLines) {
    const cells = line
      .split('|')
      .slice(1, -1)
      .map((s) => s.trim())
    if (!cells.length) continue
    html += '<tr>'
    for (const c of cells) {
      html += `<td class="border border-gray-300 px-2 py-1 align-top">${esc(
        c
      )}</td>`
    }
    html += '</tr>'
  }
  html += '</tbody></table>'
  return html
}

function buildPlainTextFromMarkdown(markdown) {
  const lines = (markdown || '').split(/\r?\n/)
  const out = []
  let inTable = false

  for (const raw of lines) {
    const line = raw.trim()
    const isTableRow = /^\s*\|.*\|\s*$/.test(line)

    if (isTableRow) {
      inTable = true
      continue
    }

    if (!isTableRow && inTable) inTable = false
    if (!inTable) out.push(raw)
  }

  return out.join('\n').trim()
}

function renderTablePreview(markdown) {
  const wrap = $('#text-table-preview')
  if (!wrap) return 0
  wrap.innerHTML = ''

  const blocks = parseMarkdownTables(markdown)
  if (!blocks.length) return 0

  const parts = []
  parts.push(
    '<div class="text-[11px] text-gray-500 mb-1">표 구조 미리보기</div>'
  )
  blocks.forEach((block, idx) => {
    if (idx > 0) parts.push('<div class="h-2"></div>')
    parts.push(tableBlockToHtml(block))
  })
  wrap.innerHTML = parts.join('')
  return blocks.length
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

function normalizeNerItems(raw) {
  if (!raw) return { items: [] }

  // 서버가 준 그대로
  if (Array.isArray(raw.entities)) {
    return { items: raw.entities }
  }

  // (혹시 다른 형태로 올 경우에만 최소 호환)
  if (Array.isArray(raw.items)) return { items: raw.items }
  if (Array.isArray(raw)) return { items: raw }

  return { items: [] }
}

async function requestNerSmart(text, exclude_spans) {
  const labels = selectedNerLabels()
  const payload = { text }
  if (labels.length) payload.labels = labels
  if (Array.isArray(exclude_spans) && exclude_spans.length)
    payload.exclude_spans = exclude_spans

  try {
    // fetch()는 Promise를 반환하고 Response를 받는다. :contentReference[oaicite:1]{index=1}
    const r2 = await fetch(`${API_BASE()}/ner/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
    if (!r2.ok) {
      const txt = await r2.text()
      console.error('NER 요청 실패', r2.status, txt)
      setStatus(`NER 분석 실패 (${r2.status})`)
      return { items: [] }
    }

    // Response에서 JSON을 읽을 때 json()을 사용한다. :contentReference[oaicite:2]{index=2}
    const j2 = await r2.json()

    // ✅ 프론트 계산 없이 서버 entities만 그대로
    return normalizeNerItems(j2)
  } catch (e) {
    console.error('NER 요청 중 오류', e)
    setStatus(`NER 분석 중 오류: ${e.message || e}`)
    return { items: [] }
  }
}

function Score(v) {
  if (typeof v !== 'number' || !Number.isFinite(v)) return '-'
  const t = Math.floor(v * 100) / 100
  return t.toFixed(2)
}

function renderNerTable(ner) {
  const rows = $('#ner-rows')
  const sum = $('#ner-summary')
  const allow = new Set()
  $('#ner-show-ps')?.checked !== false && allow.add('PS')
  $('#ner-show-lc')?.checked !== false && allow.add('LC')
  $('#ner-show-og')?.checked !== false && allow.add('OG')

  const items = (ner.items || []).filter((it) =>
    allow.has((it.label || '').toUpperCase())
  )

  if (rows) rows.innerHTML = ''
  for (const it of items) {
    const tr = document.createElement('tr')
    tr.className = 'border-b align-top'
    tr.innerHTML = `
      <td class="py-2 px-2 font-mono">${esc(it.label)}</td>
      <td class="py-2 px-2 font-mono">${esc(it.text)}</td>
      <td class="py-2 px-2 font-mono">${Score(it.score)}</td>
      <td class="py-2 px-2 font-mono">${it.start}-${it.end}</td>`
    rows?.appendChild(tr)
  }

  badge('#ner-badge', items.length)
  if (sum) {
    const counts = {}
    for (const it of items) counts[it.label] = (counts[it.label] || 0) + 1
    sum.textContent = `검출: ${
      Object.keys(counts).length
        ? Object.entries(counts)
            .map(([k, v]) => `${k}=${v}`)
            .join(', ')
        : '없음'
    }`
  }
}

function renderNerDocStats(ner, srcText = '') {
  const out = $('#ner-metrics-output')
  if (!out) return

  const items = Array.isArray(ner?.items) ? ner.items : []
  const total = items.length

  const byLabel = {}
  for (const it of items) {
    const lab = String(it.label || '').toUpperCase()
    if (!lab) continue
    byLabel[lab] = (byLabel[lab] || 0) + 1
  }

  const ranges = []
  for (const it of items) {
    const s = Number(it.start ?? 0)
    const e = Number(it.end ?? 0)
    if (!(e > s)) continue
    ranges.push([s, e])
  }
  ranges.sort((a, b) => a[0] - b[0])
  const merged = []
  for (const [s, e] of ranges) {
    if (!merged.length || s > merged[merged.length - 1][1]) merged.push([s, e])
    else
      merged[merged.length - 1][1] = Math.max(merged[merged.length - 1][1], e)
  }
  let covered = 0
  for (const [s, e] of merged) covered += Math.max(0, e - s)
  const textLen = (srcText || '').length || 1
  const coverage = covered / textLen

  const wanted = ['PS', 'LC', 'OG', 'DT']

  let maxCount = 0
  for (const lab of wanted) maxCount = Math.max(maxCount, byLabel[lab] || 0)
  if (!maxCount) maxCount = 1

  const labelRows = wanted
    .map((lab) => {
      const cnt = byLabel[lab] || 0
      const width = (cnt / maxCount) * 100
      let colorHex = '#e5e7eb'
      if (cnt > 0) {
        if (lab === 'PS') colorHex = '#0ea5e9'
        else if (lab === 'LC') colorHex = '#10b981'
        else if (lab === 'OG') colorHex = '#f59e0b'
        else if (lab === 'DT') colorHex = '#8b5cf6'
      }
      return `
        <tr class="border-t border-gray-100">
          <td class="px-2 py-1.5 text-[11px] font-medium text-gray-700">${lab}</td>
          <td class="px-2 py-1.5 text-[11px] text-right text-gray-700">
            <div class="w-full h-4 rounded-full bg-gray-100 overflow-hidden flex items-center justify-end pr-1">
              <div class="h-4 rounded-full" style="width: ${width}%; background-color: ${colorHex};"></div>
              <span class="ml-1 relative z-10 text-[11px] text-gray-800">${cnt}</span>
            </div>
          </td>
        </tr>
      `
    })
    .join('')

  const coveragePct = (coverage * 100).toFixed(1)
  const hasEntities = total > 0
  const coverageBarStyle = hasEntities
    ? 'background: linear-gradient(to right, #0ea5e9, #6366f1);'
    : 'background-color: #e5e7eb;'

  out.innerHTML = `
    <div class="space-y-3">
      <div class="flex items-center justify-between text-xs text-gray-700">
        <div><span class="font-semibold">총 엔티티 수</span>: ${total}</div>
      </div>

      <div class="space-y-1">
        <div class="flex items-center justify-between text-[11px] text-gray-500">
          <span>문서 길이 대비 엔티티</span>
          <span class="text-gray-700 font-medium">${coveragePct}%</span>
        </div>
        <div class="h-2 rounded-full bg-gray-100 overflow-hidden">
          <div class="h-2" style="${coverageBarStyle} width: ${Math.min(
    100,
    coverage * 100
  )}%;"></div>
        </div>
      </div>

      <div class="overflow-x-auto border border-gray-100 rounded-lg">
        <table class="min-w-full text-[11px]">
          <thead class="bg-gray-50 text-gray-500">
            <tr>
              <th class="px-2 py-1.5 text-left font-medium">Label</th>
              <th class="px-2 py-1.5 text-right font-medium">Count</th>
            </tr>
          </thead>
          <tbody>${labelRows}</tbody>
        </table>
      </div>
    </div>
  `
}

function setStatus(msg) {
  const el = $('#status')
  if (el) el.textContent = msg || ''
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

$('#btn-scan')?.addEventListener('click', async () => {
  const f = $('#file')?.files?.[0]
  if (!f) return alert('파일을 선택하세요.')

  const ext = (f.name.split('.').pop() || '').toLowerCase()
  __lastRedactedName = f.name
    ? f.name.replace(/\.[^.]+$/, `_redacted.${ext}`)
    : `redacted.${ext}`

  setStatus('텍스트 추출 중...')
  const fd = new FormData()
  fd.append('file', f)

  $('#match-result-block')?.classList.remove('hidden')
  $('#ner-result-block')?.classList.remove('hidden')

  try {
    const r1 = await fetch(`${API_BASE()}/text/extract`, {
      method: 'POST',
      body: fd,
    })
    if (!r1.ok)
      throw new Error(`텍스트 추출 실패 (${r1.status})\n${await r1.text()}`)
    const extractData = await r1.json()

    const fullText = extractData.full_text || ''
    let analysisText = fullText || ''

    $('#text-preview-block')?.classList.remove('hidden')
    const ta = $('#txt-out')
    if (ta) {
      ta.classList.remove('hidden')
      ta.value = analysisText || '(본문 텍스트가 비어 있습니다.)'
    }

    const tablePreviewRoot = $('#text-table-preview')
    if (tablePreviewRoot) tablePreviewRoot.innerHTML = ''

    if (ext === 'pdf') {
      try {
        const fd2 = new FormData()
        fd2.append('file', f)
        const rMd = await fetch(`${API_BASE()}/text/markdown`, {
          method: 'POST',
          body: fd2,
        })
        if (rMd.ok) {
          const mdData = await rMd.json()
          let markdown = ''
          if (typeof mdData.markdown === 'string') markdown = mdData.markdown
          else if (Array.isArray(mdData.pages_md))
            markdown = mdData.pages_md.join('\n\n')
          else if (Array.isArray(mdData.pages))
            markdown = mdData.pages.map((p) => p.markdown || '').join('\n\n')

          if (markdown.trim()) analysisText = markdown

          const tableCount = renderTablePreview(markdown)

          const ta2 = $('#txt-out')
          if (ta2) {
            if (tableCount > 0) {
              const plainPreview = buildPlainTextFromMarkdown(markdown)
              if (plainPreview.trim()) {
                ta2.classList.remove('hidden')
                ta2.value = plainPreview
              } else {
                ta2.value = ''
                ta2.classList.add('hidden')
              }
            } else {
              ta2.classList.remove('hidden')
              ta2.value = analysisText || ''
            }
          }
        } else {
          console.warn('markdown 추출 실패', rMd.status)
        }
      } catch (e) {
        console.warn('markdown 추출 중 오류', e)
      }
    }

    const normalizedText = joinBrokenLines(analysisText)

    setStatus('정규식 매칭 중...')
    const rules = selectedRuleNames()
    const r2 = await fetch(`${API_BASE()}/text/match`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: normalizedText, rules, normalize: true }),
    })
    if (!r2.ok) throw new Error(`매칭 실패 (${r2.status})\n${await r2.text()}`)
    const rawMatchData = await r2.json()
    const matchData = filterMatchByRules(rawMatchData, rules)
    renderRegexResults(matchData)
    setOpen('match', true)

    setStatus('NER 분석 중...')
    if (!normalizedText.trim()) {
      renderNerTable({ items: [] })
      renderNerDocStats({ items: [] }, normalizedText)
      setOpen('ner', true)
    } else {
      const excludeSpans = buildExcludeSpansFromMatch(matchData)
      const ner = await requestNerSmart(normalizedText, excludeSpans)

      // ✅ UI는 서버 entities 그대로 출력
      renderNerTable(ner)
      renderNerDocStats(ner, normalizedText)

      $('#ner-metrics-block')?.classList.remove('hidden')
      ;['#ner-show-ps', '#ner-show-lc', '#ner-show-og'].forEach((sel) =>
        $(sel)?.addEventListener('change', () => renderNerTable(ner))
      )
      setOpen('ner', true)
    }

    setStatus(`스캔 완료 (${ext.toUpperCase()} 처리) — 레닥션 준비 중...`)

    setStatus('레닥션 파일 생성 중...')
    const fdRedact = new FormData()
    fdRedact.append('file', f)

    const rulesForRedact = selectedRuleNames()
    if (rulesForRedact.length) {
      fdRedact.append('rules_json', JSON.stringify(rulesForRedact))
    }

    const nerLabelsForRedact = selectedNerLabels()
    if (nerLabelsForRedact.length) {
      fdRedact.append('ner_labels_json', JSON.stringify(nerLabelsForRedact))
    }

    const r4 = await fetch(`${API_BASE()}/redact/file`, {
      method: 'POST',
      body: fdRedact,
    })
    if (!r4.ok) throw new Error(`레닥션 실패 (${r4.status})`)
    const blob = await r4.blob()
    const ctype = r4.headers.get('Content-Type') || 'application/octet-stream'
    __lastRedactedBlob = new Blob([blob], { type: ctype })

    if (ctype.includes('pdf')) {
      setOpen('pdf', true)
      await renderRedactedPdfPreview(__lastRedactedBlob)
    } else {
      setOpen('pdf', false)
    }

    const btn = $('#btn-save-redacted')
    if (btn) {
      btn.classList.remove('hidden')
      btn.disabled = false
    }
    setStatus('레닥션 완료 — 다운로드 가능')
  } catch (e) {
    console.error(e)
    setStatus(`오류: ${e.message || e}`)
  }
})

$('#btn-save-redacted')?.addEventListener('click', () => {
  if (!__lastRedactedBlob) return alert('레닥션된 파일이 없습니다.')
  const url = URL.createObjectURL(__lastRedactedBlob)
  const a = document.createElement('a')
  a.href = url
  a.download = __lastRedactedName || 'redacted_file'
  a.click()
  URL.revokeObjectURL(url)
})

document.addEventListener('DOMContentLoaded', () => {
  loadRules()
  setupDropZone()
})
