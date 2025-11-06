// app.js — 업로드 + 스캔 + 정규식/NER 렌더 + PDF 미리보기

// 작은 유틸
const $ = (s) => document.querySelector(s)
const $$ = (s) => Array.from(document.querySelectorAll(s))
const API_BASE = () => window.API_BASE || 'http://127.0.0.1:8000'

let __lastRedactedBlob = null
let __lastRedactedName = 'redacted.pdf'

const esc = (s) =>
  (s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

const badge = (sel, n) => {
  const el = $(sel)
  if (el) el.textContent = String(n ?? 0)
}

const setOpen = (name, open) => {
  const cont = document.getElementById(
    name === 'pdf' ? 'pdf-preview-block' : `${name}-result-block`
  )
  const body = document.getElementById(`${name}-body`)
  const chev = document.querySelector(`[data-chevron="${name}"]`)
  cont && cont.classList.remove('hidden')
  body && body.classList.toggle('hidden', !open)
  chev && chev.classList.toggle('rotate-180', !open)
}

// 아코디언 토글
document.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-toggle]')
  if (!btn) return
  const name = btn.getAttribute('data-toggle')
  const body = document.getElementById(`${name}-body`)
  setOpen(name, body ? body.classList.contains('hidden') : true)
})

// 규칙 로드
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

// 드롭존
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

// PDF 미리보기 (레닥션 결과만)
async function renderRedactedPdfPreview(blob) {
  const cv = $('#pdf-preview')
  if (!cv) return
  const g = cv.getContext('2d')
  if (!blob) return g.clearRect(0, 0, cv.width, cv.height)
  const pdf = await pdfjsLib.getDocument({ data: await blob.arrayBuffer() })
    .promise
  const page = await pdf.getPage(1),
    vp = page.getViewport({ scale: 1.2 })
  cv.width = vp.width
  cv.height = vp.height
  await page.render({ canvasContext: g, viewport: vp }).promise
}

// 정규식 결과 렌더
const take = (s, n) => (s.length <= n ? s : s.slice(0, n) + '…')

function highlightFrag(ctx, val, pad = 60) {
  const i = (ctx || '').indexOf(val || '')
  if (i < 0) return esc(take(ctx || '', 140))
  const start = Math.max(0, i - pad),
    end = Math.min((ctx || '').length, i + (val || '').length + pad)
  const pre = esc((ctx || '').slice(start, i))
  const mid = esc(val || '')
  const post = esc((ctx || '').slice(i + (val || '').length, end))
  return pre + `<mark class="bg-yellow-200 rounded px-1">${mid}</mark>` + post
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
    const ok = arr.filter((x) => x.valid).length,
      fail = arr.length - ok

    const container = document.createElement('div')
    container.className = 'rounded-xl border border-gray-200 mb-3'
    container.innerHTML = `
      <button class="w-full flex items-center justify-between px-4 py-2.5 bg-gray-50 hover:bg-gray-100 rounded-lg">
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
        <svg class="h-4 w-4 text-gray-500" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 10.94l3.71-3.7a.75.75 0 111.06 1.06l-4.24 4.24a.75.75 0 01-1.06 0L5.21 8.29a.75.75 0 01.02-1.08z" clip-rule="evenodd"/></svg>
      </button>
      <div class="p-2"></div>
    `
    const body = container.querySelector('.p-2')
    for (const r of arr) {
      const card = document.createElement('div')
      card.className = 'border rounded-lg p-3 mb-2'
      card.dataset.valid = r.valid ? '1' : '0'
      card.innerHTML = `
        <div class="flex items-start justify-between gap-3">
          <div class="min-w-0">
            <div class="text-sm font-mono break-all">${esc(r.value || '')}</div>
            <div class="text-[12px] text-gray-500 mt-1 leading-relaxed break-words">${highlightFrag(
              r.context || '',
              r.value || ''
            )}</div>
          </div>
          <div class="text-xs ${
            r.valid ? 'text-emerald-700' : 'text-rose-700'
          } shrink-0">${r.valid ? 'OK' : 'FAIL'}</div>
        </div>`
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

  $('#filter-valid-only')?.addEventListener('change', (e) => {
    const on = e.target.checked
    wrap.querySelectorAll('[data-valid]').forEach((el) => {
      const ok = el.getAttribute('data-valid') === '1'
      el.style.display = on && !ok ? 'none' : ''
    })
  })

  $('#filter-search')?.addEventListener('input', (e) => {
    const q = (e.target.value || '').toLowerCase()
    wrap.querySelectorAll('.border.rounded-lg.p-3').forEach((el) => {
      el.style.display =
        q && !el.textContent.toLowerCase().includes(q) ? 'none' : ''
    })
  })
}

// NER 렌더
function renderNerTable(ner) {
  const rows = $('#ner-rows'),
    sum = $('#ner-summary')
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
      <td class="py-2 px-2 font-mono">${
        typeof it.score === 'number' ? it.score.toFixed(2) : '-'
      }</td>
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

// 메인 플로우
$('#btn-scan')?.addEventListener('click', async () => {
  const f = $('#file')?.files?.[0]
  if (!f) return alert('파일을 선택하세요')
  const ext = (f.name.split('.').pop() || '').toLowerCase()
  __lastRedactedName = f.name
    ? f.name.replace(/\.[^.]+$/, `_redacted.${ext}`)
    : `redacted.${ext}`

  const st = $('#status')
  if (st) st.textContent = '텍스트 추출 및 매칭 중...'
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
    const { full_text: text = '' } = await r1.json()
    $('#text-preview-block')?.classList.remove('hidden')
    const ta = $('#txt-out')
    if (ta) ta.value = text || '(본문 텍스트가 비어 있습니다.)'

    const rules = $$('input[name="rule"]:checked').map((x) => x.value)
    const r2 = await fetch(`${API_BASE()}/text/match`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, rules, normalize: true }),
    })
    if (!r2.ok) throw new Error(`매칭 실패 (${r2.status})\n${await r2.text()}`)
    renderRegexResults(await r2.json())
    setOpen('match', true)

    const r3 = await fetch(`${API_BASE()}/text/ner`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    })
    const ner = r3.ok ? await r3.json() : { items: [], counts: {} }
    renderNerTable(ner)
    ;['#ner-show-ps', '#ner-show-lc', '#ner-show-og'].forEach((sel) =>
      $(sel)?.addEventListener('change', () => renderNerTable(ner))
    )
    setOpen('ner', true)
    if (st) st.textContent = `스캔 완료 (${ext.toUpperCase()} 처리)`

    if (st) st.textContent = '레닥션 파일 생성 중...'
    const r4 = await fetch(`${API_BASE()}/redact/file`, {
      method: 'POST',
      body: fd,
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
    if (st) st.textContent = '레닥션 완료 — 다운로드 가능'
  } catch (e) {
    console.error(e)
    if (st) st.textContent = `오류: ${e.message}`
  }
})

// 다운로드
$('#btn-save-redacted')?.addEventListener('click', () => {
  if (!__lastRedactedBlob) return alert('레닥션된 파일이 없습니다.')
  const url = URL.createObjectURL(__lastRedactedBlob)
  const a = document.createElement('a')
  a.href = url
  a.download = __lastRedactedName || 'redacted_file'
  a.click()
  URL.revokeObjectURL(url)
})

// 초기화
document.addEventListener('DOMContentLoaded', () => {
  loadRules()
  setupDropZone()
})
