const $ = (s) => document.querySelector(s)
const $$ = (s) => Array.from(document.querySelectorAll(s))
const API_BASE = () => window.API_BASE || "http://127.0.0.1:8000"

let __lastRedactedBlob = null
let __lastRedactedName = "redacted.txt"

async function loadRules() {
  try {
    const resp = await fetch(`${API_BASE()}/text/rules`)
    if (!resp.ok) throw new Error(`rules ${resp.status}`)
    const rules = await resp.json()
    const container = $('#rules-container')
    container.innerHTML = ''
    rules.forEach(rule => {
      const label = document.createElement('label')
      label.className = "block"
      label.innerHTML = `<input type="checkbox" name="rule" value="${rule}" checked> ${rule}`
      container.appendChild(label)
    })
  } catch (err) {
    console.error("규칙 불러오기 실패:", err)
  }
}
document.addEventListener('DOMContentLoaded', loadRules)

// PDF 미리보기
async function renderPdfPreview(file) {
  const canvas = $('#pdf-preview')
  const g = canvas.getContext('2d')
  if (!file || file.type !== 'application/pdf') {
    g.clearRect(0, 0, canvas.width, canvas.height)
    return
  }
  const arr = await file.arrayBuffer()
  const pdf = await pdfjsLib.getDocument({ data: arr }).promise
  const page = await pdf.getPage(1)
  const viewport = page.getViewport({ scale: 1.2 })
  canvas.width = viewport.width
  canvas.height = viewport.height
  await page.render({ canvasContext: g, viewport }).promise
}

// 스캔 실행
$('#btn-scan')?.addEventListener('click', async () => {
  const f = $('#file').files[0]         //  파일 먼저 가져오기
  if (!f) return alert('파일을 선택하세요')

  const ext = f.name.split('.').pop().toLowerCase()  //  확장자 추출
  const fileName = f.name
    ? f.name.replace(/\.[^.]+$/, `_redacted.${ext}`)
    : `redacted.${ext}`

  __lastRedactedName = fileName

  $('#status').textContent = '텍스트 추출 및 매칭 중...'

  const fd = new FormData()
  fd.append('file', f)

  try {
    const extResp = await fetch(`${API_BASE()}/text/extract`, { method: 'POST', body: fd })
    if (!extResp.ok) {
      const msg = await extResp.text()
      throw new Error(`텍스트 추출 실패 (${extResp.status})\n${msg}`)
    }
    const extData = await extResp.json()

    const rules = $$('input[name="rule"]:checked').map(x => x.value)
    const matchResp = await fetch(`${API_BASE()}/text/match`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: extData.full_text, rules, normalize: true }),
    })
    if (!matchResp.ok) {
      const msg = await matchResp.text()
      throw new Error(`매칭 실패 (${matchResp.status})\n${msg}`)
    }

    const res = await matchResp.json()
    $('#text-preview-block').classList.remove('hidden')
    $('#txt-out').value = extData.full_text || ''

    // 결과표
    $('#match-result-block').classList.remove('hidden')
    const tbody = $('#result-rows')
    tbody.innerHTML = ''
    for (const r of res.items) {
      const tr = document.createElement('tr')
      tr.className = 'border-b align-top'
      tr.innerHTML = `
        <td class="py-2 px-2 mono">${r.rule}</td>
        <td class="py-2 px-2 mono">${r.value}</td>
        <td class="py-2 px-2 ${r.valid ? 'text-emerald-700' : 'text-rose-700'}">
          ${r.valid ? 'OK' : 'FAIL'}
        </td>
        <td class="py-2 px-2 mono context">${r.context || ''}</td>`
      tbody.appendChild(tr)
    }

    $('#summary').textContent = `검출: ${Object.entries(res.counts)
      .map(([k, v]) => `${k}=${v}`).join(', ')}`

    $('#status').textContent = `스캔 완료 (${ext.toUpperCase()} 처리)`

    // === 레닥션 파일 생성 ===
    $('#status').textContent = '레닥션 파일 생성 중...'
    const redactResp = await fetch(`${API_BASE()}/redact/file`, { method: 'POST', body: fd })
    if (!redactResp.ok) throw new Error(`레닥션 실패 (${redactResp.status})`)

    const blob = await redactResp.blob()
    const contentType = redactResp.headers.get('Content-Type') || 'application/octet-stream'

    const originalName = f.name || ''
    const extMatch = originalName.match(/\.([^.]+)$/)
    const extName = extMatch ? extMatch[1] : (ext || 'bin')
    const safeBase = originalName.replace(/\.[^.]+$/, '') || 'redacted'
    const finalName = `${safeBase}.${extName}`

    __lastRedactedBlob = new Blob([blob], { type: contentType })
    __lastRedactedName = finalName

    const btn = $('#btn-save-redacted')
    btn.classList.remove('hidden')
    btn.disabled = false
    $('#status').textContent = '레닥션 완료 — 다운로드 가능'
  } catch (err) {
    console.error(err)
    $('#status').textContent = `오류: ${err.message}`
  }
})


// 다운로드 버튼
$('#btn-save-redacted')?.addEventListener('click', () => {
  if (!__lastRedactedBlob) return alert('레닥션된 파일이 없습니다.')
  const url = URL.createObjectURL(__lastRedactedBlob)
  const a = document.createElement('a')
  a.href = url
  a.download = __lastRedactedName || 'redacted_file'
  a.click()
  URL.revokeObjectURL(url)
})
