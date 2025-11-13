from __future__ import annotations

import io
import re
import zipfile
import logging
from typing import Optional, List, Tuple

# ── common 유틸 임포트: 상대 경로 우선, 실패 시 절대경로 fallback ────────────────
try:
    from .common import (
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        redact_embedded_xlsx_bytes,
        HWPX_STRIP_PREVIEW,
        HWPX_DISABLE_CACHE,
        HWPX_BLANK_PREVIEW,
    )
except Exception:
    from server.modules.common import (
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        redact_embedded_xlsx_bytes,
        HWPX_STRIP_PREVIEW,
        HWPX_DISABLE_CACHE,
        HWPX_BLANK_PREVIEW,
    )

# ── schemas 임포트: core 우선, 실패 시 대안 경로 시도 ─────────────────────────
try:
    from ..core.schemas import XmlMatch, XmlLocation  # 일반적인 현재 리포 구조
except Exception:
    try:
        from ..schemas import XmlMatch, XmlLocation   # 일부 브랜치/옛 구조
    except Exception:
        from server.core.schemas import XmlMatch, XmlLocation  # 절대경로 fallback

log = logging.getLogger("xml_redaction")

# ─────────────────────────────────────────────────────────────────────────────
# HWPX 처리용: 레닥션 전 스캔에서 모은 시크릿(문자열)들을 저장했다가 OLE 프리뷰에도 반영
# ─────────────────────────────────────────────────────────────────────────────
_CURRENT_SECRETS: List[str] = []


def set_hwpx_secrets(values: List[str] | None):
    """레닥션 전에 수집된 민감 문자열(시크릿)을 저장한다."""
    global _CURRENT_SECRETS
    _CURRENT_SECRETS = list(dict.fromkeys(v for v in (values or []) if v))


# ─────────────────────────────────────────────────────────────────────────────
# 텍스트 수집: 본문 XML, 차트 XML, 내장 XLSX(sharedStrings, worksheets, charts)
# ─────────────────────────────────────────────────────────────────────────────
def hwpx_text(zipf: zipfile.ZipFile) -> str:
    out: List[str] = []

    names = zipf.namelist()

    # 1) 본문 Contents/* 의 텍스트
    for name in sorted(names):
        low = name.lower()
        if not (low.startswith("contents/") and low.endswith(".xml")):
            continue
        try:
            xml = zipf.read(name).decode("utf-8", "ignore")
            out += [m.group(1) for m in re.finditer(r">([^<>]+)<", xml)]
        except Exception:
            continue

    # 2) 차트 Chart(s)/* 의 a:t, c:v 텍스트 (라벨/범주/제목 등)
    for name in sorted(names):
        low = name.lower()
        if not ((low.startswith("chart/") or low.startswith("charts/")) and low.endswith(".xml")):
            continue
        try:
            s = zipf.read(name).decode("utf-8", "ignore")
            for m in re.finditer(
                r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>",
                s,
                re.I | re.DOTALL,
            ):
                v = (m.group(1) or m.group(2) or "").strip()
                if v:
                    out.append(v)
        except Exception:
            continue

    # 3) BinData/*: ZIP(=내장 XLSX)이면 그 안에서도 텍스트 수집
    for name in names:
        low = name.lower()
        if not low.startswith("bindata/"):
            continue
        try:
            b = zipf.read(name)
        except KeyError:
            continue
        if len(b) >= 4 and b[:2] == b"PK":
            # OOXML(XLSX)일 가능성 → 공유 문자열/워크시트/차트에서 텍스트 수집
            try:
                from .common import xlsx_text_from_zip
            except Exception:  # pragma: no cover
                from server.modules.common import xlsx_text_from_zip  # type: ignore
            try:
                with zipfile.ZipFile(io.BytesIO(b), "r") as ez:
                    out.append(xlsx_text_from_zip(ez))
            except Exception:
                pass

    return cleanup_text("\n".join(x for x in out if x))


# ─────────────────────────────────────────────────────────────────────────────
# /text/extract 용 텍스트 추출 (사람이 보기 좋게 정리)
# ─────────────────────────────────────────────────────────────────────────────
def extract_text(file_bytes: bytes) -> dict:
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zipf:
        raw = hwpx_text(zipf)

    # 1) 차트/내장 XLSX 에서 섞여 들어온 XML 태그 제거
    txt = re.sub(r"<[^>\n]+>", "", raw)

    # 2) HWP 각주/주석 마커 줄 제거: "^1.", "^2)", "(^3)" 등
    lines: List[str] = []
    for line in txt.splitlines():
        s = line.strip()
        if re.fullmatch(r"\(?\^\d+[\).\s]*", s):
            continue
        lines.append(line)
    txt = "\n".join(lines)
    txt = re.sub(r"\(\^\d+\)", "", txt)

    # 3) 엑셀 시트/범위 토큰 제거
    txt = re.sub(
        r"Sheet\d*!\$[A-Z]+\$\d+(?::\$[A-Z]+\$\d+)?",
        "",
        txt,
        flags=re.IGNORECASE,
    )

    # 4) "General4.3" 같은 포맷 문자열에서 General 제거 → "4.3"
    txt = re.sub(r"General(?=\s*\d)", "", txt, flags=re.IGNORECASE)

    # 5) 공백/줄바꿈 정리
    cleaned = cleanup_text(txt)

    return {
        "full_text": cleaned,
        "pages": [
            {"page": 1, "text": cleaned},
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# 스캔: 정규식 규칙으로 텍스트에서 민감정보 후보를 추출
# ─────────────────────────────────────────────────────────────────────────────
def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = hwpx_text(zipf)
    comp = compile_rules()

    # RULES에서 validator 가져오기 (없으면 None → 항상 True로 간주)
    try:
        from ..core.redaction_rules import RULES
    except Exception:
        try:
            from ..redaction_rules import RULES
        except Exception:
            from server.core.redaction_rules import RULES

    def _get_validator(rule_name: str):
        v = None
        try:
            v = RULES.get(rule_name, {}).get("validator")
        except Exception:
            v = None
        return v if callable(v) else None

    out: List[XmlMatch] = []

    for ent in comp:
        try:
            if isinstance(ent, (list, tuple)):
                rule_name = ent[0]
                rx = ent[1]
                need_valid = bool(ent[2]) if len(ent) >= 3 else True
            else:
                rule_name = getattr(ent, "name", getattr(ent, "rule", "unknown"))
                rx = getattr(ent, "rx", getattr(ent, "regex", None))
                need_valid = bool(getattr(ent, "need_valid", True))
            if rx is None:
                continue
        except Exception:
            continue

        validator = _get_validator(rule_name)

        for m in rx.finditer(text):
            val = m.group(0)
            ok = True
            if need_valid and validator:
                try:
                    try:
                        ok = bool(validator(val))
                    except TypeError:
                        ok = bool(validator(val, None))
                except Exception:
                    ok = False  # 검증 예외는 실패로 간주

            out.append(
                XmlMatch(
                    rule=rule_name,
                    value=val,
                    valid=ok,
                    context=text[max(0, m.start() - 20): min(len(text), m.end() + 20)],
                    location=XmlLocation(
                        kind="hwpx",
                        part="*merged_text*",
                        start=m.start(),
                        end=m.end(),
                    ),
                )
            )

    return out, "hwpx", text


# ─────────────────────────────────────────────────────────────────────────────
# 파일 단위 레닥션
# ─────────────────────────────────────────────────────────────────────────────
def redact_item(filename: str, data: bytes, comp) -> Optional[bytes]:
    low = filename.lower()

    # 1) Preview 폴더: 내용 전부 제거 (텍스트/이미지 포함 전체 0바이트)
    if low.startswith("preview/"):
        # 프리뷰는 보안상 전부 날려 버린다.
        return b""

    # 2) settings.xml: 캐시/프리뷰 비활성화
    if HWPX_DISABLE_CACHE and low.endswith("settings.xml"):
        try:
            txt = data.decode("utf-8", "ignore")
            # usePreview / preview / useCache / cache 끄기
            txt = re.sub(r'(?i)usepreview\s*=\s*"(?:true|1)"', 'usePreview="false"', txt)
            txt = re.sub(r"(?i)usepreview\s*=\s*'(?:true|1)'", "usePreview='false'", txt)
            txt = re.sub(r"(?is)<\s*usepreview\s*>.*?</\s*usepreview\s*>", "<usePreview>false</usePreview>", txt)
            txt = re.sub(r"(?is)<\s*preview\s*>.*?</\s*preview\s*>", "<preview>0</preview>", txt)
            txt = re.sub(r'(?i)usecache\s*=\s*"(?:true|1)"', 'useCache="false"', txt)
            txt = re.sub(r"(?is)<\s*cache\s*>.*?</\s*cache\s*>", "<cache>0</cache>", txt)
            return txt.encode("utf-8", "ignore")
        except Exception:
            return data

    # 3) 본문 XML: 규칙 기반 텍스트 마스킹 (Contents/*)
    if low.startswith("contents/") and low.endswith(".xml"):
        masked, _ = sub_text_nodes(data, comp)
        return masked

    # 4) 차트 XML: 텍스트 라벨만 마스킹(+ 남은 텍스트 노드 안전망)
    if (low.startswith("chart/") or low.startswith("charts/")) and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)   # a:t, c:strCache
        masked, _ = sub_text_nodes(b2, comp)
        return masked

    # 5) BinData: 내장 XLSX 또는 OLE(CFBF)
    if low.startswith("bindata/"):
        # (a) ZIP(=PK..) → 내장 XLSX
        if len(data) >= 4 and data[:2] == b"PK":
            try:
                return redact_embedded_xlsx_bytes(data)
            except Exception:
                return data
        # (b) 그 외 → CFBF(OLE) 가능. 프리뷰는 무조건 블랭크 + 시크릿/이메일 동일길이 마스킹
        try:
            try:
                from .ole_redactor import redact_ole_bin_preserve_size
            except Exception:  # pragma: no cover
                from server.modules.ole_redactor import redact_ole_bin_preserve_size  # type: ignore

            return redact_ole_bin_preserve_size(data, _CURRENT_SECRETS, mask_preview=True)
        except Exception:
            return data

    # 6) 그 외 XML 파트(머리말/꼬리말/기타)도 텍스트 노드만 마스킹
    if low.endswith(".xml") and not low.startswith("preview/"):
        masked, _ = sub_text_nodes(data, comp)
        return masked
    return None