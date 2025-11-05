# server/modules/hwpx_module.py
# -*- coding: utf-8 -*-
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
except Exception:  # pragma: no cover
    from server.modules.common import (  # type: ignore
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
    """
    HWPX(zip)에서 텍스트를 모아 하나의 문자열로 합친다.
    - Contents/*.xml: 본문
    - Chart(s)/*.xml: 차트 라벨/값
    - BinData/*: 내장 XLSX 안의 텍스트
    """
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
    """
    /text/extract 엔드포인트가 기대하는 형식으로 HWPX 텍스트를 반환.
    - full_text: 전체 텍스트
    - pages    : 페이지 배열 (HWPX는 페이지 개념이 없어 1페이지로 통합)
    텍스트 미리보기에서 쓰레기값(XML 태그, 각주 마커, 시트 주소 등)을 최대한 제거한다.
    """
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zipf:
        raw = hwpx_text(zipf)

    # 1) 차트/내장 XLSX 에서 섞여 들어온 XML 태그 제거
    #    예: "<c:v>계열 1" -> "계열 1"
    txt = re.sub(r"<[^>\n]+>", "", raw)

    # 2) HWP 각주/주석 마커 줄 제거: "^1.", "^2)", "(^3)" 등
    lines: List[str] = []
    for line in txt.splitlines():
        s = line.strip()
        # 전체 라인이 각주 마커만 있으면 버림
        if re.fullmatch(r"\(?\^\d+[\).\s]*", s):
            continue
        lines.append(line)
    txt = "\n".join(lines)

    # 라인 중간에 남은 "(^5)" 같은 패턴도 제거
    txt = re.sub(r"\(\^\d+\)", "", txt)

    # 3) 엑셀 시트/범위 토큰 제거
    #    예: "Sheet1!$B$1", "Sheet1!$B$2:$B$5"
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
        # 일반적인 현재 리포 구조
        from ..core.redaction_rules import RULES
    except Exception:
        # 일부 브랜치/옛 구조/절대경로 fallback
        try:
            from ..redaction_rules import RULES  # type: ignore
        except Exception:
            from server.core.redaction_rules import RULES  # type: ignore

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
    """
    filename: HWPX ZIP 내 엔트리 경로
    data    : 원본 바이트
    comp    : compile_rules() 결과
    return  : 바이트를 반환하면 교체, None이면 원본 유지
    """
    low = filename.lower()

    # 1) Preview 폴더: 삭제 또는 블랭크
    if low.startswith("preview/"):
        if HWPX_STRIP_PREVIEW:
            return b""
        if HWPX_BLANK_PREVIEW and low.endswith((".png", ".jpg", ".jpeg")):
            # 1x1 PNG (고정 바이트)
            return (
                b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
                b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x0cIDATx\x9cc\x00\x01"
                b"\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
            )

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
        # settings.xml, contents/*, charts/*, bindata/* 는 위에서 이미 처리되었으므로
        masked, _ = sub_text_nodes(data, comp)
        return masked

    # 7) 그 외 파트는 원본 유지
    return None
