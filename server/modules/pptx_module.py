# server/modules/pptx_module.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import io
import re
import zipfile
from typing import List, Tuple

# ── common 유틸 임포트: 상대 경로 우선, 실패 시 절대 경로 fallback ────────────────
try:
    from .common import (
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        chart_rels_sanitize,
        xlsx_text_from_zip,
        redact_embedded_xlsx_bytes,
    )
except Exception:  # pragma: no cover - 패키지 구조 달라졌을 때 대비
    from server.modules.common import (  # type: ignore
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        chart_rels_sanitize,
        xlsx_text_from_zip,
        redact_embedded_xlsx_bytes,
    )

# ── schemas 임포트: core 우선, 실패 시 대안 경로 시도 ─────────────────────────
try:
    from ..core.schemas import XmlMatch, XmlLocation  # 현재 리포 구조
except Exception:
    try:
        from ..schemas import XmlMatch, XmlLocation   # 옛 구조 호환
    except Exception:
        from server.core.schemas import XmlMatch, XmlLocation  # 절대경로 fallback


# ─────────────────────────────────────────────────────────────────────────────
# PPTX 텍스트 추출
#   - ppt/slides/*.xml          : 슬라이드 본문 텍스트(<a:t>)
#   - ppt/charts/*.xml          : 차트 라벨/값(<a:t>, <c:v>)
#   - ppt/embeddings/*.xlsx     : 임베디드 엑셀의 셀/차트 텍스트
# ─────────────────────────────────────────────────────────────────────────────
def _collect_chart_and_embedded_texts(zipf: zipfile.ZipFile) -> str:
    parts: List[str] = []

    # 1) 차트 XML 내부 라벨/값
    for name in sorted(
        n for n in zipf.namelist()
        if n.startswith("ppt/charts/") and n.endswith(".xml")
    ):
        s = zipf.read(name).decode("utf-8", "ignore")
        for m in re.finditer(
            r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>",
            s,
            re.I | re.DOTALL,
        ):
            v = (m.group(1) or m.group(2) or "")
            if v:
                parts.append(v)

    # 2) 임베디드 XLSX (차트 데이터가 들어있는 통합문서)
    for name in sorted(
        n for n in zipf.namelist()
        if n.startswith("ppt/embeddings/") and n.lower().endswith(".xlsx")
    ):
        try:
            xlsx_bytes = zipf.read(name)
            with zipfile.ZipFile(io.BytesIO(xlsx_bytes), "r") as xzf:
                parts.append(xlsx_text_from_zip(xzf))
        except KeyError:
            pass
        except zipfile.BadZipFile:
            # 깨진 임베딩은 그냥 무시
            continue

    return cleanup_text("\n".join(p for p in parts if p))


def pptx_text(zipf: zipfile.ZipFile) -> str:
    all_txt: List[str] = []

    # 슬라이드 본문 텍스트
    for name in sorted(
        n for n in zipf.namelist()
        if n.startswith("ppt/slides/") and n.endswith(".xml")
    ):
        xml = zipf.read(name).decode("utf-8", "ignore")
        all_txt += [
            tm.group(1)
            for tm in re.finditer(r"<a:t[^>]*>(.*?)</a:t>", xml, re.DOTALL)
        ]

    # 차트 + 임베디드 XLSX 텍스트
    chart_txt = _collect_chart_and_embedded_texts(zipf)
    if chart_txt:
        all_txt.append(chart_txt)

    return cleanup_text("\n".join(all_txt))


# ─────────────────────────────────────────────────────────────────────────────
# 스캔: 정규식 규칙으로 텍스트에서 민감정보 후보 추출
#   - compile_rules()가 3/4/5튜플 또는 네임드 객체여도 동작하게 처리
#   - validator가 있으면 valid 플래그도 채워 줌
# ─────────────────────────────────────────────────────────────────────────────
def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = pptx_text(zipf)
    comp = compile_rules()
    out: List[XmlMatch] = []

    for ent in comp:
        try:
            # tuple/list 계열
            if isinstance(ent, (list, tuple)):
                if len(ent) >= 2:
                    rule_name, rx = ent[0], ent[1]
                else:
                    continue
                need_valid = bool(ent[2]) if len(ent) >= 3 else True
                validator = ent[4] if len(ent) >= 5 else None
            else:
                # 네임드 객체(SimpleNamespace 등)
                rule_name = getattr(ent, "name", getattr(ent, "rule", "unknown"))
                rx = getattr(ent, "rx", getattr(ent, "regex", None))
                need_valid = bool(getattr(ent, "need_valid", True))
                validator = getattr(ent, "validator", None)

            if rx is None:
                continue
        except Exception:
            continue

        for m in rx.finditer(text):
            val = m.group(0)
            ok = True
            if need_valid and callable(validator):
                try:
                    try:
                        ok = bool(validator(val))
                    except TypeError:
                        ok = bool(validator(val, None))
                except Exception:
                    ok = False

            out.append(
                XmlMatch(
                    rule=rule_name,
                    value=val,
                    valid=ok,
                    context=text[max(0, m.start() - 20): min(len(text), m.end() + 20)],
                    location=XmlLocation(
                        kind="pptx",
                        part="*merged_text*",
                        start=m.start(),
                        end=m.end(),
                    ),
                )
            )

    return out, "pptx", text


# ─────────────────────────────────────────────────────────────────────────────
# 파일 단위 레닥션
#   - ppt/slides/*.xml        : 슬라이드 텍스트 노드 마스킹
#   - ppt/charts/*.xml        : 차트 라벨/값 마스킹
#   - ppt/charts/_rels/*.rels : 차트 관계 정리(외부데이터 링크 정리용, 현재는 스텁)
#   - ppt/embeddings/*.xlsx   : 임베디드 엑셀 내부까지 레닥션
# ─────────────────────────────────────────────────────────────────────────────
def redact_item(filename: str, data: bytes, comp):
    low = filename.lower()

    # 1) 슬라이드 본문 XML: 텍스트 노드만 마스킹
    if low.startswith("ppt/slides/") and low.endswith(".xml"):
        return sub_text_nodes(data, comp)[0]

    # 2) 차트 XML: 라벨/값 + 텍스트 노드 마스킹
    if low.startswith("ppt/charts/") and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        # chart_sanitize 안에서 이미 sub_text_nodes를 쓰지만,
        # 안전하게 한 번 더 텍스트 노드 기준으로 돌려준다.
        return sub_text_nodes(b2, comp)[0]

    # 3) 차트 RELS: externalData / 임베딩 / 외부 링크 정리 (복구 팝업 방지)
    if low.startswith("ppt/charts/_rels/") and low.endswith(".rels"):
        b3, _ = chart_rels_sanitize(data)
        return b3

    # 4) 임베디드 XLSX: 내부까지 레닥션(셀/차트 텍스트 모두 마스킹)
    if low.startswith("ppt/embeddings/") and low.endswith(".xlsx"):
        return redact_embedded_xlsx_bytes(data)

    # 5) 기타 파트는 그대로 유지
    return data
