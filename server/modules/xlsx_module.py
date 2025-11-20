from __future__ import annotations
import io, zipfile, re, unicodedata
from typing import List, Tuple

try:
    from .common import (
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        xlsx_text_from_zip,
    )
except Exception:
    from server.modules.common import (
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        xlsx_text_from_zip,
    )

# schemas 임포트: core 우선, 실패 시 대안 경로 시도
from server.core.schemas import XmlMatch, XmlLocation


# ────────────────────────────────────────────────────
# XLSX 텍스트 추출
# ────────────────────────────────────────────────────
def xlsx_text(zipf: zipfile.ZipFile) -> str:
    out: List[str] = []

    # 1) 공유 문자열
    try:
        sst = zipf.read("xl/sharedStrings.xml").decode("utf-8", "ignore")
        for m in re.finditer(r"<t[^>]*>(.*?)</t>", sst, re.DOTALL):
            v = (m.group(1) or "").strip()
            if not v:
                continue
            v = unicodedata.normalize("NFKC", v)
            out.append(v)
    except KeyError:
        pass

    # 2) 워크시트: <v>, <t>
    for name in (
        n for n in zipf.namelist()
        if n.startswith("xl/worksheets/") and n.endswith(".xml")
    ):
        try:
            xml = zipf.read(name).decode("utf-8", "ignore")
        except KeyError:
            continue

        for m in re.finditer(r"<v[^>]*>(.*?)</v>", xml, re.DOTALL):
            v = (m.group(1) or "").strip()
            if not v:
                continue
            v = unicodedata.normalize("NFKC", v)
            if re.fullmatch(r"\d{1,4}", v):
                continue
            out.append(v)

        for m in re.finditer(r"<t[^>]*>(.*?)</t>", xml, re.DOTALL):
            v = (m.group(1) or "").strip()
            if not v:
                continue
            v = unicodedata.normalize("NFKC", v)
            out.append(v)

    # 3) 차트: <a:t>, <c:v>
    for name in (
        n for n in zipf.namelist()
        if n.startswith("xl/charts/") and n.endswith(".xml")
    ):
        try:
            s2 = zipf.read(name).decode("utf-8", "ignore")
        except KeyError:
            continue

        for m in re.finditer(
            r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>",
            s2,
            re.IGNORECASE | re.DOTALL,
        ):
            text_part = m.group(1)
            num_part = m.group(2)
            v = (text_part or num_part or "").strip()
            if not v:
                continue
            v = unicodedata.normalize("NFKC", v)
            if num_part is not None and re.fullmatch(r"\d{1,4}", v):
                continue
            out.append(v)

    text = cleanup_text("\n".join(out))

    # 잡다한 라인 제거
    filtered_lines: List[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if "<c:" in s:
            continue
        if s.endswith(":") and not re.search(r"[0-9@]", s):
            continue
        filtered_lines.append(line)

    return "\n".join(filtered_lines)


# /text/extract, /redactions/xml/scan 에서 사용하는 래퍼
def extract_text(file_bytes: bytes) -> dict:
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zipf:
        txt = xlsx_text(zipf)
    return {
        "full_text": txt,
        "pages": [
            {"page": 1, "text": txt},
        ],
    }


# 스캔: 정규식 규칙으로 텍스트에서 민감정보 후보를 추출
def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = xlsx_text(zipf)
    comp = compile_rules()
    out: List[XmlMatch] = []

    for ent in comp:
        try:
            if isinstance(ent, (list, tuple)):
                # (name, regex, need_valid, priority, validator)까지 올 수 있음
                if len(ent) >= 5:
                    rule_name, rx, need_valid, _prio, validator = ent[0], ent[1], bool(ent[2]), ent[3], ent[4]
                elif len(ent) >= 3:
                    rule_name, rx, need_valid = ent[0], ent[1], bool(ent[2])
                    validator = None
                elif len(ent) >= 2:
                    rule_name, rx = ent[0], ent[1]
                    need_valid, validator = True, None
                else:
                    continue
            else:
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
                        kind="xlsx",
                        part="*merged_text*",
                        start=m.start(),
                        end=m.end(),
                    ),
                )
            )

    return out, "xlsx", text


# 파일 단위 레닥션: 시트/공유문자열/차트 처리
def redact_item(filename: str, data: bytes, comp):
    low = filename.lower()

    if low == "xl/sharedstrings.xml" or low.startswith("xl/worksheets/"):
        b, _ = sub_text_nodes(data, comp)
        return b

    if low.startswith("xl/charts/") and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        return b2

    return data