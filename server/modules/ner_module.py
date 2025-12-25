from __future__ import annotations
from typing import List, Dict, Any, Tuple, Optional
import re
import logging

logger = logging.getLogger(__name__)


def _chunk_text(
    text: str,
    chunk_size: int = 1500,
    overlap: int = 200,
) -> List[Tuple[int, int, str]]:
    n = len(text)
    if n <= 0:
        return []

    chunk_size = max(1, int(chunk_size))
    overlap = max(0, int(overlap))

    chunks: List[Tuple[int, int, str]] = []
    i = 0
    while i < n:
        j = min(n, i + chunk_size)

        if j < n:
            back = text.rfind("\n", i, j)
            if back != -1 and (j - back) <= 80:
                j = back + 1
            else:
                back = text.rfind(" ", i, j)
                if back != -1 and (j - back) <= 80:
                    j = back + 1

        chunks.append((i, j, text[i:j]))
        if j == n:
            break
        i = max(0, j - overlap)
    return chunks


def _coerce_spans(exclude_spans: Optional[List[Dict[str, Any]]]) -> List[Tuple[int, int]]:
    if not exclude_spans:
        return []
    out: List[Tuple[int, int]] = []
    for sp in exclude_spans:
        if not isinstance(sp, dict):
            continue
        s = sp.get("start")
        e = sp.get("end")
        if s is None or e is None:
            continue
        try:
            s = int(s)
            e = int(e)
        except Exception:
            continue
        if e <= s:
            continue
        out.append((s, e))
    out.sort()
    merged: List[Tuple[int, int]] = []
    for s, e in out:
        if not merged:
            merged.append((s, e))
            continue
        ps, pe = merged[-1]
        if s <= pe:
            merged[-1] = (ps, max(pe, e))
        else:
            merged.append((s, e))
    return merged


_MD_TABLE_RE = re.compile(r"^\s*\|.*\|\s*$")
_MD_SEP_RE = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?\s*$")


def _mask_markdown_keep_len(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text

    lines = text.splitlines(True)  # keepends
    out: List[str] = []
    for ln in lines:
        raw = ln.rstrip("\r\n")
        if _MD_SEP_RE.match(raw) or _MD_TABLE_RE.match(raw):
            # 길이 유지: 개행 제외하고 공백으로 치환
            core = list(raw)
            for i, ch in enumerate(core):
                if ch != "\n":
                    core[i] = " "
            out.append("".join(core) + (ln[len(raw):] if len(ln) > len(raw) else ""))
        else:
            out.append(ln)
    return "".join(out)


def _normalize_pipeline_entities(
    raw_entities: Any,
    chunk_start: int,
    chunk_text: str,
    allowed_set: Optional[set[str]] = None,
) -> List[Dict[str, Any]]:
    if not isinstance(raw_entities, list):
        return []

    out: List[Dict[str, Any]] = []
    # 중복 제거는 라벨별로만 수행(라벨이 다르면 유지)
    used_by_label: Dict[str, List[Tuple[int, int]]] = {}

    def _overlap(a: Tuple[int, int], b: Tuple[int, int]) -> bool:
        return min(a[1], b[1]) - max(a[0], b[0]) > 0

    n = len(chunk_text)

    for e in raw_entities:
        if not isinstance(e, dict):
            continue

        lab = (
            e.get("label")
            or e.get("entity_group")
            or e.get("entity")
            or e.get("type")
        )
        if not lab:
            continue

        # 라벨 정규화: BIO 제거 + 공백 제거 + 대문자
        lab = str(lab).strip()
        if lab.startswith("B-") or lab.startswith("I-"):
            lab = lab[2:]
        lab = lab.strip().upper()

        if allowed_set is not None and lab not in allowed_set:
            continue

        s_local = e.get("start")
        t_local = e.get("end")
        if s_local is None or t_local is None:
            continue
        try:
            s_local = int(s_local)
            t_local = int(t_local)
        except Exception:
            continue
        if t_local <= s_local:
            continue

        s_local = max(0, min(n, s_local))
        t_local = max(0, min(n, t_local))
        if t_local <= s_local:
            continue

        s = chunk_start + s_local
        t = chunk_start + t_local

        used_list = used_by_label.setdefault(lab, [])
        if any(_overlap((s, t), r) for r in used_list):
            continue

        score = e.get("score")
        try:
            score = float(score) if score is not None else None
        except Exception:
            score = None

        out.append(
            {
                "start": s,
                "end": t,
                "label": lab,
                "source": "ner",
                "score": score,
                "text": chunk_text[s_local:t_local],
            }
        )
        used_list.append((s, t))

    return out


def _merge_spans(spans: List[Dict[str, Any]], gap: int = 0) -> List[Dict[str, Any]]:
    if not spans:
        return []
    spans = sorted(spans, key=lambda x: (str(x.get("label", "")), int(x.get("start", 0)), int(x.get("end", 0))))

    merged: List[Dict[str, Any]] = []
    for sp in spans:
        lab = str(sp.get("label", ""))
        s = int(sp.get("start", 0) or 0)
        e = int(sp.get("end", 0) or 0)
        if e <= s:
            continue

        if not merged:
            merged.append({**sp, "label": lab, "start": s, "end": e})
            continue

        last = merged[-1]
        if str(last.get("label", "")) != lab:
            merged.append({**sp, "label": lab, "start": s, "end": e})
            continue

        last_s = int(last.get("start", 0) or 0)
        last_e = int(last.get("end", 0) or 0)

        if s <= last_e:
            last["end"] = max(last_e, e)
            try:
                last_len = max(1, int(last_e) - int(last_s))
                sp_len   = max(1, int(e) - int(s))
                s1 = float(last.get("score") or 0.0)
                s2 = float(sp.get("score") or 0.0)
                last["score"] = (s1 * last_len + s2 * sp_len) / (last_len + sp_len)
            except Exception:
                pass
            continue

        if gap > 0 and s <= last_e + gap:
            last["end"] = max(last_e, e)
            try:
                last_len = max(1, int(last_e) - int(last_s))
                sp_len   = max(1, int(e) - int(s))
                s1 = float(last.get("score") or 0.0)
                s2 = float(sp.get("score") or 0.0)
                last["score"] = (s1 * last_len + s2 * sp_len) / (last_len + sp_len)
            except Exception:
                pass
            continue

        merged.append({**sp, "label": lab, "start": s, "end": e})

    return merged


def run_ner(
    text: str,
    policy: Dict[str, Any],
    exclude_spans: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    from server.api.ner_api import ner_predict_local

    if exclude_spans:
        chars = list(text)
        n = len(chars)
        for sp in exclude_spans:
            s = sp.get("start"); e = sp.get("end")
            if s is None or e is None:
                continue
            try:
                s = int(s); e = int(e)
            except Exception:
                continue
            if e <= s:
                continue
            s = max(0, min(n, s))
            e = max(0, min(n, e))
            if e <= s:
                continue
            for i in range(s, e):
                if chars[i] != "\n":
                    chars[i] = " "
        text = "".join(chars)

    if bool(policy.get("mask_markdown", False)):
        text = _mask_markdown_keep_len(text)

    chunk_size = int(policy.get("chunk_size", 1500))
    overlap = int(policy.get("chunk_overlap", 50))
    allowed = policy.get("allowed_labels", None)
    allow_set = {str(x).strip().upper() for x in allowed} if isinstance(allowed, list) else None

    spans: List[Dict[str, Any]] = []

    for s, t, sub in _chunk_text(text, chunk_size=chunk_size, overlap=overlap):
        try:
            raw = ner_predict_local(sub, labels=sorted(allow_set) if allow_set else None)
            chunk_spans = _normalize_pipeline_entities(raw, s, sub, allowed_set=allow_set)
            spans.extend(chunk_spans)
        except Exception as ex:
            logger.warning(
                "[NER] chunk inference failed start=%d end=%d len=%d err=%s",
                s, t, len(sub), ex,
                exc_info=True,
            )
            continue

    # overlap 청크 때문에 생기는 중복/분절 병합(핵심)
    merge_gap = int(policy.get("merge_gap", 0))
    spans = _merge_spans(spans, gap=merge_gap)

    spans.sort(key=lambda x: (x["start"], x["end"]))
    return spans