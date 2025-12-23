from __future__ import annotations
from typing import List, Dict, Any, Tuple
import re

# ──────────────────────────────────────────────────────────────────────────────
def _chunk_text(text: str, chunk_size: int = 1500, overlap: int = 50) -> List[Tuple[int, int, str]]:
    n = len(text)
    if n <= 0:
        return []
    chunks: List[Tuple[int, int, str]] = []
    i = 0
    while i < n:
        j = min(n, i + chunk_size)
        chunks.append((i, j, text[i:j]))
        if j == n:
            break
        i = j - overlap
        if i < 0:
            i = 0
    return chunks

# ──────────────────────────────────────────────────────────────────────────────
_LABEL_MAP = {
    "PS": "PS", "LC": "LC", "OG": "OG", "DT": "DT", "QT": "QT",
    "PERSON": "PS", "PER": "PS", "PEOPLE": "PS",
    "ORGANIZATION": "OG", "ORG": "OG", "INSTITUTION": "OG", "COMPANY": "OG",
    "LOCATION": "LC", "ADDRESS": "LC", "ADDR": "LC", "GPE": "LC", "PLACE": "LC", "FAC": "LC", "FACILITY": "LC",
    "DATE": "DT", "TIME": "DT", "DATETIME": "DT",
    "NUMBER": "QT", "QUANTITY": "QT", "CARDINAL": "QT", "NUM": "QT",
}
def _std_label(label: str) -> str:
    if not label:
        return ""
    key = label.strip().upper()
    return _LABEL_MAP.get(key, key)

# ──────────────────────────────────────────────────────────────────────────────
def _normalize_raw_entities(raw: Any, chunk_start: int, chunk_text: str) -> List[Dict[str, Any]]:
    data = raw
    if isinstance(raw, dict):
        if "entities" in raw:
            data = raw.get("entities", [])
        elif "result" in raw:
            data = raw.get("result", [])
        elif isinstance(raw.get("data"), list):
            data = raw["data"]

    out: List[Dict[str, Any]] = []
    used_ranges: List[Tuple[int, int]] = []

    def _overlap(a: Tuple[int,int], b: Tuple[int,int]) -> bool:
        return min(a[1], b[1]) - max(a[0], b[0]) > 0

    if isinstance(data, list):
        for e in data:
            if not isinstance(e, dict):
                continue
            label = e.get("label") or e.get("entity") or e.get("entity_group") or ""
            std = _std_label(str(label))
            if not std:
                continue

            start = e.get("start") or e.get("begin") or e.get("start_idx") or e.get("offset_start")
            end   = e.get("end")   or e.get("finish") or e.get("end_idx")   or e.get("offset_end")
            score = e.get("score")
            try:
                score = float(score) if score is not None else None
            except Exception:
                score = None

            if start is not None and end is not None:
                try:
                    s = int(start) + chunk_start
                    t = int(end) + chunk_start
                except Exception:
                    continue
                if t <= s:
                    continue
                out.append({"start": s, "end": t, "label": std, "source": "ner", "score": score})
                used_ranges.append((s, t))
                continue

            txt = (e.get("text") or e.get("word") or "").strip()
            if not txt:
                continue
            for m in re.finditer(re.escape(txt), chunk_text):
                s_local, t_local = m.start(), m.end()
                s = chunk_start + s_local
                t = chunk_start + t_local
                if any(_overlap((s, t), ur) for ur in used_ranges):
                    continue
                out.append({"start": s, "end": t, "label": std, "source": "ner", "score": score})
                used_ranges.append((s, t))
                break
    return out

# ──────────────────────────────────────────────────────────────────────────────
_DATE_REGEXES = [
    re.compile(r"\b(19|20)\d{2}[./-](0?[1-9]|1[0-2])[./-](0?[1-9]|[12]\d|3[01])\b"),
    re.compile(r"(19|20)\d{2}\s*년\s*(0?[1-9]|1[0-2])\s*월\s*(0?[1-9]|[12]\d|3[01])\s*일"),
    re.compile(r"\b(0?[1-9]|1[0-2])[./-](0?[1-9]|[12]\d|3[01])[./-]((19|20)\d{2})\b"),
    re.compile(r"\b(0?[1-9]|1[0-2])[/-](\d{2})\b"),
]
def _synthesize_dt_spans(text: str, policy: Dict[str, Any], existing: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    dt_policy = str(policy.get("dt_policy", "sensitive_only"))
    if dt_policy == "off":
        return []
    if any(s.get("label") == "DT" for s in existing):
        return []
    triggers = list(policy.get("dt_sensitive_triggers", []))
    window = int(policy.get("context_window", 18))
    synthesized: List[Dict[str, Any]] = []
    for rx in _DATE_REGEXES:
        for m in rx.finditer(text):
            s, t = m.start(), m.end()
            lo, hi = max(0, s - window), min(len(text), t + window)
            ctx = text[lo:hi]
            if dt_policy == "sensitive_only" and not any(tr in ctx for tr in triggers):
                continue
            synthesized.append({"start": s, "end": t, "label": "DT", "source": "ner", "score": None})
    return synthesized

# ──────────────────────────────────────────────────────────────────────────────
def _merge_adjacent_same_label(spans: List[Dict[str, Any]], text: str, label: str, max_gap: int = 2) -> List[Dict[str, Any]]:
    if not spans:
        return spans
    spans = sorted(spans, key=lambda x: (x["start"], x["end"]))
    out: List[Dict[str, Any]] = []
    for s in spans:
        if not out:
            out.append(s); continue
        last = out[-1]
        if last["label"] == s["label"] == label:
            gap_text = text[last["end"]:s["start"]]
            if len(gap_text) <= max_gap and re.fullmatch(r"[\s,\-–—]*", gap_text or ""):
                last["end"] = s["end"]
                continue
        out.append(s)
    return out

_ADDR_NUM_RX = re.compile(r"^\d+(?:-\d+)?(?:번지|호)?$")
_ROAD_END_RX = re.compile(r"(로|길)\s*$")
_SUFFIX_RX = re.compile(r'^[\s,\-–—]{0,3}((?:지하)?\d+(?:층|호|호실)|\d+(?:-\d+)?(?:호|호실)?|\d+동)')

def _extend_lc_suffix_by_text(text: str, end: int, max_steps: int = 3) -> int:
    pos = end
    steps = 0
    n = len(text)
    while steps < max_steps and pos < n:
        m = _SUFFIX_RX.match(text[pos:])
        if not m:
            break
        pos += m.end()
        steps += 1
    return pos

def _attach_address_numbers(spans: List[Dict[str, Any]], text: str, max_gap: int = 2) -> List[Dict[str, Any]]:
    if not spans:
        return spans
    spans = sorted(spans, key=lambda x: (x["start"], x["end"]))
    out: List[Dict[str, Any]] = []
    idx = 0
    while idx < len(spans):
        cur = spans[idx]
        if cur.get("label") != "LC":
            out.append(cur); idx += 1; continue
        end = cur["end"]; j = idx + 1
        while j < len(spans):
            nxt = spans[j]
            gap_text = text[end:nxt["start"]]
            if len(gap_text) > max_gap or not re.fullmatch(r"[\s,\-–—]*", gap_text or ""):
                break
            is_qt_addrnum = (nxt.get("label") == "QT" and _ADDR_NUM_RX.match(text[nxt["start"]:nxt["end"]]))
            prev_seg = text[cur["start"]:end]
            prev_ends_with_road = _ROAD_END_RX.search(prev_seg) is not None
            if nxt.get("label") == "LC":
                end = nxt["end"]; j += 1; continue
            if is_qt_addrnum or prev_ends_with_road:
                end = nxt["end"]; j += 1; continue
            break
        end = _extend_lc_suffix_by_text(text, end, max_steps=3)

        cur = dict(cur); cur["end"] = end
        out.append(cur)
        idx = j

    out.sort(key=lambda x: (x["start"], x["end"]))
    merged: List[Dict[str, Any]] = []
    for s in out:
        if not merged:
            merged.append(s); continue
        last = merged[-1]
        if last["label"] == s["label"] == "LC" and last["end"] >= s["start"]:
            last["end"] = max(last["end"], s["end"])
        else:
            merged.append(s)
    return merged

_ROAD_RX = re.compile(r"\b[가-힣A-Za-z0-9]+(?:로|길)\b")
def _synthesize_road_names(text: str) -> List[Dict[str, Any]]:
    spans: List[Dict[str, Any]] = []
    for m in _ROAD_RX.finditer(text):
        spans.append({"start": m.start(), "end": m.end(), "label": "LC", "source": "ner", "score": None})
    return spans

# ──────────────────────────────────────────────────────────────────────────────
def run_ner(text: str, policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    from server.api.ner_api import ner_predict_blocking
    chunk_size = int(policy.get("chunk_size", 1500))
    overlap = int(policy.get("chunk_overlap", 50))
    allowed = policy.get("allowed_labels", None)

    spans: List[Dict[str, Any]] = []
    for s, t, sub in _chunk_text(text, chunk_size=chunk_size, overlap=overlap):
        try:
            res = ner_predict_blocking(sub, labels=allowed)
            raw = res.get("raw")
            spans.extend(_normalize_raw_entities(raw, s, sub))
        except Exception:
            continue

    if text:
        spans.extend(_synthesize_dt_spans(text, policy, spans))

    spans.sort(key=lambda x: (x["start"], x["end"]))
    spans = _merge_adjacent_same_label(spans, text, label="LC", max_gap=2)

    try:
        road_spans = _synthesize_road_names(text)
        spans.extend(road_spans)
    except Exception:
        pass
    spans.sort(key=lambda x: (x["start"], x["end"]))

    spans = _attach_address_numbers(spans, text, max_gap=2)
    spans.sort(key=lambda x: (x["start"], x["end"]))
    return spans