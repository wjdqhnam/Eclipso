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
    if overlap < 0:
        overlap = 0
    if overlap >= chunk_size:
        overlap = max(0, chunk_size // 5)

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


def _coerce_spans(exclude_spans: Optional[List[Dict[str, Any]]], n: int) -> List[Tuple[int, int]]:
    if not exclude_spans or n <= 0:
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
        if s < 0:
            s = 0
        if e > n:
            e = n
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


def _overlap(a: Tuple[int, int], b: Tuple[int, int]) -> bool:
    return min(a[1], b[1]) - max(a[0], b[0]) > 0


_LABEL_MAP = {
    "PS": "PS",
    "PERSON": "PS",
    "PER": "PS",
    "B-PER": "PS",
    "I-PER": "PS",
    "OG": "OG",
    "ORG": "OG",
    "ORGANIZATION": "OG",
    "B-ORG": "OG",
    "I-ORG": "OG",
    "LC": "LC",
    "LOCATION": "LC",
    "LOC": "LC",
    "ADDRESS": "LC",
    "GPE": "LC",
    "B-LOC": "LC",
    "I-LOC": "LC",
    "DT": "DT",
    "DATE": "DT",
    "TIME": "DT",
    "DATETIME": "DT",
}


def _std_label(label: str) -> str:
    key = (label or "").strip().upper()
    if key.startswith("B-") or key.startswith("I-"):
        key = key[2:]
    return _LABEL_MAP.get(key, key)


def _normalize_pipeline_entities(
    raw_entities: Any,
    chunk_start: int,
    chunk_text: str,
    allowed_set: Optional[set[str]] = None,
) -> List[Dict[str, Any]]:
    if not isinstance(raw_entities, list):
        return []

    out: List[Dict[str, Any]] = []
    used: List[Tuple[int, int]] = []

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
        lab = str(lab)
        if lab.startswith("B-") or lab.startswith("I-"):
            lab = lab[2:]

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

        if any(_overlap((s, t), r) for r in used):
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
        used.append((s, t))

    return out



def _merge_spans(spans: List[Dict[str, Any]], gap: int = 1) -> List[Dict[str, Any]]:
    """
    ✅ overlap chunk 때문에 생기는 중복/분절 엔터티 병합
    - 같은 라벨이고 겹치거나 인접(gap)하면 합침
    """
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
            merged.append(dict(sp))
            continue

        last = merged[-1]
        llab = str(last.get("label", ""))
        ls = int(last.get("start", 0) or 0)
        le = int(last.get("end", 0) or 0)

        if lab == llab and s <= le + gap:
            last["end"] = max(le, e)
            # score는 max로 유지(없으면 보수적으로 처리)
            try:
                last_score = float(last.get("score")) if last.get("score") is not None else None
            except Exception:
                last_score = None
            try:
                cur_score = float(sp.get("score")) if sp.get("score") is not None else None
            except Exception:
                cur_score = None
            if last_score is None:
                last["score"] = cur_score
            elif cur_score is not None:
                last["score"] = max(last_score, cur_score)
        else:
            merged.append(dict(sp))

    # label별 정렬이므로 최종은 start 기준으로 한 번 더 정렬
    merged.sort(key=lambda x: (int(x.get("start", 0) or 0), int(x.get("end", 0) or 0)))
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
            s = sp.get("start")
            e = sp.get("end")
            if s is None or e is None:
                continue
            try:
                s = int(s)
                e = int(e)
            except Exception:
                continue
            s = max(0, min(n, s))
            e = max(0, min(n, e))
            if e <= s:
                continue
            for i in range(s, e):
                if chars[i] != "\n":
                    chars[i] = " "
        text = "".join(chars)

    chunk_size = int(policy.get("chunk_size", 1500))
    overlap = int(policy.get("chunk_overlap", 50))
    allowed = policy.get("allowed_labels", None)
    allow_set = set(map(str, allowed)) if isinstance(allowed, list) else None

    spans: List[Dict[str, Any]] = []

    for s, t, sub in _chunk_text(text, chunk_size=chunk_size, overlap=overlap):
        try:
            raw = ner_predict_local(sub)
            chunk_spans = _normalize_pipeline_entities(raw, s, sub, allowed_set=allow_set)
            if allow_set is not None:
                chunk_spans = [sp for sp in chunk_spans if sp.get("label") in allow_set]
            spans.extend(chunk_spans)
        except Exception:
            continue

    spans.sort(key=lambda x: (x["start"], x["end"]))
    return spans


def _span_key(sp: Dict[str, Any]) -> Tuple[str, int, int]:
    return (str(sp.get("label", "")), int(sp.get("start", 0)), int(sp.get("end", 0)))


def compute_span_metrics(
    gold_spans: List[Dict[str, Any]],
    pred_spans: List[Dict[str, Any]],
    labels: Optional[List[str]] = None,
) -> Dict[str, Any]:
    label_list = labels or sorted({str(s.get("label")) for s in gold_spans if s.get("label")})

    gold = set(_span_key(s) for s in gold_spans if s.get("label") in label_list or labels is None)
    pred = set(_span_key(s) for s in pred_spans if s.get("label") in label_list or labels is None)

    tp = len(gold & pred)
    fn = len(gold - pred)
    fp = len(pred - gold)

    overall_recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    overall_precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    overall_f1 = (
        2 * overall_precision * overall_recall / (overall_precision + overall_recall)
        if (overall_precision + overall_recall) > 0
        else 0.0
    )

    out: Dict[str, Any] = {
        "overall_precision": overall_precision,
        "overall_recall": overall_recall,
        "overall_f1": overall_f1,
        "overall_miss_rate": 1.0 - overall_recall,
        "by_label": {},
    }

    for lab in label_list:
        g = set(k for k in gold if k[0] == lab)
        p = set(k for k in pred if k[0] == lab)
        tp_l = len(g & p)
        fn_l = len(g - p)
        fp_l = len(p - g)

        recall = tp_l / (tp_l + fn_l) if (tp_l + fn_l) > 0 else 1.0
        precision = tp_l / (tp_l + fp_l) if (tp_l + fp_l) > 0 else 1.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        out["by_label"][lab] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "miss_rate": 1.0 - recall,
        }

    out["sensitive_protection_index"] = overall_recall
    return out


def compute_document_level_metrics(
    docs: List[Dict[str, Any]],
    labels: Optional[List[str]] = None,
) -> Dict[str, Any]:
    per_doc = []
    complete_cnt = 0

    miss_doc_cnt_by_label: Dict[str, int] = {}
    have_gold_doc_cnt_by_label: Dict[str, int] = {}

    for d in docs:
        gold = d.get("gold_spans", []) or []
        pred = d.get("pred_spans", []) or []

        m = compute_span_metrics(gold, pred, labels=labels)
        per_doc.append({"id": d.get("id"), "metrics": m})
        gold_set = set(_span_key(s) for s in gold)
        pred_set = set(_span_key(s) for s in pred)
        if gold_set.issubset(pred_set):
            complete_cnt += 1

        labs = labels or sorted({str(s.get("label")) for s in gold if s.get("label")})
        for lab in labs:
            gold_lab = [s for s in gold if str(s.get("label")) == lab]
            if not gold_lab:
                continue
            have_gold_doc_cnt_by_label[lab] = have_gold_doc_cnt_by_label.get(lab, 0) + 1

            gold_lab_set = set(_span_key(s) for s in gold_lab)
            pred_lab_set = set(k for k in pred_set if k[0] == lab)
            if not gold_lab_set.issubset(pred_lab_set):
                miss_doc_cnt_by_label[lab] = miss_doc_cnt_by_label.get(lab, 0) + 1

    n = len(docs)
    complete_rate = complete_cnt / n if n else 0.0

    miss_rate_docs_by_label = {}
    for lab, denom in have_gold_doc_cnt_by_label.items():
        miss = miss_doc_cnt_by_label.get(lab, 0)
        miss_rate_docs_by_label[lab] = (miss / denom) if denom else 0.0

    return {
        "doc_count": n,
        "complete_doc_rate": complete_rate,
        "miss_doc_rate_by_label": miss_rate_docs_by_label,
        "per_doc": per_doc,
    }
