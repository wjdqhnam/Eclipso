from __future__ import annotations

import os
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, HTTPException

from server.modules.ner_module import compute_span_metrics, compute_document_level_metrics

try:
    from server.api.redaction_api import match_text  # type: ignore
except Exception:
    match_text = None  # type: ignore


SERVER_DIR = Path(__file__).resolve().parents[1]
DEFAULT_MODEL_DIR = SERVER_DIR / "modules" / "ner"

NER_MODEL_DIR = Path(os.getenv("ECLIPSO_NER_MODEL_PATH", str(DEFAULT_MODEL_DIR)))
NER_FORCE_CPU = os.getenv("NER_FORCE_CPU", "0") == "1"

NER_MAX_LENGTH = int(os.getenv("NER_MAX_LENGTH", "384"))
NER_STRIDE = int(os.getenv("NER_STRIDE", "64"))
NER_BATCH_SIZE = int(os.getenv("NER_BATCH_SIZE", "8"))

NER_MERGE_GAP = int(os.getenv("NER_MERGE_GAP", "1"))
NER_SCORE_THRESHOLD = float(os.getenv("NER_SCORE_THRESHOLD", "0.0"))


class NerAPIError(Exception):
    pass


router = APIRouter(prefix="/ner", tags=["ner"])


def _normalize_label(label: str) -> str:
    if not label:
        return label
    if label.startswith("B-") or label.startswith("I-"):
        return label[2:]
    return label


def _overlap(a: Tuple[int, int], b: Tuple[int, int]) -> bool:
    return min(a[1], b[1]) - max(a[0], b[0]) > 0


def _looks_like_email(v: str) -> bool:
    s = (v or "").strip()
    if "@" not in s:
        return False
    dom = s.split("@", 1)[-1]
    return "." in dom and len(dom) >= 3


def _auto_exclude_spans_by_regex(text: str) -> List[Dict[str, Any]]:
    if not match_text:
        return []
    try:
        res = match_text(text)
        items = list(res.get("items", []) or [])
    except Exception:
        return []

    spans: List[Dict[str, Any]] = []
    for it in items:
        s = it.get("start")
        e = it.get("end")
        if s is None or e is None:
            continue
        try:
            s = int(s)
            e = int(e)
        except Exception:
            continue
        if e <= s:
            continue

        ok = it.get("valid", True)
        val = str(it.get("value") or "")
        if ok is False and not _looks_like_email(val):
            continue

        spans.append({"start": s, "end": e})
    return spans


def _coerce_ranges(exclude_spans: Any, n: int) -> List[Tuple[int, int]]:
    if not exclude_spans or n <= 0:
        return []
    if not isinstance(exclude_spans, list):
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
        s = max(0, min(n, s))
        e = max(0, min(n, e))
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


def _mask_text(text: str, ranges: List[Tuple[int, int]]) -> str:
    if not text or not ranges:
        return text
    chars = list(text)
    n = len(chars)
    for s, e in ranges:
        s = max(0, min(n, s))
        e = max(0, min(n, e))
        if e <= s:
            continue
        for i in range(s, e):
            if chars[i] != "\n":
                chars[i] = " "
    return "".join(chars)


def _merge_entities(ents: List[Dict[str, Any]], merge_gap: int = NER_MERGE_GAP) -> List[Dict[str, Any]]:
    if not ents:
        return []

    ents = sorted(ents, key=lambda x: (x["label"], x["start"], x["end"]))
    merged: List[Dict[str, Any]] = []

    for e in ents:
        if not merged:
            merged.append(e)
            continue

        last = merged[-1]
        if e["label"] == last["label"] and e["start"] <= last["end"] + merge_gap:
            last["end"] = max(last["end"], e["end"])
            last["score"] = max(float(last.get("score", 0.0)), float(e.get("score", 0.0)))
        else:
            merged.append(e)

    return merged


@lru_cache(maxsize=1)
def _get_local_model():
    try:
        import torch
        from transformers import AutoModelForTokenClassification, AutoTokenizer

        if not NER_MODEL_DIR.is_dir():
            raise NerAPIError(f"NER model dir not found: {NER_MODEL_DIR}")

        device = torch.device("cpu" if NER_FORCE_CPU else ("cuda:0" if torch.cuda.is_available() else "cpu"))

        tokenizer = AutoTokenizer.from_pretrained(str(NER_MODEL_DIR), local_files_only=True)
        model = AutoModelForTokenClassification.from_pretrained(str(NER_MODEL_DIR), local_files_only=True)

        model.to(device)
        model.eval()

        is_fast = bool(getattr(tokenizer, "is_fast", False))
        id2label = getattr(model.config, "id2label", None) or {}
        label2id = getattr(model.config, "label2id", None) or {}

        return {
            "tokenizer": tokenizer,
            "model": model,
            "device": device,
            "is_fast": is_fast,
            "id2label": id2label,
            "label2id": label2id,
        }
    except NerAPIError:
        raise
    except Exception as e:
        raise NerAPIError(f"Failed to load local NER model: {e}") from e


def _infer_entities_no_text(
    text: str,
    labels: Optional[List[str]] = None,
    exclude_spans: Optional[List[Dict[str, Any]]] = None,
    max_length: int = NER_MAX_LENGTH,
    stride: int = NER_STRIDE,
    batch_size: int = NER_BATCH_SIZE,
    score_threshold: float = NER_SCORE_THRESHOLD,
) -> List[Dict[str, Any]]:
    if not isinstance(text, str) or not text:
        return []

    pack = _get_local_model()
    tokenizer = pack["tokenizer"]
    model = pack["model"]
    device = pack["device"]
    is_fast = pack["is_fast"]
    id2label = pack["id2label"] or {}
    label2id = pack["label2id"] or {}

    if not is_fast:
        raise NerAPIError("Tokenizer is not a Fast tokenizer; cannot compute stable char offsets (start/end).")

    n = len(text)
    ranges = _coerce_ranges(exclude_spans, n) if exclude_spans else []
    masked = _mask_text(text, ranges) if ranges else text

    has_bio = any(isinstance(v, str) and (v.startswith("B-") or v.startswith("I-")) for v in id2label.values())
    o_id: Optional[int] = None
    if isinstance(label2id, dict) and "O" in label2id:
        try:
            o_id = int(label2id["O"])
        except Exception:
            o_id = None
    if o_id is None and (not has_bio) and isinstance(label2id, dict) and "LABEL_0" in label2id:
        try:
            o_id = int(label2id["LABEL_0"])
        except Exception:
            o_id = None

    def _id_to_label(i: int) -> str:
        v = id2label.get(i, str(i))
        return str(v)

    import torch

    enc = tokenizer(
        masked,
        truncation=True,
        max_length=max_length,
        stride=stride,
        return_overflowing_tokens=True,
        return_offsets_mapping=True,
        padding=False,
        return_tensors="pt",
    )

    input_ids = enc["input_ids"]
    attention_mask = enc.get("attention_mask")
    token_type_ids = enc.get("token_type_ids")
    offsets = enc["offset_mapping"]

    num_chunks = int(input_ids.shape[0])
    all_ents: List[Dict[str, Any]] = []

    with torch.no_grad():
        for st in range(0, num_chunks, batch_size):
            ed = min(num_chunks, st + batch_size)

            batch = {"input_ids": input_ids[st:ed].to(device)}
            if attention_mask is not None:
                batch["attention_mask"] = attention_mask[st:ed].to(device)
            if token_type_ids is not None:
                batch["token_type_ids"] = token_type_ids[st:ed].to(device)

            out = model(**batch)
            logits = out.logits

            probs = torch.softmax(logits, dim=-1)
            pred_ids = torch.argmax(probs, dim=-1)
            pred_scores = torch.max(probs, dim=-1).values

            for bi in range(ed - st):
                offs = offsets[st + bi]
                offs_list = offs.tolist() if hasattr(offs, "tolist") else list(offs)

                cur_label: Optional[str] = None
                cur_start: Optional[int] = None
                cur_end: Optional[int] = None
                cur_scores: List[float] = []

                for ti, (cs, ce) in enumerate(offs_list):
                    if ce is None or cs is None:
                        continue
                    cs = int(cs)
                    ce = int(ce)
                    if ce <= cs:
                        continue

                    lid = int(pred_ids[bi, ti].item())
                    sc = float(pred_scores[bi, ti].item())
                    raw_lab = _id_to_label(lid)

                    is_o = (raw_lab == "O") or (o_id is not None and lid == o_id)
                    if is_o:
                        if cur_label is not None and cur_start is not None and cur_end is not None:
                            avg_score = sum(cur_scores) / max(1, len(cur_scores))
                            all_ents.append({"label": cur_label, "start": cur_start, "end": cur_end, "score": float(avg_score)})
                        cur_label, cur_start, cur_end, cur_scores = None, None, None, []
                        continue

                    norm_lab = _normalize_label(raw_lab)

                    if labels and norm_lab not in labels:
                        if cur_label is not None and cur_start is not None and cur_end is not None:
                            avg_score = sum(cur_scores) / max(1, len(cur_scores))
                            all_ents.append({"label": cur_label, "start": cur_start, "end": cur_end, "score": float(avg_score)})
                        cur_label, cur_start, cur_end, cur_scores = None, None, None, []
                        continue

                    if sc < score_threshold:
                        if cur_label is not None and cur_start is not None and cur_end is not None:
                            avg_score = sum(cur_scores) / max(1, len(cur_scores))
                            all_ents.append({"label": cur_label, "start": cur_start, "end": cur_end, "score": float(avg_score)})
                        cur_label, cur_start, cur_end, cur_scores = None, None, None, []
                        continue

                    is_b = isinstance(raw_lab, str) and raw_lab.startswith("B-")
                    if cur_label is None:
                        cur_label, cur_start, cur_end = norm_lab, cs, ce
                        cur_scores = [sc]
                        continue

                    if is_b or norm_lab != cur_label or cs > (cur_end or 0) + NER_MERGE_GAP:
                        if cur_start is not None and cur_end is not None:
                            avg_score = sum(cur_scores) / max(1, len(cur_scores))
                            all_ents.append({"label": cur_label, "start": cur_start, "end": cur_end, "score": float(avg_score)})
                        cur_label, cur_start, cur_end = norm_lab, cs, ce
                        cur_scores = [sc]
                    else:
                        cur_end = max(cur_end or ce, ce)
                        cur_scores.append(sc)

                if cur_label is not None and cur_start is not None and cur_end is not None:
                    avg_score = sum(cur_scores) / max(1, len(cur_scores))
                    all_ents.append({"label": cur_label, "start": cur_start, "end": cur_end, "score": float(avg_score)})

    merged = _merge_entities(all_ents, merge_gap=NER_MERGE_GAP)

    if ranges:
        merged = [e for e in merged if not any(_overlap((e["start"], e["end"]), r) for r in ranges)]

    merged.sort(key=lambda x: (x["start"], x["end"]))
    return merged


def ner_predict_local(
    text: str,
    labels: Optional[List[str]] = None,
    exclude_spans: Optional[List[Dict[str, Any]]] = None,
    max_length: int = NER_MAX_LENGTH,
    stride: int = NER_STRIDE,
    batch_size: int = NER_BATCH_SIZE,
    score_threshold: float = NER_SCORE_THRESHOLD,
) -> List[Dict[str, Any]]:
    ents = _infer_entities_no_text(
        text=text,
        labels=labels,
        exclude_spans=exclude_spans,
        max_length=max_length,
        stride=stride,
        batch_size=batch_size,
        score_threshold=score_threshold,
    )
    out: List[Dict[str, Any]] = []
    for e in ents:
        out.append(
            {
                "entity_group": e["label"],
                "entity": e["label"],
                "start": int(e["start"]),
                "end": int(e["end"]),
                "score": float(e.get("score", 0.0)),
            }
        )
    return out


@router.get("/health", summary="NER 로컬 로딩 상태 확인")
async def health() -> Dict[str, Any]:
    exists = NER_MODEL_DIR.is_dir()
    must_files = ["config.json", "model.safetensors", "tokenizer.json"]
    present = {fn: (NER_MODEL_DIR / fn).is_file() for fn in must_files}

    load_ok = False
    device_info: Optional[str] = None
    is_fast: Optional[bool] = None
    labels: Optional[List[str]] = None
    err: Optional[str] = None

    try:
        pack = _get_local_model()
        load_ok = True
        device_info = str(pack["device"])
        is_fast = bool(pack.get("is_fast", False))
        id2label = pack.get("id2label") or {}
        labels = [str(id2label[k]) for k in sorted(id2label.keys())] if isinstance(id2label, dict) else None
    except Exception as e:
        err = str(e)

    return {
        "ok": True,
        "model_dir": str(NER_MODEL_DIR),
        "dir_exists": exists,
        "required_files": present,
        "load_ok": load_ok,
        "device": device_info,
        "tokenizer_is_fast": is_fast,
        "labels": labels,
        "error": err,
        "config": {
            "NER_MAX_LENGTH": NER_MAX_LENGTH,
            "NER_STRIDE": NER_STRIDE,
            "NER_BATCH_SIZE": NER_BATCH_SIZE,
            "NER_MERGE_GAP": NER_MERGE_GAP,
            "NER_SCORE_THRESHOLD": NER_SCORE_THRESHOLD,
        },
    }


@router.post(
    "/predict",
    summary="로컬 NER 추론",
    description="입력: text, labels(옵션), exclude_spans(옵션). exclude_spans 미전달 시 정규식 탐지로 자동 제외구간 생성",
)
async def predict_endpoint(payload: Dict[str, Any]) -> Dict[str, Any]:
    text = (payload or {}).get("text", "") or ""
    labels = (payload or {}).get("labels", None)
    exclude_spans = (payload or {}).get("exclude_spans", None)

    if not isinstance(text, str) or not text.strip():
        raise HTTPException(status_code=400, detail="text is required")

    if labels is not None and not isinstance(labels, list):
        raise HTTPException(status_code=400, detail="labels must be a list or null")

    if exclude_spans is None:
        exclude_spans = _auto_exclude_spans_by_regex(text)

    try:
        t0 = time.time()
        ents = _infer_entities_no_text(
            text=text,
            labels=labels,
            exclude_spans=exclude_spans,
            max_length=NER_MAX_LENGTH,
            stride=NER_STRIDE,
            batch_size=NER_BATCH_SIZE,
            score_threshold=NER_SCORE_THRESHOLD,
        )
        latency_ms = int((time.time() - t0) * 1000)

        entities: List[Dict[str, Any]] = []
        n = len(text)
        for e in ents:
            s = max(0, min(n, int(e["start"])))
            ed = max(0, min(n, int(e["end"])))
            if ed <= s:
                continue
            entities.append(
                {
                    "label": str(e["label"]),
                    "start": s,
                    "end": ed,
                    "score": float(e.get("score", 0.0)),
                    "text": text[s:ed],
                }
            )

        return {"ok": True, "latency_ms": latency_ms, "entities": entities}
    except NerAPIError as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"NER inference failed: {e}") from e


@router.post(
    "/metrics",
    summary="NER 문서 단위 평가 지표 계산",
    description='입력 예시: {"labels":["PS","LC","OG","DT"],"docs":[{"id":"doc1","gold_spans":[...], "pred_spans":[...]}]}',
)
async def ner_metrics(payload: Dict[str, Any]) -> Dict[str, Any]:
    docs = (payload or {}).get("docs") or []
    labels = (payload or {}).get("labels")

    if not isinstance(docs, list):
        raise HTTPException(status_code=400, detail="docs 필드는 리스트여야 합니다.")
    if labels is not None and not isinstance(labels, list):
        raise HTTPException(status_code=400, detail="labels 필드는 리스트여야 합니다.")

    doc_metrics = compute_document_level_metrics(docs, labels=labels)

    all_gold: List[Dict[str, Any]] = []
    all_pred: List[Dict[str, Any]] = []
    for d in docs:
        all_gold.extend(d.get("gold_spans", []) or [])
        all_pred.extend(d.get("pred_spans", []) or [])

    span_metrics = compute_span_metrics(all_gold, all_pred, labels=labels)

    return {"span_metrics": span_metrics, "doc_metrics": doc_metrics}
