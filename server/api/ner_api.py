from __future__ import annotations

import json
import os
import sys
import time
import re
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from collections import Counter

from fastapi import APIRouter, HTTPException

try:
    from server.api.redaction_api import match_text  # type: ignore
except Exception:
    match_text = None  # type: ignore


log_prefix = "[NER]"

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

if not logger.handlers:
    h = logging.StreamHandler(sys.stdout)
    h.setLevel(logging.INFO)
    h.setFormatter(logging.Formatter("%(levelname)s:%(name)s:%(message)s"))
    logger.addHandler(h)

logger.propagate = False


SERVER_DIR = Path(__file__).resolve().parents[1]
DEFAULT_MODEL_DIR = SERVER_DIR / "modules" / "ner"

NER_MODEL_DIR = Path(os.getenv("ECLIPSO_NER_MODEL_PATH", str(DEFAULT_MODEL_DIR)))
NER_FORCE_CPU = os.getenv("NER_FORCE_CPU", "0") == "1"

NER_MAX_LENGTH = int(os.getenv("NER_MAX_LENGTH", "384"))
NER_STRIDE = int(os.getenv("NER_STRIDE", "64"))
NER_BATCH_SIZE = int(os.getenv("NER_BATCH_SIZE", "8"))

NER_MERGE_GAP = int(os.getenv("NER_MERGE_GAP", "0"))
NER_SCORE_THRESHOLD = float(os.getenv("NER_SCORE_THRESHOLD", "0.0"))
NER_TEMPERATURE = float(os.getenv("NER_TEMPERATURE", "3.0"))

NER_MASK_MARKDOWN = os.getenv("NER_MASK_MARKDOWN", "1") == "1"
NER_LOG_MAX_CHARS = int(os.getenv("NER_LOG_MAX_CHARS", "20000"))
NER_SOFT_GAP_MAX = int(os.getenv("NER_SOFT_GAP_MAX", "8"))


class NerAPIError(Exception):
    pass


router = APIRouter(prefix="/ner", tags=["ner"])

def _truncate(s: str, max_chars: int) -> str:
    if not isinstance(s, str):
        s = str(s)
    if max_chars > 0 and len(s) > max_chars:
        return s[:max_chars] + "\n...(truncated)"
    return s

def _log_ner_input_text(ner_input: str) -> None:
    if not isinstance(ner_input, str):
        return
    logger.info("%s ner_input:\n%s", log_prefix, _truncate(ner_input, NER_LOG_MAX_CHARS))

def _log_predict_result(payload: Dict[str, Any]) -> None:
    try:
        s = json.dumps(payload, ensure_ascii=False, indent=2)
    except Exception:
        s = str(payload)
    logger.info("%s predict_result:\n%s", log_prefix, _truncate(s, NER_LOG_MAX_CHARS))

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


def _mask_markdown_noise_keep_len(text: str) -> str:
    if not text:
        return text

    text = (
        text.replace("\u200b", " ")
        .replace("\u200c", " ")
        .replace("\u200d", " ")
        .replace("\ufeff", " ")
        .replace("\u00a0", " ")
        .replace("\t", " ")
    )

    trans = {
        ord("|"): " ",
        ord("`"): " ",
        ord("*"): " ",
        ord("_"): " ",
        ord("#"): " ",
        ord(">"): " ",
        ord("<"): " ",
    }
    return text.translate(trans)


def _merge_entities(ents: List[Dict[str, Any]], merge_gap: int) -> List[Dict[str, Any]]:
    if not ents:
        return []

    ents = sorted(ents, key=lambda x: (x["label"], x["start"], x["end"]))
    merged: List[Dict[str, Any]] = []

    for e in ents:
        if not merged:
            merged.append(e)
            continue

        last = merged[-1]
        if e["label"] != last["label"]:
            merged.append(e)
            continue

        # 겹치거나 붙어있는 경우
        if e["start"] <= last["end"]:
            last_len = max(1, int(last["end"]) - int(last["start"]))
            e_len = max(1, int(e["end"]) - int(e["start"]))
            s1 = float(last.get("score", 0.0))
            s2 = float(e.get("score", 0.0))

            last["end"] = max(int(last["end"]), int(e["end"]))
            last["score"] = (s1 * last_len + s2 * e_len) / (last_len + e_len)
            continue

        # gap 허용 병합 (여기도 max 말고 mean으로)
        if merge_gap > 0 and e["start"] <= last["end"] + merge_gap:
            last_len = max(1, int(last["end"]) - int(last["start"]))
            e_len = max(1, int(e["end"]) - int(e["start"]))
            s1 = float(last.get("score", 0.0))
            s2 = float(e.get("score", 0.0))

            last["end"] = max(int(last["end"]), int(e["end"]))
            last["score"] = (s1 * last_len + s2 * e_len) / (last_len + e_len)
            continue

        merged.append(e)

    return merged


def _ensure_pad_token(tokenizer: Any, model: Any) -> None:
    try:
        if getattr(tokenizer, "pad_token_id", None) is not None:
            return

        eos = getattr(tokenizer, "eos_token", None)
        if eos is not None:
            tokenizer.pad_token = eos
            return

        tokenizer.add_special_tokens({"pad_token": "[PAD]"})
        if hasattr(model, "resize_token_embeddings"):
            model.resize_token_embeddings(len(tokenizer))
    except Exception:
        return


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

        _ensure_pad_token(tokenizer, model)

        model.to(device)
        model.eval()

        is_fast = bool(getattr(tokenizer, "is_fast", False))
        if not is_fast:
            raise NerAPIError("Tokenizer is not a Fast tokenizer; cannot compute stable char offsets (start/end).")

        id2label_raw = getattr(model.config, "id2label", None) or {}
        label2id_raw = getattr(model.config, "label2id", None) or {}

        id2label: Dict[int, str] = {}
        for k, v in dict(id2label_raw).items():
            try:
                id2label[int(k)] = str(v)
            except Exception:
                pass

        label2id: Dict[str, int] = {}
        for k, v in dict(label2id_raw).items():
            try:
                label2id[str(k)] = int(v)
            except Exception:
                pass

        return {
            "tokenizer": tokenizer,
            "model": model,
            "device": device,
            "id2label": id2label,
            "label2id": label2id,
        }
    except NerAPIError:
        raise
    except Exception as e:
        raise NerAPIError(f"Failed to load local NER model: {e}") from e


def _postprocess_split_ps(text: str, ents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not ents:
        return []
    rx = re.compile(r"[^\s,]+")
    out: List[Dict[str, Any]] = []

    def is_noise(tok: str) -> bool:
        if not tok:
            return True
        if tok.isdigit():
            return True
        return False

    for e in ents:
        lab = str(e.get("label") or "")
        s = int(e.get("start", 0))
        ed = int(e.get("end", 0))
        sc = float(e.get("score", 0.0))
        if lab != "PS" or ed <= s:
            out.append(e)
            continue

        seg = text[s:ed]
        hits = list(rx.finditer(seg))
        if not hits:
            out.append(e)
            continue

        for m in hits:
            tok = seg[m.start() : m.end()]
            if is_noise(tok):
                continue
            out.append({"label": "PS", "start": s + m.start(), "end": s + m.end(), "score": sc})

    out.sort(key=lambda x: (int(x.get("start", 0)), int(x.get("end", 0))))
    return out


def _postprocess_merge_lc_parentheses(text: str, ents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not ents:
        return []
    out: List[Dict[str, Any]] = []
    i = 0
    n = len(text)

    def _safe_int(x: Any, d: int) -> int:
        try:
            return int(x)
        except Exception:
            return d

    while i < len(ents):
        a = dict(ents[i])
        if str(a.get("label") or "") != "LC":
            out.append(a)
            i += 1
            continue

        if i + 1 >= len(ents):
            out.append(a)
            i += 1
            continue

        b = dict(ents[i + 1])
        if str(b.get("label") or "") != "LC":
            out.append(a)
            i += 1
            continue

        a_s = max(0, min(n, _safe_int(a.get("start"), 0)))
        a_e = max(0, min(n, _safe_int(a.get("end"), 0)))
        b_s = max(0, min(n, _safe_int(b.get("start"), 0)))
        b_e = max(0, min(n, _safe_int(b.get("end"), 0)))

        if not (a_s < a_e <= b_s < b_e):
            out.append(a)
            i += 1
            continue

        gap = text[a_e:b_s]
        if not re.fullmatch(r"\s*\(\s*", gap):
            out.append(a)
            i += 1
            continue

        new_end = b_e
        if new_end < n and text[new_end] == ")":
            new_end += 1

        a["end"] = new_end
        a_len = max(1, int(a_e) - int(a_s))
        b_len = max(1, int(b_e) - int(b_s))
        sa = float(a.get("score", 0.0))
        sb = float(b.get("score", 0.0))
        a["score"] = (sa * a_len + sb * b_len) / (a_len + b_len)

        out.append(a)
        i += 2

    out.sort(key=lambda x: (_safe_int(x.get("start"), 0), _safe_int(x.get("end"), 0)))
    return out

logger.info("%s NER_TEMPERATURE=%s", log_prefix, NER_TEMPERATURE)

def _infer_entities_no_text(
    text: str,
    labels: Optional[List[str]] = None,
    exclude_spans: Optional[List[Dict[str, Any]]] = None,
    max_length: int = NER_MAX_LENGTH,
    stride: int = NER_STRIDE,
    batch_size: int = NER_BATCH_SIZE,
    score_threshold: float = NER_SCORE_THRESHOLD,
    debug: bool = False,
) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    if not isinstance(text, str) or not text:
        return [], ({"reason": "empty_text"} if debug else None)

    pack = _get_local_model()
    tokenizer = pack["tokenizer"]
    model = pack["model"]
    device = pack["device"]
    id2label: Dict[int, str] = pack["id2label"] or {}
    label2id: Dict[str, int] = pack["label2id"] or {}

    n = len(text)
    ranges = _coerce_ranges(exclude_spans, n) if exclude_spans else []
    masked = _mask_text(text, ranges) if ranges else text
    ner_input = _mask_markdown_noise_keep_len(masked) if NER_MASK_MARKDOWN else masked

    _log_ner_input_text(ner_input)

    o_id: Optional[int] = None
    if "O" in label2id:
        o_id = label2id.get("O")
    elif "LABEL_0" in label2id:
        o_id = label2id.get("LABEL_0")

    def _id_to_label(i: int) -> str:
        v = id2label.get(int(i))
        return str(v) if v is not None else str(i)

    import torch

    enc = tokenizer(
        ner_input,
        truncation=True,
        max_length=max_length,
        stride=stride,
        return_overflowing_tokens=True,
        return_offsets_mapping=True,
        padding="max_length",
        return_tensors="pt",
    )

    input_ids = enc["input_ids"]
    attention_mask = enc.get("attention_mask")
    token_type_ids = enc.get("token_type_ids")
    offsets = enc["offset_mapping"]

    num_chunks = int(input_ids.shape[0])
    all_ents: List[Dict[str, Any]] = []
    pred_dist: Counter[str] = Counter()

    with torch.no_grad():
        for st in range(0, num_chunks, batch_size):
            ed = min(num_chunks, st + batch_size)

            batch: Dict[str, Any] = {"input_ids": input_ids[st:ed].to(device)}
            if attention_mask is not None:
                batch["attention_mask"] = attention_mask[st:ed].to(device)
            if token_type_ids is not None:
                batch["token_type_ids"] = token_type_ids[st:ed].to(device)

            out = model(**batch)
            logits = out.logits
            
            #Temperature 적용 
            T = max(1e-6, float(NER_TEMPERATURE))
            probs = torch.softmax(logits / T, dim=-1)

            pred_ids = torch.argmax(probs, dim=-1)
            pred_scores = torch.max(probs, dim=-1).values

            pred_ids_cpu = pred_ids.detach().cpu()
            pred_scores_cpu = pred_scores.detach().cpu()

            if debug:
                flat = pred_ids_cpu.view(-1).tolist()
                for lid in flat:
                    pred_dist[_id_to_label(int(lid))] += 1

            bsz = int(pred_ids_cpu.shape[0])
            for bi in range(bsz):
                offs = offsets[st + bi]
                offs_list = offs.tolist() if hasattr(offs, "tolist") else list(offs)

                def _soft_gap(prev_end: Optional[int], next_start: int, max_len: int) -> bool:
                    if prev_end is None:
                        return False
                    if next_start <= prev_end:
                        return True
                    gap = ner_input[prev_end:next_start]
                    if "\n" in gap or "\r" in gap:
                        return False
                    if len(gap) > max(0, max_len):
                        return False
                    return all(ch in (" ", "\t") for ch in gap)

                cur_label: Optional[str] = None
                cur_start: Optional[int] = None
                cur_end: Optional[int] = None
                cur_scores: List[float] = []

                for ti, (cs, ce) in enumerate(offs_list):
                    if cs is None or ce is None:
                        continue
                    cs = int(cs)
                    ce = int(ce)
                    if ce <= cs:
                        continue

                    lid = int(pred_ids_cpu[bi, ti].item())
                    sc = float(pred_scores_cpu[bi, ti].item())
                    raw_lab = _id_to_label(lid)

                    is_o = (raw_lab == "O") or (o_id is not None and lid == o_id) or (raw_lab == "LABEL_0")
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

                    if cur_label is None:
                        cur_label, cur_start, cur_end = norm_lab, cs, ce
                        cur_scores = [sc]
                        continue

                    if norm_lab != cur_label:
                        if cur_start is not None and cur_end is not None:
                            avg_score = sum(cur_scores) / max(1, len(cur_scores))
                            all_ents.append({"label": cur_label, "start": cur_start, "end": cur_end, "score": float(avg_score)})
                        cur_label, cur_start, cur_end = norm_lab, cs, ce
                        cur_scores = [sc]
                        continue

                    if cur_label in ("LC", "OG", "DT"):
                        if not _soft_gap(cur_end, cs, NER_SOFT_GAP_MAX):
                            if cur_start is not None and cur_end is not None:
                                avg_score = sum(cur_scores) / max(1, len(cur_scores))
                                all_ents.append({"label": cur_label, "start": cur_start, "end": cur_end, "score": float(avg_score)})
                            cur_label, cur_start, cur_end = norm_lab, cs, ce
                            cur_scores = [sc]
                            continue
                        cur_end = max(cur_end or ce, ce)
                        cur_scores.append(sc)
                        continue

                    if cs <= (cur_end or 0):
                        cur_end = max(cur_end or ce, ce)
                        cur_scores.append(sc)
                        continue

                    if not _soft_gap(cur_end, cs, 0):
                        if cur_start is not None and cur_end is not None:
                            avg_score = sum(cur_scores) / max(1, len(cur_scores))
                            all_ents.append({"label": cur_label, "start": cur_start, "end": cur_end, "score": float(avg_score)})
                        cur_label, cur_start, cur_end = norm_lab, cs, ce
                        cur_scores = [sc]
                        continue

                    cur_end = max(cur_end or ce, ce)
                    cur_scores.append(sc)

                if cur_label is not None and cur_start is not None and cur_end is not None:
                    avg_score = sum(cur_scores) / max(1, len(cur_scores))
                    all_ents.append({"label": cur_label, "start": cur_start, "end": cur_end, "score": float(avg_score)})

    merged = _merge_entities(all_ents, merge_gap=NER_MERGE_GAP)

    if ranges:
        merged = [e for e in merged if not any(_overlap((int(e["start"]), int(e["end"])), r) for r in ranges)]

    merged.sort(key=lambda x: (int(x.get("start", 0)), int(x.get("end", 0))))
    merged = _postprocess_split_ps(text, merged)
    merged = _postprocess_merge_lc_parentheses(text, merged)

    debug_info = None
    if debug:
        debug_info = {
            "model_dir": str(NER_MODEL_DIR),
            "labels_filter": labels,
            "exclude_ranges": ranges[:10],
            "pred_label_dist_top": pred_dist.most_common(12),
        }

    return merged, debug_info


def ner_predict_local(
    text: str,
    labels: Optional[List[str]] = None,
    exclude_spans: Optional[List[Dict[str, Any]]] = None,
    max_length: int = NER_MAX_LENGTH,
    stride: int = NER_STRIDE,
    batch_size: int = NER_BATCH_SIZE,
    score_threshold: float = NER_SCORE_THRESHOLD,
) -> List[Dict[str, Any]]:
    ents, _ = _infer_entities_no_text(
        text=text,
        labels=labels,
        exclude_spans=exclude_spans,
        max_length=max_length,
        stride=stride,
        batch_size=batch_size,
        score_threshold=score_threshold,
        debug=False,
    )

    out: List[Dict[str, Any]] = []
    for e in ents:
        out.append(
            {
                "entity_group": str(e["label"]),
                "entity": str(e["label"]),
                "start": int(e["start"]),
                "end": int(e["end"]),
                "score": float(e.get("score", 0.0)),
            }
        )
    return out


@router.get("/health")
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
        is_fast = True
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
            "NER_MASK_MARKDOWN": NER_MASK_MARKDOWN,
            "NER_LOG_MAX_CHARS": NER_LOG_MAX_CHARS,
            "NER_SOFT_GAP_MAX": NER_SOFT_GAP_MAX,
        },
    }


@router.post("/predict")
async def predict_endpoint(payload: Dict[str, Any]) -> Dict[str, Any]:
    text = (payload or {}).get("text", "") or ""
    labels = (payload or {}).get("labels", None)
    exclude_spans = (payload or {}).get("exclude_spans", None)
    debug = bool((payload or {}).get("debug", False))

    if not isinstance(text, str) or not text.strip():
        raise HTTPException(status_code=400, detail="text is required")
    if labels is not None and not isinstance(labels, list):
        raise HTTPException(status_code=400, detail="labels must be a list or null")

    if exclude_spans is None:
        exclude_spans = _auto_exclude_spans_by_regex(text)

    try:
        t0 = time.time()
        ents, dbg = _infer_entities_no_text(
            text=text,
            labels=labels,
            exclude_spans=exclude_spans,
            max_length=NER_MAX_LENGTH,
            stride=NER_STRIDE,
            batch_size=NER_BATCH_SIZE,
            score_threshold=NER_SCORE_THRESHOLD,
            debug=debug,
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

        out: Dict[str, Any] = {"ok": True, "latency_ms": latency_ms, "entities": entities}
        if debug:
            out["debug"] = dbg

        _log_predict_result(out)
        return out

    except NerAPIError as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"NER inference failed: {e}") from e


@router.post("/metrics")
async def ner_metrics(payload: Dict[str, Any]) -> Dict[str, Any]:
    from server.modules.ner_module import compute_span_metrics, compute_document_level_metrics

    docs = (payload or {}).get("docs") or []
    labels = (payload or {}).get("labels")

    if not isinstance(docs, list):
        raise HTTPException(status_code=400, detail="docs must be a list")
    if labels is not None and not isinstance(labels, list):
        raise HTTPException(status_code=400, detail="labels must be a list or null")

    doc_metrics = compute_document_level_metrics(docs, labels=labels)

    all_gold: List[Dict[str, Any]] = []
    all_pred: List[Dict[str, Any]] = []
    for d in docs:
        all_gold.extend(d.get("gold_spans", []) or [])
        all_pred.extend(d.get("pred_spans", []) or [])

    span_metrics = compute_span_metrics(all_gold, all_pred, labels=labels)
    return {"span_metrics": span_metrics, "doc_metrics": doc_metrics}
