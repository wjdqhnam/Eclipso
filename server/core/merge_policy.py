from __future__ import annotations
from typing import List, Dict, Any, Tuple
import re


# 기본 정책 + 색상 매핑
DEFAULT_POLICY: Dict[str, Any] = {
    "allowed_labels": ["PS", "OG", "LC", "DT"],
    "thresholds": {"PS": 0.50, "OG": 0.55, "LC": 0.55, "DT": 0.60},
    "regex_priority": True,                 
    "qt_policy": "off",                   
    "dt_policy": "sensitive_only",         
    "dt_sensitive_triggers": [
        "생년월일", "출생", "DOB",
        "발급", "만료", "유효기간",
        "입사", "퇴사", "고용",
        "진료", "검사", "접수", "접종", "가입"
    ],
    "addr_hints": ["시", "군", "구", "동", "읍", "면", "리", "로", "길", "번지", "빌딩", "센터"],
    "context_window": 18,
    "emit_text_sample": True,
    "text_sample_maxlen": 40,

    "use_ner_highlight": True,
    "color_map": {
        "PS": "#ff4d4f",   
        "LC": "#ffb6c1",  
        "OG": "#ffd666",   
        "DT": "#87cefa",   
        "QT": "#90ee90"    
    }
}

NER_PRIORITY = {"PS": 5, "OG": 4, "LC": 3, "DT": 2, "QT": 1}


RRN_RE = re.compile(r"\d{6}-\d{7}")
FGN_RE = re.compile(r"\d{6}-\d{7}")
CARD_RE = re.compile(r"(?:\d[ -]?){15,16}")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}")
MOBILE_RE = re.compile(r"01[016789]-?\d{3,4}-?\d{4}")
CITY_RE = re.compile(r"(?:02|0(?:3[1-3]|4[1-4]|5[1-5]|6[1-4]))-?\d{3,4}-?\d{4}")
PASSPORT_RE = re.compile(r"(?:[MSRODG]\d{8}|[MSRODG]\d{3}[A-Z]\d{4})")
DRIVER_RE = re.compile(r"\d{2}-?\d{2}-?\d{6}-?\d{2}")

SENSITIVE_NUMBER_PATTERNS = [
    RRN_RE, FGN_RE, CARD_RE, EMAIL_RE, MOBILE_RE, CITY_RE, PASSPORT_RE, DRIVER_RE
]

def _is_sensitive_number(s: str) -> bool:
    if not s:
        return False
    t = s.strip()
    for rx in SENSITIVE_NUMBER_PATTERNS:
        if rx.fullmatch(t) or rx.search(t):
            return True
    return False

def _clip(i: int, n: int) -> int:
    return max(0, min(n, i))

def _text_sample(text: str, s: int, e: int, maxlen: int) -> str:
    frag = text[_clip(s, len(text)):_clip(e, len(text))]
    if len(frag) > maxlen:
        return frag[:maxlen-1] + "…"
    return frag

def _overlaps(a: Tuple[int,int], b: Tuple[int,int]) -> bool:
    return min(a[1], b[1]) - max(a[0], b[0]) > 0


class MergePolicy:
    def __init__(self, policy: Dict[str, Any] = None):
        self.policy = dict(DEFAULT_POLICY)
        if policy:
            self.policy.update(policy)

    def merge(
        self,
        text: str,
        regex_spans: List[Dict[str, Any]],
        ner_spans: List[Dict[str, Any]],
        degrade: bool = False
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        p = self.policy
        allowed = set(p.get("allowed_labels", []))
        thresholds = p.get("thresholds", {})
        regex_first = bool(p.get("regex_priority", True))
        dt_policy = str(p.get("dt_policy", "sensitive_only"))
        dt_triggers = list(p.get("dt_sensitive_triggers", []))
        ctx = int(p.get("context_window", 18))
        use_hl = bool(p.get("use_ner_highlight", True))
        color_map = p.get("color_map", {})
        emit_sample = bool(p.get("emit_text_sample", True))
        sample_len = int(p.get("text_sample_maxlen", 40))

        n = len(text or "")
        report = {
            "degrade": degrade,
            "conflicts_resolved": 0,
            "dropped_by_regex_lock": 0,
            "dropped_by_threshold": 0,
            "dropped_by_label_block": 0,
            "dropped_dt_not_sensitive": 0,
            "merged_adjacent": 0,
            "counts_by_label": {},
            "policy_snapshot": p
        }

        out: List[Dict[str, Any]] = []

        regex_locks: List[Tuple[int,int]] = []
        for r in regex_spans or []:
            s, e = int(r["start"]), int(r["end"])
            if e <= s: 
                continue
            span = {
                "start": s, "end": e,
                "label": str(r.get("label", "REGEX")),
                "source": "regex",
                "score": None,
                "decision": "redact",
                "color": None,
                "reason": "R1_regex_lock"
            }
            if emit_sample:
                span["text_sample"] = _text_sample(text, s, e, sample_len)
            out.append(span)
            regex_locks.append((s, e))

        filtered_ner: List[Dict[str, Any]] = []
        for s in ner_spans or []:
            lab = str(s.get("label", "")).upper()
            if lab not in allowed and lab != "QT":
                report["dropped_by_label_block"] += 1
                continue
            score = s.get("score")
            th = thresholds.get(lab)
            if (th is not None) and (score is not None) and (float(score) < float(th)):
                report["dropped_by_threshold"] += 1
                continue
            if lab == "DT" and dt_policy == "sensitive_only":
                s0, e0 = int(s["start"]), int(s["end"])
                lo, hi = _clip(s0 - ctx, n), _clip(e0 + ctx, n)
                ctxt = text[lo:hi]
                if not any(t in ctxt for t in dt_triggers):
                    report["dropped_dt_not_sensitive"] += 1
                    continue
            filtered_ner.append(s)

        if regex_first and regex_locks:
            kept: List[Dict[str, Any]] = []
            for s in filtered_ner:
                a = (int(s["start"]), int(s["end"]))
                if any(_overlaps(a, b) for b in regex_locks):
                    report["dropped_by_regex_lock"] += 1
                    continue
                kept.append(s)
            filtered_ner = kept

        for s in filtered_ner:
            s0, e0 = int(s["start"]), int(s["end"])
            lab = str(s.get("label", "")).upper()
            frag = text[_clip(s0, n):_clip(e0, n)]
            item = {
                "start": s0, "end": e0,
                "label": lab,
                "source": "ner",
                "score": s.get("score"),
            }

            # QT 특례: 민감 숫자면 레닥션
            if lab == "QT":
                if _is_sensitive_number(frag):
                    item.update({"decision": "redact", "color": None, "reason": "R3_qt_sensitive"})
                else:
                    if use_hl:
                        item.update({"decision": "highlight", "color": color_map.get("QT"), "reason": "R2_ner_accept"})
                    else:
                        # highlight off면 그냥 버림
                        report["dropped_by_label_block"] += 1
                        continue
            else:
                # 일반 라벨은 하이라이트
                if use_hl:
                    item.update({"decision": "highlight", "color": color_map.get(lab), "reason": "R2_ner_accept"})
                else:
                    # 하이라이트 비활성화면 버림
                    report["dropped_by_label_block"] += 1
                    continue

            if emit_sample:
                item["text_sample"] = _text_sample(text, s0, e0, sample_len)
            out.append(item)

        # 5) 정렬 + 라벨 카운트
        out.sort(key=lambda x: (x["start"], x["end"], x["source"]))
        counts: Dict[str,int] = {}
        for s in out:
            counts[s["label"]] = counts.get(s["label"], 0) + 1
        report["counts_by_label"] = counts
        return out, report
