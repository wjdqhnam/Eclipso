import re, unicodedata

_ZERO_WIDTH = re.compile(r"[\u200B\u200C\u200D\u2060\ufeff]")
_NBSP       = re.compile(r"[\u00A0\u2007\u202F]")
_DASHES     = re.compile(r"[\u2010\u2011\u2012\u2013\u2014\u2212\ufe63\u2043]")

def digits_only(s: str | None) -> str:
    return re.sub(r"\D+", "", s or "")

def strip_invisible(s: str) -> str:
    s = _ZERO_WIDTH.sub("", s)
    s = _NBSP.sub(" ", s)
    return s

#매핑 필요없는 곳에 사용하는 단순 정규화 방식
def normalization_text(s: str | None) -> str:
    if not s: return ""
    s = unicodedata.normalize("NFKC", s)
    s = re.sub(r"\r\n?", "\n", s)
    s = strip_invisible(s)
    s = _DASHES.sub("-", s)
    s = s.replace("\t", " ")
    s = re.sub(r"[ \f\v]+", " ", s)
    s = "\n".join(re.sub(r"[ \t]+$", "", line) for line in s.split("\n"))
    return s

#정규화된 문자열과 원문 인덱스 매핑한 맵을 반환함.
# dict: {정규화된 인덱스: 원문 인덱스}
def normalization_index(s: str | None) -> tuple[str, dict[int, int]]:
    if not s:
        return "", {}

    normalized_chars: list[str] = []
    index_map: dict[int, int] = {}
    norm_i = 0

    for i, ch in enumerate(s):
        norm_ch = unicodedata.normalize("NFKC", ch)
        if _ZERO_WIDTH.match(norm_ch):
            continue
        norm_ch = _NBSP.sub(" ", norm_ch)
        norm_ch = _DASHES.sub("-", norm_ch)
        for c in norm_ch:
            normalized_chars.append(c)
            index_map[norm_i] = i
            norm_i += 1

    text = "".join(normalized_chars)
    # 후처리 (공백, 줄바꿈 등 동일 정리)
    text = re.sub(r"\r\n?", "\n", text)
    text = text.replace("\t", " ")
    text = re.sub(r"[ \f\v]+", " ", text)
    text = "\n".join(re.sub(r"[ \t]+$", "", line) for line in text.split("\n"))

    return text, index_map