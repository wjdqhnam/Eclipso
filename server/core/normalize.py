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

    out_chars: list[str] = []
    index_map: dict[int, int] = {}
    norm_i = 0
    prev_space = False

    for i, ch in enumerate(s):
        # 1) NFKC
        norm = unicodedata.normalize("NFKC", ch)

        # 2) 제로폭 제거
        if _ZERO_WIDTH.match(norm):
            if out_chars:
                index_map[len(out_chars)] = i
            continue

        # 3) NBSP류 → ' '
        norm = _NBSP.sub(" ", norm)
        if out_chars:
            index_map[len(out_chars)] = i

        # 4) 대시류 → '-'
        norm = _DASHES.sub("-", norm)

        for c in norm:
            # 탭 → 공백
            if c == "\t":
                c = " "
            # CR/LF 정규화: \r?\n → \n  (여기서는 이미 원문 문자 단위에서 처리)
            if c == "\r":
                continue

            # 연속 공백 압축 (줄바꿈 제외)
            if c == " ":
                if prev_space:
                    continue
                prev_space = True
            else:
                    prev_space = False

            out_chars.append(c)
            index_map[norm_i] = i
            norm_i += 1

    text = "".join(out_chars)
    return text, index_map