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

def normalize_text(s: str | None) -> str:
    if not s: return ""
    s = unicodedata.normalize("NFKC", s)
    s = re.sub(r"\r\n?", "\n", s)
    s = strip_invisible(s)
    s = _DASHES.sub("-", s)
    s = s.replace("\t", " ")
    s = re.sub(r"[ \f\v]+", " ", s)
    s = "\n".join(re.sub(r"[ \t]+$", "", line) for line in s.split("\n"))
    return s
