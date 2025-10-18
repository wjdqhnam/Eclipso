import re
from datetime import datetime

# 숫자만 추출(공통)
def _digits(s: str) -> str:
    return re.sub(r"\D", "", s or "")

# 날짜 형식 유효성 검증
def is_valid_date6(digits: str) -> bool:
    try:
        dt = datetime.strptime(digits, "%y%m%d")
        return dt.date() <= datetime.today().date()  # 오늘 이후면 False
    except ValueError:
        return False

# 주민등록번호 (내국인)
def is_valid_rrn(rrn: str, opts: dict | None = None) -> bool:
    d = _digits(rrn)
    if len(d) != 13:
        return False
    if not is_valid_date6(d[:6]):
        return False
    use_checksum = (opts or {}).get("rrn_checksum", True)
    if use_checksum and not is_valid_rrn_checksum(d):
        return False
    return True

# 외국인등록번호 checksum 검증
def is_valid_fgn_checksum(fgn: str) -> bool:
    d = _digits(fgn)
    if len(d) != 13:
        return False
    weights = [2,3,4,5,6,7,8,9,2,3,4,5]
    total = sum(int(x) * w for x, w in zip(d[:-1], weights))
    chk = (11 - (total % 11)) % 10
    chk = (chk + 2) % 10
    return chk == int(d[-1])

def is_valid_fgn(fgn: str, opts: dict | None = None) -> bool:
    d = _digits(fgn)
    if len(d) != 13:
        return False
    if not is_valid_date6(d[:6]):
        return False
    if d[6] not in "5678":
        return False
    y = int(d[:2])
    this_year = int(str(datetime.today().year)[2:])
    full_year = 1900 + y if y > this_year else 2000 + y
    if full_year < 2020:
        if not is_valid_fgn_checksum(d):
            return False
    return True

# 주민등록번호 checksum 검증
def is_valid_rrn_checksum(rrn: str) -> bool:
    d = _digits(rrn)
    if len(d) != 13:
        return False
    weights = [2,3,4,5,6,7,8,9,2,3,4,5]
    total = sum(int(x) * w for x, w in zip(d[:-1], weights))
    chk = (11 - (total % 11)) % 10
    return chk == int(d[-1])


# 운전면허번호
def is_valid_driver_license(lic: str, opts: dict | None = None) -> bool:
    d = _digits(lic)
    if len(d) != 12:
        return False
    year = d[2:4]
    try:
        y = int(year)
        this_year = int(str(datetime.today().year)[2:])
        full_year = 1900 + y if y > this_year else 2000 + y
        if not (1960 <= full_year <= datetime.today().year):
            return False
    except ValueError:
        return False
    return True


# 카드번호
def _luhn_ok(d: str) -> bool:
    s = 0
    alt = False
    for ch in reversed(d):
        n = ord(ch) - 48
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        s += n
        alt = not alt
    return (s % 10) == 0


#신용카드 번호
def is_valid_card(number: str, options: dict | None = None) -> bool:
    opts = {"luhn": True, "iin": True}
    if options:
        opts.update(options)

    d = _digits(number)
    if len(d) not in (15, 16):
        return False

    if opts["iin"]:
        if len(d) == 16:
            prefix2 = int(d[:2]) if d[:2].isdigit() else None
            prefix4 = int(d[:4]) if d[:4].isdigit() else None

            if d[0] == "4":        # Visa
                pass
            elif d[0] == "5" and 51 <= int(d[:2]) <= 55:  # Master
                pass
            elif d[0] == "2" and 2221 <= prefix4 <= 2720:  # Master 2-series
                pass
            elif d[0] == "6":      # Discover
                pass
            elif d[0] == "9":      # 국내 카드 BIN 허용
                pass
            elif prefix2 == 35:    # JCB
                pass
            else:
                return False
        else:  # 15자리 → Amex
            if not (d.startswith("34") or d.startswith("37")):
                return False

    if opts["luhn"] and not _luhn_ok(d):
        return False
    return True


# 전화번호
def is_valid_phone_mobile(number: str, options: dict | None = None) -> bool:
    d = _digits(number)
    return d.startswith("010") and len(d) == 11

#지역번호
def is_valid_phone_city(number: str, options: dict | None = None) -> bool:
    d = _digits(number)
    if d.startswith("02") and 9 <= len(d) <= 10:
        return True
    if d[:3] in {f"0{x}" for x in range(31 ,65)} and 10 <= len(d) <= 11:
        return True
    return False

# 이메일
def is_valid_email(addr: str, options: dict | None = None) -> bool:
    pat = re.compile(r"^[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$")
    return bool(pat.match(addr or ""))
