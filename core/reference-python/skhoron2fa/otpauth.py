# SPDX-License-Identifier: Apache-2.0
"""Разбор и сборка otpauth:// (формат Key URI)."""
from dataclasses import dataclass
from urllib.parse import parse_qs, quote, unquote, urlsplit

from .otp import ALGORITHMS, VALID_DIGITS, b32decode, b32encode


MAX_URI_LENGTH = 2048


@dataclass(frozen=True)
class Entry:
    type: str            # "totp" | "hotp"
    issuer: str
    account: str
    secret: bytes
    algorithm: str = "SHA1"
    digits: int = 6
    period: int = 30
    counter: int = 0

    def dedupe_key(self):
        return (self.type, self.issuer.casefold(), self.account.casefold(),
                self.secret, self.algorithm, self.digits, self.period)


def parse(uri: str) -> Entry:
    if len(uri) > MAX_URI_LENGTH:
        raise ValueError("слишком длинный URI")
    parts = urlsplit(uri.strip())
    if parts.scheme.lower() != "otpauth":
        raise ValueError("ожидается схема otpauth://")
    kind = parts.netloc.lower()
    if kind not in ("totp", "hotp"):
        raise ValueError("тип должен быть totp или hotp")
    raw_label = parts.path.lstrip("/")
    query = {k.lower(): v[-1] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}

    if "secret" not in query:
        raise ValueError("нет параметра secret")
    secret = b32decode(query["secret"])

    algorithm = query.get("algorithm", "SHA1").upper()
    if algorithm not in ALGORITHMS:
        raise ValueError("неподдерживаемый алгоритм: %s" % algorithm)

    digits = int(query.get("digits", "6"))
    if digits not in VALID_DIGITS:
        raise ValueError("digits должно быть 6, 7 или 8")

    period = int(query.get("period", "30"))
    if period <= 0:
        raise ValueError("period должен быть положительным")

    counter = 0
    if kind == "hotp":
        if "counter" not in query:
            raise ValueError("для hotp нужен counter")
        counter = int(query["counter"])
        if counter < 0:
            raise ValueError("отрицательный counter")

    # Делим по первому ":" ДО раскодирования: двоеточие внутри issuer приходит как %3A.
    # Часть генераторов кодирует и сам разделитель (%3A) - тогда делим по нему.
    issuer, account = "", unquote(raw_label).strip()
    separator = raw_label.find(":")
    width = 1
    if separator < 0:
        separator = raw_label.upper().find("%3A")
        width = 3
    if separator >= 0:
        issuer = unquote(raw_label[:separator]).strip()
        account = unquote(raw_label[separator + width:]).strip()
    if query.get("issuer"):
        issuer = query["issuer"]
    return Entry(kind, issuer, account, secret, algorithm, digits, period, counter)


def build(entry: Entry) -> str:
    label = quote(entry.account, safe="@")
    if entry.issuer:
        label = quote(entry.issuer, safe="") + ":" + label
    params = ["secret=" + b32encode(entry.secret)]
    if entry.issuer:
        params.append("issuer=" + quote(entry.issuer, safe=""))
    params.append("algorithm=" + entry.algorithm)
    params.append("digits=%d" % entry.digits)
    if entry.type == "totp":
        params.append("period=%d" % entry.period)
    else:
        params.append("counter=%d" % entry.counter)
    return "otpauth://%s/%s?%s" % (entry.type, label, "&".join(params))