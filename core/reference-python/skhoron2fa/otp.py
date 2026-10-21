# SPDX-License-Identifier: Apache-2.0
"""HOTP (RFC 4226) и TOTP (RFC 6238). Только hashlib и hmac из стандартной библиотеки."""
import base64
import hashlib
import hmac
import re
import struct

ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}
VALID_DIGITS = (6, 7, 8)


def b32decode(text: str) -> bytes:
    """Base32 с допусками: пробелы, дефисы, нижний регистр, отсутствие '='."""
    cleaned = re.sub(r"[\s-]", "", text).upper().rstrip("=")
    if not cleaned or re.search(r"[^A-Z2-7]", cleaned):
        raise ValueError("некорректный base32")
    cleaned += "=" * (-len(cleaned) % 8)
    return base64.b32decode(cleaned)


def b32encode(data: bytes) -> str:
    return base64.b32encode(data).decode("ascii").rstrip("=")


def hotp(secret: bytes, counter: int, digits: int = 6, algorithm: str = "SHA1") -> str:
    if digits not in VALID_DIGITS:
        raise ValueError("digits должно быть 6, 7 или 8")
    if algorithm not in ALGORITHMS:
        raise ValueError("неподдерживаемый алгоритм: %r" % algorithm)
    if not secret:
        raise ValueError("пустой секрет")
    if counter < 0:
        raise ValueError("отрицательный счётчик")
    mac = hmac.new(secret, struct.pack(">Q", counter), ALGORITHMS[algorithm]).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** digits).zfill(digits)


def totp(secret: bytes, unix_time: int, period: int = 30, digits: int = 6,
         algorithm: str = "SHA1", t0: int = 0) -> str:
    if period <= 0:
        raise ValueError("period должен быть положительным")
    return hotp(secret, (int(unix_time) - t0) // period, digits, algorithm)


def seconds_remaining(unix_time: int, period: int = 30) -> int:
    return period - int(unix_time) % period