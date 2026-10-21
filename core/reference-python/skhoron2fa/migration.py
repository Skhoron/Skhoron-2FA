# SPDX-License-Identifier: Apache-2.0
"""Импорт из Google Authenticator: otpauth-migration://offline?data=...

Схема MigrationPayload: repeated OtpParameters = 1;
OtpParameters { bytes secret = 1; string name = 2; string issuer = 3;
Algorithm algorithm = 4; DigitCount digits = 5; OtpType type = 6; int64 counter = 7 }.
"""
import base64
import binascii
from urllib.parse import parse_qs, urlsplit

from .otpauth import Entry

_ALGORITHMS = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512"}
_DIGITS = {0: 6, 1: 6, 2: 8}
_TYPES = {0: "totp", 1: "hotp", 2: "totp"}


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def eof(self) -> bool:
        return self.pos >= len(self.data)

    def varint(self) -> int:
        result = shift = 0
        while True:
            if self.pos >= len(self.data):
                raise ValueError("обрыв varint")
            byte = self.data[self.pos]
            self.pos += 1
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return result
            shift += 7
            if shift > 63:
                raise ValueError("слишком длинный varint")

    def length_delimited(self) -> bytes:
        size = self.varint()
        end = self.pos + size
        if end > len(self.data):
            raise ValueError("поле длиннее данных")
        chunk = self.data[self.pos:end]
        self.pos = end
        return chunk

    def skip(self, wire: int) -> None:
        if wire == 0:
            self.varint()
        elif wire == 1:
            self._advance(8)
        elif wire == 2:
            self.length_delimited()
        elif wire == 5:
            self._advance(4)
        else:
            raise ValueError("неподдерживаемый wire type %d" % wire)

    def _advance(self, count: int) -> None:
        if self.pos + count > len(self.data):
            raise ValueError("обрыв данных")
        self.pos += count


def _parse_otp_parameters(blob: bytes) -> Entry:
    reader = _Reader(blob)
    secret, name, issuer = b"", "", ""
    algorithm = digits = kind = counter = 0
    while not reader.eof():
        tag = reader.varint()
        field, wire = tag >> 3, tag & 7
        if field == 1 and wire == 2:
            secret = reader.length_delimited()
        elif field == 2 and wire == 2:
            name = reader.length_delimited().decode("utf-8")
        elif field == 3 and wire == 2:
            issuer = reader.length_delimited().decode("utf-8")
        elif field == 4 and wire == 0:
            algorithm = reader.varint()
        elif field == 5 and wire == 0:
            digits = reader.varint()
        elif field == 6 and wire == 0:
            kind = reader.varint()
        elif field == 7 and wire == 0:
            counter = reader.varint()
        else:
            reader.skip(wire)
    if not secret:
        raise ValueError("запись без секрета")
    if algorithm not in _ALGORITHMS:
        raise ValueError("неподдерживаемый алгоритм (код %d)" % algorithm)
    if digits not in _DIGITS:
        raise ValueError("неподдерживаемое число цифр (код %d)" % digits)
    if kind not in _TYPES:
        raise ValueError("неизвестный тип OTP (код %d)" % kind)
    account = name
    if ":" in name:
        prefix, rest = name.split(":", 1)
        if not issuer:
            issuer = prefix.strip()
        if prefix.strip() == issuer:
            account = rest.strip()
    return Entry(_TYPES[kind], issuer, account, secret, _ALGORITHMS[algorithm],
                 _DIGITS[digits], 30, counter)


def decode_payload(payload: bytes) -> list:
    reader = _Reader(payload)
    entries = []
    while not reader.eof():
        tag = reader.varint()
        field, wire = tag >> 3, tag & 7
        if field == 1 and wire == 2:
            entries.append(_parse_otp_parameters(reader.length_delimited()))
        else:
            reader.skip(wire)
    if not entries:
        raise ValueError("в данных нет ни одной записи")
    return entries


def decode_uri(uri: str) -> list:
    parts = urlsplit(uri.strip())
    if parts.scheme != "otpauth-migration" or parts.netloc != "offline":
        raise ValueError("ожидается otpauth-migration://offline?data=...")
    values = parse_qs(parts.query).get("data")
    if not values:
        raise ValueError("нет параметра data")
    text = values[-1].replace(" ", "+")      # '+' мог потерять процентное кодирование
    text += "=" * (-len(text) % 4)
    try:
        raw = base64.b64decode(text.replace("-", "+").replace("_", "/"), validate=True)
    except binascii.Error as exc:
        raise ValueError("data не является base64") from exc
    return decode_payload(raw)