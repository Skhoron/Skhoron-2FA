# SPDX-License-Identifier: Apache-2.0
"""Зашифрованный экспорт/импорт (см. docs/EXPORT_FORMAT.md) и слияние без дублей."""
import base64
import json
import os
import unicodedata

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from .otp import b32decode, b32encode
from .otpauth import Entry, build

FORMAT = "skhoron-2fa-export"
VERSION = 1
DEFAULT_KDF = {"iterations": 3, "memory_kib": 65536, "lanes": 4}
MAX_MEMORY_KIB = 262144      # верхняя граница, чтобы чужой файл не съел всю память
MAX_ITERATIONS = 10
MAX_LANES = 16


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def _derive(password: str, salt: bytes, kdf: dict) -> bytes:
    pw = unicodedata.normalize("NFKC", password).encode("utf-8")
    return Argon2id(salt=salt, length=32, iterations=kdf["iterations"],
                    lanes=kdf["lanes"], memory_cost=kdf["memory_kib"]).derive(pw)


def _aad(header: dict) -> bytes:
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def encrypt_entries(entries, password: str, kdf_params: dict = None) -> str:
    if not password:
        raise ValueError("пустой пароль")
    params = dict(DEFAULT_KDF, **(kdf_params or {}))
    salt, nonce = os.urandom(16), os.urandom(12)
    header = {
        "format": FORMAT,
        "version": VERSION,
        "kdf": dict(name="argon2id", salt=_b64(salt), **params),
        "cipher": {"name": "aes-256-gcm", "nonce": _b64(nonce)},
    }
    plain = json.dumps({"entries": [_entry_to_json(e) for e in entries]},
                       ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(_derive(password, salt, header["kdf"])).encrypt(nonce, plain, _aad(header))
    return json.dumps(dict(header, ciphertext=_b64(ciphertext)), indent=2)


def decrypt_entries(text: str, password: str) -> list:
    doc = json.loads(text)
    ciphertext = _unb64(doc.pop("ciphertext"))
    header = doc
    if header.get("format") != FORMAT or header.get("version") != VERSION:
        raise ValueError("неизвестный формат или версия файла")
    kdf, cipher = header["kdf"], header["cipher"]
    if kdf.get("name") != "argon2id" or cipher.get("name") != "aes-256-gcm":
        raise ValueError("неподдерживаемые алгоритмы в файле")
    if (kdf["memory_kib"] > MAX_MEMORY_KIB or kdf["iterations"] > MAX_ITERATIONS
            or kdf["lanes"] > MAX_LANES or kdf["memory_kib"] < 8 * kdf["lanes"]
            or kdf["iterations"] < 1 or kdf["lanes"] < 1):
        raise ValueError("параметры KDF вне допустимых границ")
    key = _derive(password, _unb64(kdf["salt"]), kdf)
    plain = AESGCM(key).decrypt(_unb64(cipher["nonce"]), ciphertext, _aad(header))
    return [_entry_from_json(item) for item in json.loads(plain)["entries"]]


def _entry_to_json(e: Entry) -> dict:
    return {"type": e.type, "issuer": e.issuer, "account": e.account,
            "secret": b32encode(e.secret), "algorithm": e.algorithm,
            "digits": e.digits, "period": e.period, "counter": e.counter}


def _entry_from_json(d: dict) -> Entry:
    return Entry(d["type"], d["issuer"], d["account"], b32decode(d["secret"]),
                 d["algorithm"], d["digits"], d["period"], d["counter"])


def merge_entries(existing, incoming):
    """Добавляет только те записи, которых ещё нет. Возвращает (список, добавлено, пропущено)."""
    merged = list(existing)
    seen = {e.dedupe_key() for e in merged}
    added = skipped = 0
    for entry in incoming:
        key = entry.dedupe_key()
        if key in seen:
            skipped += 1
        else:
            seen.add(key)
            merged.append(entry)
            added += 1
    return merged, added, skipped


def to_otpauth_list(entries) -> str:
    return "\n".join(build(e) for e in entries) + "\n"