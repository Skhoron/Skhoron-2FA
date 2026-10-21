# SPDX-License-Identifier: Apache-2.0
"""Генерирует core/test-vectors/{cross,uri}.tsv и uri_invalid.txt.

cross.tsv считается отдельным кодом (hashlib/hmac напрямую), не через skhoron2fa.otp,
поэтому служит независимой проверкой и для Python-, и для Java-реализации.
"""
import base64
import hashlib
import hmac
import json
import os
import random
import struct
import sys

OUT = os.path.join(os.path.dirname(__file__), "..", "core", "test-vectors")
HASHES = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def raw_totp(secret, algo, digits, period, t):
    msg = struct.pack(">Q", t // period)
    mac = hmac.new(secret, msg, HASHES[algo]).digest()
    off = mac[-1] & 15
    return str((struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


def cross():
    rng = random.Random(20261020)
    lines = ["# secret_base32\talgorithm\tdigits\tperiod\tunix_time\texpected"]
    for _ in range(300):
        secret = bytes(rng.randrange(256) for _ in range(rng.randint(10, 64)))
        algo = rng.choice(list(HASHES))
        digits = rng.choice((6, 7, 8))
        period = rng.choice((15, 30, 60))
        t = rng.randrange(0, 4_000_000_000)
        b32 = base64.b32encode(secret).decode().rstrip("=")
        lines.append("\t".join(map(str, (b32, algo, digits, period, t, raw_totp(secret, algo, digits, period, t)))))
    return "\n".join(lines) + "\n"


def hexs(b32):
    return base64.b32decode(b32 + "=" * (-len(b32) % 8)).hex()


def uris():
    hello = hexs("JBSWY3DPEHPK3PXP")
    acme = hexs("HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ")
    rfc = hexs("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    rows = [
        ("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
         "Example", "alice@google.com", hello, "SHA1", 6, 30, "totp", 0),
        ("otpauth://totp/alice@example.com?secret=jbswy3dpehpk3pxp",
         "", "alice@example.com", hello, "SHA1", 6, 30, "totp", 0),
        ("otpauth://totp/ACME%20Co:john.doe%40email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
         "ACME Co", "john.doe@email.com", acme, "SHA256", 8, 60, "totp", 0),
        ("otpauth://hotp/Svc:bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=5&issuer=Svc",
         "Svc", "bob", rfc, "SHA1", 6, 30, "hotp", 5),
        ("otpauth://totp/Old:carol?secret=JBSWY3DPEHPK3PXP&issuer=New",
         "New", "carol", hello, "SHA1", 6, 30, "totp", 0),
        ("otpauth://totp/x?secret=JBSW%20Y3DP-EHPK%203PXP",
         "", "x", hello, "SHA1", 6, 30, "totp", 0),
        ("otpauth://totp/%D0%9F%D1%80%D0%B8%D0%BC%D0%B5%D1%80:%D0%B8%D0%B2%D0%B0%D0%BD?secret=JBSWY3DPEHPK3PXP",
         "Пример", "иван", hello, "SHA1", 6, 30, "totp", 0),
        ("otpauth://totp/Seven:u?secret=JBSWY3DPEHPK3PXP&digits=7&algorithm=sha512",
         "Seven", "u", hello, "SHA512", 7, 30, "totp", 0),
        ("otpauth://totp/A%3AB:acct?secret=JBSWY3DPEHPK3PXP",
         "A:B", "acct", hello, "SHA1", 6, 30, "totp", 0),
        ("otpauth://totp/Example%3Aalice?secret=JBSWY3DPEHPK3PXP",
         "Example", "alice", hello, "SHA1", 6, 30, "totp", 0),
        (PREFIX + "A" * (LIMIT - len(PREFIX)),
         "A" * (LIMIT - len(PREFIX)), "x", hello, "SHA1", 6, 30, "totp", 0),
    ]
    head = "# uri\tissuer\taccount\tsecret_hex\talgorithm\tdigits\tperiod\ttype\tcounter"
    return head + "\n" + "\n".join("\t".join(map(str, r)) for r in rows) + "\n"


EXPORT_PASSWORD = "пароль-тест"
REFERENCE_PYTHON = os.path.join(os.path.dirname(__file__), "..", "core", "reference-python")
RFC9106_ID_TAG = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"


def blake():
    rng = random.Random(7)
    lines = ["# outlen\tinput_hex\texpected_hex"]
    for outlen in (1, 16, 32, 48, 64):
        for length in (0, 1, 3, 127, 128, 129, 200, 255, 256, 257, 1000, 1030):
            data = bytes(rng.randrange(256) for _ in range(length))
            digest = hashlib.blake2b(data, digest_size=outlen).hexdigest()
            lines.append("%d\t%s\t%s" % (outlen, data.hex(), digest))
    return "\n".join(lines) + "\n"


def argon():
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    rng = random.Random(9)

    def rb(n):
        return bytes(rng.randrange(256) for _ in range(n))

    lines = ["# password_hex\tsalt_hex\tsecret_hex\tad_hex\titerations\tmemory_kib\tlanes\ttag_len\texpected_hex"]

    def add(pw, salt, secret, ad, t, m, p, n):
        tag = Argon2id(salt=salt, length=n, iterations=t, lanes=p, memory_cost=m,
                       ad=ad or None, secret=secret or None).derive(pw)
        lines.append("\t".join((pw.hex(), salt.hex(), secret.hex(), ad.hex(), str(t), str(m), str(p), str(n), tag.hex())))
        return tag

    rfc = add(b"\x01" * 32, b"\x02" * 16, b"\x03" * 8, b"\x04" * 12, 3, 32, 4, 32)
    assert rfc.hex() == RFC9106_ID_TAG, "оракул не совпал с вектором RFC 9106"
    for t, m, p, n in [(1, 8, 1, 32), (2, 16, 2, 32), (3, 32, 4, 32), (3, 64, 4, 16), (1, 1024, 1, 64),
                       (2, 256, 3, 100), (4, 128, 2, 32), (1, 24, 3, 32), (2, 40, 5, 8), (2, 100, 3, 32),
                       (3, 65536, 4, 32)]:
        add(rb(rng.randint(1, 40)), rb(rng.randint(8, 32)), rb(rng.choice((0, 8))), rb(rng.choice((0, 12))), t, m, p, n)
    return "\n".join(lines) + "\n"


def export_entries():
    sys.path.insert(0, REFERENCE_PYTHON)
    from skhoron2fa.otpauth import Entry
    return [
        Entry("totp", "Example", "alice@example.com", bytes(range(1, 21)), "SHA1", 6, 30, 0),
        Entry("totp", "ACME", "bob", bytes(range(50, 82)), "SHA256", 8, 60, 0),
        Entry("hotp", 'Пример "кавычки" \\ слэш', "иван\tтаб", b"\x09" * 20, "SHA512", 7, 30, 4),
        Entry("totp", "Control", "line1\nline2\u0001", b"\x11" * 10, "SHA1", 6, 15, 0),
    ]


def export_expected():
    sys.path.insert(0, REFERENCE_PYTHON)
    from skhoron2fa import vault
    return json.dumps({"entries": [vault._entry_to_json(e) for e in export_entries()]},
                      ensure_ascii=False, indent=1) + "\n"


def export_python():
    """Файл экспорта, созданный Python-эталоном (соль и nonce детерминированы ради воспроизводимости)."""
    sys.path.insert(0, REFERENCE_PYTHON)
    from skhoron2fa import vault
    rng = random.Random(77)
    original = vault.os.urandom
    vault.os.urandom = lambda n: bytes(rng.randrange(256) for _ in range(n))
    try:
        text = vault.encrypt_entries(export_entries(), EXPORT_PASSWORD,
                                     {"iterations": 2, "memory_kib": 1024, "lanes": 2})
    finally:
        vault.os.urandom = original
    return text + "\n"


PREFIX = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer="
LIMIT = 2048   # core: MAX_URI_LENGTH

INVALID = """# каждая строка обязана отклоняться парсером
http://totp/x?secret=JBSWY3DPEHPK3PXP
otpauth://steam/x?secret=JBSWY3DPEHPK3PXP
otpauth://totp/x
otpauth://totp/x?secret=
otpauth://totp/x?secret=!!!!
otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=5
otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=9
otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=abc
otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5
otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0
otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP
"""

if __name__ == "__main__":
    too_long = PREFIX + "A" * (LIMIT + 1 - len(PREFIX)) + "\n"           # ровно LIMIT+1 символов
    outputs = (("cross.tsv", cross()), ("uri.tsv", uris()), ("uri_invalid.txt", INVALID + too_long),
               ("blake2b.tsv", blake()), ("argon2id.tsv", argon()),
               ("export_expected.json", export_expected()), ("export_python.json", export_python()))
    for name, text in outputs:
        with open(os.path.join(OUT, name), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        print("записан", name)