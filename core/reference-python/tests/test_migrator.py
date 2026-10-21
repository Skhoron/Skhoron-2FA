# SPDX-License-Identifier: Apache-2.0
import base64
import unittest
from urllib.parse import quote

from skhoron2fa.migration import decode_payload, decode_uri


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def field_bytes(num, data):
    return varint(num << 3 | 2) + varint(len(data)) + data


def field_varint(num, value):
    return varint(num << 3) + varint(value)


def otp_params(secret, name, issuer="", algo=1, digits=1, kind=2, counter=0):
    body = field_bytes(1, secret) + field_bytes(2, name.encode()) + field_bytes(3, issuer.encode())
    body += field_varint(4, algo) + field_varint(5, digits) + field_varint(6, kind)
    if counter:
        body += field_varint(7, counter)
    return field_bytes(1, body)


def uri_for(payload):
    return "otpauth-migration://offline?data=" + quote(base64.b64encode(payload).decode(), safe="")


class Migration(unittest.TestCase):
    # Пример из открытого описания формата (tabnews.com.br): сторонний, не сгенерирован здесь.
    PUBLIC = ("otpauth-migration://offline?data=CkoKD/EwZ5q6g80oq98RRQnD2hIgX0ZpY3RpY2lvdXNfTmFtZTp1c2VyQGRvbWFpbi"
              "50bGQaD0lzc3Vlcl9Db21wYW55ZSABKAEwAhABGAEgAA==")

    def test_public_sample(self):
        (e,) = decode_uri(self.PUBLIC)
        self.assertEqual(e.secret.hex(), "f130679aba83cd28abdf114509c3da")
        self.assertEqual((e.type, e.algorithm, e.digits), ("totp", "SHA1", 6))
        self.assertEqual(e.issuer, "Issuer_Companye")
        self.assertEqual(e.account, "_Ficticious_Name:user@domain.tld")

    def test_synthetic_multi(self):
        payload = (otp_params(b"\x01" * 20, "Example:alice", "Example")
                   + otp_params(b"\x02" * 32, "bob", "", algo=2, digits=2)
                   + otp_params(b"\x03" * 20, "Corp:carol", "", algo=3, kind=1, counter=9)
                   + field_varint(2, 1) + field_varint(3, 1) + field_varint(4, 0) + field_varint(5, 77))
        a, b, c = decode_uri(uri_for(payload))
        self.assertEqual((a.issuer, a.account, a.type), ("Example", "alice", "totp"))
        self.assertEqual((b.algorithm, b.digits, b.issuer), ("SHA256", 8, ""))
        self.assertEqual((c.issuer, c.account, c.type, c.counter, c.algorithm), ("Corp", "carol", "hotp", 9, "SHA512"))

    def test_unencoded_plus_survives(self):
        # base64 из байт FB EF BE даёт "++++"; перебираем сдвиги, пока "+" не попадёт в строку
        for secret in (bytes([0xFB, 0xEF, 0xBE] * 7), bytes([0xEF, 0xBE, 0xFB] * 7), bytes([0xBE, 0xFB, 0xEF] * 7)):
            payload = otp_params(secret, "n", "i")
            uri = "otpauth-migration://offline?data=" + base64.b64encode(payload).decode()
            if "+" in uri:
                break
        self.assertIn("+", uri)
        (e,) = decode_uri(uri)
        self.assertEqual(e.secret, secret)

    def test_rejections(self):
        with self.assertRaises(ValueError):
            decode_payload(otp_params(b"\x01" * 20, "x", algo=4))        # MD5
        with self.assertRaises(ValueError):
            decode_payload(b"")
        with self.assertRaises(ValueError):
            decode_payload(otp_params(b"", "x"))
        with self.assertRaises(ValueError):
            decode_payload(otp_params(b"\x01" * 20, "x")[:-3])           # обрыв
        with self.assertRaises(ValueError):
            decode_payload(b"\x0a\xff\xff\xff\xff\x0f")                 # длина больше данных
        for bad in ("otpauth://totp/x?secret=AAAA", "otpauth-migration://offline",
                    "otpauth-migration://offline?data=%%%"):
            with self.assertRaises(ValueError, msg=bad):
                decode_uri(bad)


if __name__ == "__main__":
    unittest.main()