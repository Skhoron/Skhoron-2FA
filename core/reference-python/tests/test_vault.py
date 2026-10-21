# SPDX-License-Identifier: Apache-2.0
import json
import os
import unittest

from cryptography.exceptions import InvalidTag

from skhoron2fa import vault
from skhoron2fa.otp import b32encode
from skhoron2fa.otpauth import Entry

FAST = {"iterations": 1, "memory_kib": 1024, "lanes": 1}
ENTRIES = [
    Entry("totp", "Example", "alice@example.com", bytes(range(1, 21)), "SHA1", 6, 30, 0),
    Entry("totp", "ACME", "bob", bytes(range(50, 82)), "SHA256", 8, 60, 0),
    Entry("hotp", "Svc", "иван", b"\x09" * 20, "SHA512", 7, 30, 4),
]


class Export(unittest.TestCase):
    def test_roundtrip(self):
        text = vault.encrypt_entries(ENTRIES, "пароль-123", FAST)
        self.assertEqual(vault.decrypt_entries(text, "пароль-123"), ENTRIES)

    def test_roundtrip_default_kdf(self):
        text = vault.encrypt_entries(ENTRIES[:1], "pw", None)
        self.assertEqual(json.loads(text)["kdf"]["memory_kib"], 65536)
        self.assertEqual(vault.decrypt_entries(text, "pw"), ENTRIES[:1])

    def test_wrong_password(self):
        text = vault.encrypt_entries(ENTRIES, "right", FAST)
        with self.assertRaises(InvalidTag):
            vault.decrypt_entries(text, "wrong")

    def test_no_plaintext_leak(self):
        text = vault.encrypt_entries(ENTRIES, "pw", FAST)
        for e in ENTRIES:
            self.assertNotIn(b32encode(e.secret), text)
            self.assertNotIn(e.account, text)

    def test_tamper_ciphertext(self):
        doc = json.loads(vault.encrypt_entries(ENTRIES, "pw", FAST))
        raw = bytearray(__import__("base64").b64decode(doc["ciphertext"]))
        raw[0] ^= 1
        doc["ciphertext"] = __import__("base64").b64encode(bytes(raw)).decode()
        with self.assertRaises(InvalidTag):
            vault.decrypt_entries(json.dumps(doc), "pw")

    def test_header_is_authenticated(self):
        doc = json.loads(vault.encrypt_entries(ENTRIES, "pw", FAST))
        doc["note"] = "добавлено снаружи"
        with self.assertRaises(InvalidTag):
            vault.decrypt_entries(json.dumps(doc), "pw")

    def test_fresh_salt_and_nonce(self):
        a = json.loads(vault.encrypt_entries(ENTRIES, "pw", FAST))
        b = json.loads(vault.encrypt_entries(ENTRIES, "pw", FAST))
        self.assertNotEqual(a["kdf"]["salt"], b["kdf"]["salt"])
        self.assertNotEqual(a["cipher"]["nonce"], b["cipher"]["nonce"])
        self.assertNotEqual(a["ciphertext"], b["ciphertext"])

    def test_kdf_bounds(self):
        doc = json.loads(vault.encrypt_entries(ENTRIES, "pw", FAST))
        for key, value in (("memory_kib", 10 ** 7), ("iterations", 1000), ("lanes", 64), ("iterations", 0)):
            bad = json.loads(json.dumps(doc))
            bad["kdf"][key] = value
            with self.assertRaises(ValueError, msg=key):
                vault.decrypt_entries(json.dumps(bad), "pw")

    def test_unknown_format_and_version(self):
        doc = json.loads(vault.encrypt_entries(ENTRIES, "pw", FAST))
        for key, value in (("format", "other"), ("version", 2)):
            bad = dict(doc, **{key: value})
            with self.assertRaises(ValueError):
                vault.decrypt_entries(json.dumps(bad), "pw")

    def test_unicode_normalization_of_password(self):
        text = vault.encrypt_entries(ENTRIES[:1], "caf\u00e9", FAST)       # é одним символом
        self.assertEqual(vault.decrypt_entries(text, "cafe\u0301"), ENTRIES[:1])   # e + combining

    def test_empty_password_rejected(self):
        with self.assertRaises(ValueError):
            vault.encrypt_entries(ENTRIES, "", FAST)


class Fixture(unittest.TestCase):
    def test_exported_fixture_decrypts(self):
        base = os.path.join(os.path.dirname(__file__), "..", "..", "test-vectors")
        with open(os.path.join(base, "export_python.json"), encoding="utf-8") as fh:
            text = fh.read()
        with open(os.path.join(base, "export_expected.json"), encoding="utf-8") as fh:
            expected = [vault._entry_from_json(item) for item in json.load(fh)["entries"]]
        self.assertEqual(vault.decrypt_entries(text, "пароль-тест"), expected)


class Merge(unittest.TestCase):
    def test_no_duplicates(self):
        again = Entry("totp", "EXAMPLE", "ALICE@example.com", ENTRIES[0].secret, "SHA1", 6, 30, 0)
        merged, added, skipped = vault.merge_entries(ENTRIES[:2], [again, ENTRIES[2], ENTRIES[2]])
        self.assertEqual((len(merged), added, skipped), (3, 1, 2))

    def test_same_account_different_secret_is_kept(self):
        other = Entry("totp", "Example", "alice@example.com", b"\x55" * 20, "SHA1", 6, 30, 0)
        merged, added, skipped = vault.merge_entries(ENTRIES[:1], [other])
        self.assertEqual((added, skipped), (1, 0))

    def test_otpauth_list_roundtrip(self):
        from skhoron2fa.otpauth import parse
        lines = vault.to_otpauth_list(ENTRIES).strip().split("\n")
        self.assertEqual([parse(l) for l in lines], ENTRIES)


if __name__ == "__main__":
    unittest.main()