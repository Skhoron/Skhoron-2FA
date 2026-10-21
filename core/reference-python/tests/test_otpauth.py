# SPDX-License-Identifier: Apache-2.0
import os
import unittest

from skhoron2fa.otpauth import Entry, build, parse

VECTORS = os.path.join(os.path.dirname(__file__), "..", "..", "test-vectors")


def rows(name):
    with open(os.path.join(VECTORS, name), encoding="utf-8") as fh:
        return [l.rstrip("\n") for l in fh if l.strip() and not l.startswith("#")]


class UriVectors(unittest.TestCase):
    def test_valid(self):
        for line in rows("uri.tsv"):
            uri, issuer, account, secret_hex, algo, digits, period, kind, counter = line.split("\t")
            e = parse(uri)
            self.assertEqual((e.issuer, e.account, e.secret.hex(), e.algorithm, e.digits,
                              e.period, e.type, e.counter),
                             (issuer, account, secret_hex, algo, int(digits), int(period), kind, int(counter)),
                             uri)

    def test_invalid(self):
        for uri in rows("uri_invalid.txt"):
            with self.assertRaises(ValueError, msg=uri):
                parse(uri)


class RoundTrip(unittest.TestCase):
    def test_build_parse(self):
        samples = [
            Entry("totp", "ACME Co", "john.doe@email.com", bytes(range(1, 21)), "SHA256", 8, 60, 0),
            Entry("totp", "", "solo", b"\x01" * 10, "SHA1", 6, 30, 0),
            Entry("hotp", "Svc", "bob", b"\xfe" * 20, "SHA512", 7, 30, 12),
            Entry("totp", "Пример: тест", "иван иванов", b"\x07" * 16, "SHA1", 6, 30, 0),
        ]
        for e in samples:
            self.assertEqual(parse(build(e)), e)


if __name__ == "__main__":
    unittest.main()