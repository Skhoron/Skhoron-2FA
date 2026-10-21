# SPDX-License-Identifier: Apache-2.0
import os
import unittest

from skhoron2fa.otp import b32decode, b32encode, hotp, seconds_remaining, totp

VECTORS = os.path.join(os.path.dirname(__file__), "..", "..", "test-vectors")

SECRETS = {
    "SHA1": b"12345678901234567890",
    "SHA256": b"12345678901234567890123456789012",
    "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234",
}


class Rfc4226(unittest.TestCase):
    def test_appendix_d(self):
        expected = ["755224", "287082", "359152", "969429", "338314",
                    "254676", "287922", "162583", "399871", "520489"]
        for counter, code in enumerate(expected):
            self.assertEqual(hotp(SECRETS["SHA1"], counter), code)


class Rfc6238(unittest.TestCase):
    # Приложение B RFC 6238: время -> (SHA1, SHA256, SHA512), 8 цифр
    TABLE = {
        59: ("94287082", "46119246", "90693936"),
        1111111109: ("07081804", "68084774", "25091201"),
        1111111111: ("14050471", "67062674", "99943326"),
        1234567890: ("89005924", "91819424", "93441116"),
        2000000000: ("69279037", "90698825", "38618901"),
        20000000000: ("65353130", "77737706", "47863826"),
    }

    def test_appendix_b(self):
        for t, codes in self.TABLE.items():
            for algo, code in zip(("SHA1", "SHA256", "SHA512"), codes):
                self.assertEqual(totp(SECRETS[algo], t, 30, 8, algo), code, (t, algo))


class CrossVectors(unittest.TestCase):
    def test_independent_vectors(self):
        count = 0
        with open(os.path.join(VECTORS, "cross.tsv"), encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("#") or not line.strip():
                    continue
                b32, algo, digits, period, t, expected = line.rstrip("\n").split("\t")
                got = totp(b32decode(b32), int(t), int(period), int(digits), algo)
                self.assertEqual(got, expected, line)
                count += 1
        self.assertEqual(count, 300)


class Helpers(unittest.TestCase):
    def test_base32_tolerant(self):
        self.assertEqual(b32decode("jbsw y3dp-ehpk 3pxp"), bytes.fromhex("48656c6c6f21deadbeef"))
        self.assertEqual(b32decode("JBSWY3DPEHPK3PXP===="), bytes.fromhex("48656c6c6f21deadbeef"))

    def test_base32_roundtrip(self):
        for n in range(1, 40):
            data = bytes(range(n))
            self.assertEqual(b32decode(b32encode(data)), data)

    def test_base32_rejects_garbage(self):
        for bad in ("", "!!!", "A", "1890"):
            with self.assertRaises(ValueError):
                b32decode(bad)

    def test_parameter_validation(self):
        with self.assertRaises(ValueError):
            hotp(b"k", 0, digits=5)
        with self.assertRaises(ValueError):
            hotp(b"k", 0, algorithm="MD5")
        with self.assertRaises(ValueError):
            hotp(b"", 0)
        with self.assertRaises(ValueError):
            totp(b"k", 0, period=0)

    def test_seconds_remaining(self):
        self.assertEqual(seconds_remaining(0), 30)
        self.assertEqual(seconds_remaining(29), 1)
        self.assertEqual(seconds_remaining(30), 30)

    def test_window_boundary(self):
        s = SECRETS["SHA1"]
        self.assertEqual(totp(s, 59), totp(s, 30))
        self.assertNotEqual(totp(s, 59), totp(s, 60))


if __name__ == "__main__":
    unittest.main()