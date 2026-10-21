# SPDX-License-Identifier: Apache-2.0
import os
import subprocess
import sys
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
RFC_URI = "otpauth://totp/RFC:test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8"


def run(*args):
    return subprocess.run([sys.executable, "-m", "skhoron2fa", *args], cwd=ROOT,
                          capture_output=True, text=True)


class Cli(unittest.TestCase):
    def test_code_rfc_vector(self):
        r = run("code", RFC_URI, "--time", "59")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "94287082 (ещё 1 с)")

    def test_hotp(self):
        uri = "otpauth://hotp/RFC:test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=1"
        self.assertEqual(run("code", uri).stdout.strip(), "287082")

    def test_bad_uri_fails(self):
        r = run("code", "otpauth://totp/x")
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()