# SPDX-License-Identifier: Apache-2.0
"""Расшифровывает файл, созданный Java (VaultExport.encrypt), эталонным Python-кодом.

Использование: python3 tools/check_java_export.py <java_export.json>
Ожидаемое содержимое берётся из core/test-vectors/export_expected.json.
"""
import json
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "core", "reference-python"))

from cryptography.exceptions import InvalidTag  # noqa: E402

from skhoron2fa import vault  # noqa: E402

PASSWORD = "пароль-тест"

with open(sys.argv[1], encoding="utf-8") as fh:
    text = fh.read()
with open(os.path.join(ROOT, "core", "test-vectors", "export_expected.json"), encoding="utf-8") as fh:
    expected = [vault._entry_from_json(item) for item in json.load(fh)["entries"]]

got = vault.decrypt_entries(text, PASSWORD)
if got != expected:
    sys.exit("ПРОВАЛ: Python прочитал файл Java иначе, чем ожидалось")
try:
    vault.decrypt_entries(text, PASSWORD + "x")
except InvalidTag:
    pass
else:
    sys.exit("ПРОВАЛ: файл Java открылся с неверным паролем")
print("файл Java прочитан Python: записей %d, неверный пароль отклонён" % len(got))