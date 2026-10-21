#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Полная проверка: tools/verify.sh [папка_проекта]
# Нужны: python3 + cryptography >= 46, JDK 17+ (модуль jdk.compiler).
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT"

echo "== 1. Контрольные суммы =="
if [ -f SHA256SUMS ]; then
    sha256sum -c --quiet SHA256SUMS && echo "все файлы совпадают с SHA256SUMS"
else
    echo "SHA256SUMS нет, пропуск"
fi

echo "== 2. Векторы воспроизводятся генератором =="
python3 tools/gen_test_vectors.py >/dev/null
if [ -f SHA256SUMS ]; then
    grep "core/test-vectors/" SHA256SUMS | sha256sum -c --quiet && echo "перегенерация дала те же файлы"
fi

echo "== 3. Python-ядро =="
(cd core/reference-python && python3 -m unittest discover -s tests 2>&1 | tail -4)

echo "== 4. Java-ядро =="
JAVA_OUT="$(mktemp -d)"
trap 'rm -rf "$JAVA_OUT"' EXIT
SKHORON_JAVA_OUT="$JAVA_OUT" java tools/run-jvm-tests.java

echo "== 4b. Файл, созданный Java, читается Python =="
python3 tools/check_java_export.py "$JAVA_OUT/java_export.json"

echo "== 5. CLI (RFC 6238, t=59, SHA-1, 8 цифр) =="
OUT="$(cd core/reference-python && python3 -m skhoron2fa code 'otpauth://totp/RFC:test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8' --time 59)"
echo "$OUT"
[ "$OUT" = "94287082 (ещё 1 с)" ]

echo "== 6. Android: статическая проверка (без компиляции) =="
python3 tools/static_check_android.py | tail -3

echo
echo "ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ"