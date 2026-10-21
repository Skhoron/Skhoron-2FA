#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Подпись APK у себя на компьютере. Ключ подписи никогда не попадает на GitHub.
# Использование: tools/sign-apk.sh app-release-unsigned.apk skhoron2fa.jks Skhoron-2FA.apk
# Нужен ANDROID_HOME с установленными build-tools (zipalign, apksigner).
set -euo pipefail
IN="${1:?неподписанный APK}"; KS="${2:?файл ключа .jks}"; OUT="${3:?имя подписанного APK}"
: "${ANDROID_HOME:?задайте ANDROID_HOME}"
BT="$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)"
ALIGNED="$(mktemp --suffix=.apk)"
trap 'rm -f "$ALIGNED"' EXIT
"$BT/zipalign" -f -p 4 "$IN" "$ALIGNED"
"$BT/apksigner" sign --ks "$KS" --out "$OUT" "$ALIGNED"      # пароль запросит сам apksigner
"$BT/apksigner" verify --verbose --print-certs "$OUT"
sha256sum "$OUT"