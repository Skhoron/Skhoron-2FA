# SPDX-License-Identifier: Apache-2.0
"""Статическая проверка того, что нельзя собрать без Android SDK.

Проверяет: манифест (нет INTERNET, allowBackup=false), баланс скобок в .kt,
что каждый вызов Java-ядра из Kotlin существует, что в core/jvm/src нет API новее Android 11,
что minSdk не ниже требований используемых вызовов Keystore.
Это не замена компиляции: типы и сигнатуры Kotlin здесь не проверяются.
"""
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parent.parent
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
errors = []


def fail(message):
    errors.append(message)
    print("ПРОВАЛ:", message)


def ok(message):
    print("ок:", message)


# 1. манифест
manifest = ET.parse(ROOT / "android/app/src/main/AndroidManifest.xml").getroot()
permissions = [p.get(ANDROID_NS + "name") for p in manifest.findall("uses-permission")]
if "android.permission.INTERNET" in permissions:
    fail("в манифесте есть INTERNET")
else:
    ok("в манифесте нет INTERNET (разрешения: %s)" % ", ".join(permissions))
app = manifest.find("application")
if app.get(ANDROID_NS + "allowBackup") != "false":
    fail("allowBackup не false")
else:
    ok("allowBackup=false")
activities = {a.get(ANDROID_NS + "name"): a.get(ANDROID_NS + "exported") for a in app.findall("activity")}
if activities.get(".MainActivity") != "true":
    fail("MainActivity не объявлена как exported=true (нужно для LAUNCHER)")
else:
    ok("MainActivity объявлена")

# 2. баланс скобок в Kotlin: посимвольный сканер (строки, шаблоны ${...}, комментарии)
PAIRS = {")": "(", "]": "[", "}": "{"}


def brackets_balanced(text):
    stack = []          # элементы: "(", "[", "{", "$" (шаблон ${...} внутри строки), "str"
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        top = stack[-1] if stack else None
        if top == "str":
            if c == "\\":
                i += 2
                continue
            if c == '"':
                stack.pop()
            elif c == "$" and text.startswith("${", i):
                stack.append("$")
                i += 2
                continue
        else:
            if text.startswith("//", i):
                i = text.find("\n", i)
                if i < 0:
                    break
                continue
            if text.startswith("/*", i):
                i = text.find("*/", i)
                if i < 0:
                    return False
                i += 2
                continue
            if c == '"':
                stack.append("str")
            elif c in "([{":
                stack.append(c)
            elif c in ")]}":
                if c == "}" and top == "$":
                    stack.pop()
                elif top == PAIRS[c]:
                    stack.pop()
                else:
                    return False
        i += 1
    return not stack


kotlin_files = sorted((ROOT / "android").rglob("*.kt"))
for path in kotlin_files:
    if brackets_balanced(path.read_text(encoding="utf-8")):
        ok("%s: скобки и строки сбалансированы" % path.name)
    else:
        fail("%s: несбалансированные скобки или незакрытая строка" % path.name)

# 3. обращения Kotlin -> Java-ядро
core = ROOT / "core/jvm/src/org/skhoron/twofa/core"
algorithm_src = (core / "Algorithm.java").read_text(encoding="utf-8")
totp_src = (core / "Totp.java").read_text(encoding="utf-8")
uri_src = (core / "OtpAuthUri.java").read_text(encoding="utf-8")
vault_src = (core / "VaultExport.java").read_text(encoding="utf-8")
entry_src = (core / "OtpEntry.java").read_text(encoding="utf-8")
known = {
    "Algorithm": set(re.findall(r"^\s+([A-Z0-9]+)\(", algorithm_src, flags=re.M))
    | {"jcaName", "parse", "name", "valueOf", "values"},
    "Totp": set(re.findall(r"public (?:static )?[\w.<>\[\]]+ (\w+)\(", totp_src)) | {"HmacFunction"},
    "OtpAuthUri": set(re.findall(r"public (?:static )?(?:final )?[\w.<>\[\]]+ (\w+)[;(]", uri_src)),
}
known["VaultExport"] = (set(re.findall(r"public static [^=;(]*?\b(\w+)\(", vault_src))
                        | set(re.findall(r"public static final class (\w+)", vault_src)))
known["OtpEntry"] = set(re.findall(r"public static [^=;(]*?\b(\w+)\(", entry_src))
all_kotlin = "\n".join(p.read_text(encoding="utf-8") for p in kotlin_files)
for owner, members in known.items():
    for member in sorted(set(re.findall(r"\b%s\.(\w+)" % owner, all_kotlin))):
        if member not in members:
            fail("Kotlin использует %s.%s, в Java-ядре такого нет" % (owner, member))
        else:
            ok("%s.%s есть в ядре" % (owner, member))
parsed_fields = set(re.findall(r"\bparsed\.(\w+)", all_kotlin))
for field in sorted(parsed_fields):
    if field not in known["OtpAuthUri"]:
        fail("Kotlin читает parsed.%s, в OtpAuthUri такого поля нет" % field)
ok("поля OtpAuthUri, используемые в MainActivity: %s" % ", ".join(sorted(parsed_fields)))

# 4. API, недоступные на Android 11 (minSdk 30), в общем ядре
banned = [r"\.strip\(", r"\.isBlank\(", r"\bList\.of\(", r"\bMap\.of\(", r"\bSet\.of\(",
          r"HexFormat", r"\.toList\(\)", r"\.repeat\(", r"\.lines\(", r"\bvar\s+\w+\s*="]
for path in sorted(core.glob("*.java")):
    source = path.read_text(encoding="utf-8")
    hits = [pattern for pattern in banned if re.search(pattern, source)]
    if hits:
        fail("%s использует API новее Android 11: %s" % (path.name, ", ".join(hits)))
    else:
        ok("%s: нет API новее Android 11" % path.name)

# 5. minSdk против используемых вызовов (setUserAuthenticationParameters: API 30)
gradle = (ROOT / "android/app/build.gradle.kts").read_text(encoding="utf-8")
min_sdk = int(re.search(r"minSdk\s*=\s*(\d+)", gradle).group(1))
if "setUserAuthenticationParameters" in all_kotlin and min_sdk < 30:
    fail("setUserAuthenticationParameters требует API 30, а minSdk=%d" % min_sdk)
else:
    ok("minSdk=%d согласован с setUserAuthenticationParameters (API 30)" % min_sdk)

# 6. EntryStore: запись с проверяемым результатом; ключи-сироты и общий префикс
entry_store = (ROOT / "android/app/src/main/java/org/skhoron/twofa/android/EntryStore.kt").read_text(encoding="utf-8")
if ".apply()" in entry_store or ".commit()" not in entry_store:
    fail("EntryStore должен писать через commit() и проверять результат, а не apply()")
else:
    ok("EntryStore пишет через commit()")
if "KeystoreHmac.ALIAS_PREFIX" not in all_kotlin or "reconcileKeys" not in all_kotlin:
    fail("нет очистки ключей-сирот (reconcileKeys / ALIAS_PREFIX)")
else:
    ok("очистка ключей-сирот подключена")
if "problems > 0" not in all_kotlin:
    fail("нет защиты от записи в повреждённый список")
else:
    ok("при повреждённом списке запись и удаление ключей отключены")

# 7. Гигиена CI: workflow и подпись
workflow_path = ROOT / ".github/workflows/build.yml"
workflow = workflow_path.read_text(encoding="utf-8")
try:
    import yaml
    doc = yaml.safe_load(workflow)
    if doc.get("permissions") != {"contents": "read"}:
        fail("permissions верхнего уровня должны быть ровно contents: read")
    else:
        ok("YAML разбирается, permissions: contents: read")
    if set(doc["jobs"]) != {"core-tests", "apk"}:
        fail("ожидались задания core-tests и apk, есть %s" % sorted(doc["jobs"]))
except ImportError:
    ok("PyYAML не установлен: структура YAML не разбиралась, работают текстовые правила")
if re.search(r"secrets\.|pull_request_target|GITHUB_TOKEN", workflow):
    fail("в workflow есть secrets / pull_request_target / GITHUB_TOKEN")
else:
    ok("в workflow нет secrets, pull_request_target и явного GITHUB_TOKEN")
allowed = ("actions/checkout@", "actions/setup-java@", "actions/upload-artifact@", "gradle/actions/setup-gradle@")
for ref in re.findall(r"uses:\s*(\S+)", workflow):
    if not ref.startswith(allowed):
        fail("действие вне списка разрешённых: %s" % ref)
    else:
        ok("действие разрешено: %s" % ref)
checkouts = workflow.count("actions/checkout@")
if workflow.count("persist-credentials: false") != checkouts:
    fail("у каждого checkout должно быть persist-credentials: false")
else:
    ok("persist-credentials: false у всех checkout (%d)" % checkouts)
if "assembleRelease" not in workflow or "retention-days" not in workflow:
    fail("нет assembleRelease или retention-days")
else:
    ok("собирается release, у артефакта задан срок хранения")
signing_words = re.compile(r"signingConfig|storePassword|keyPassword|\.jks|\.keystore", re.I)
for name, text in (("build.yml", workflow), ("app/build.gradle.kts", gradle)):
    if signing_words.search(text):
        fail("в %s упомянут материал подписи: APK должен собираться неподписанным" % name)
    else:
        ok("%s не содержит настроек подписи" % name)
props = (ROOT / "android/gradle.properties").read_text(encoding="utf-8")
if "android.useAndroidX=true" not in props:
    fail("в gradle.properties нет android.useAndroidX=true")
else:
    ok("android.useAndroidX=true")

# 8. Лицензия: неизменный текст Apache 2.0, NOTICE, SPDX-заголовки, README
import hashlib

APACHE_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
license_bytes = (ROOT / "LICENSE").read_bytes()
if hashlib.sha256(license_bytes).hexdigest() != APACHE_SHA256:
    fail("LICENSE не совпадает с эталонным текстом Apache 2.0")
elif b"END OF TERMS AND CONDITIONS" not in license_bytes:
    fail("в LICENSE нет конца условий")
else:
    ok("LICENSE совпадает с эталонным текстом Apache 2.0")
notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
if "Copyright" not in notice:
    fail("в NOTICE нет строки Copyright")
else:
    ok("NOTICE на месте")
suffixes = {".py", ".java", ".kt", ".kts", ".sh", ".yml"}
missing = [str(p.relative_to(ROOT)) for p in sorted(ROOT.rglob("*"))
           if p.is_file() and p.suffix in suffixes
           and "SPDX-License-Identifier: Apache-2.0" not in "\n".join(p.read_text(encoding="utf-8").split("\n")[:3])]
if missing:
    fail("нет SPDX-заголовка: %s" % ", ".join(missing))
else:
    ok("SPDX-заголовок есть во всех исходниках")
if "Apache License 2.0" not in (ROOT / "README.md").read_text(encoding="utf-8"):
    fail("README не упоминает лицензию")
else:
    ok("README указывает лицензию")

print()
if errors:
    print("Статическая проверка: ошибок %d" % len(errors))
    sys.exit(1)
print("Статическая проверка: ошибок нет")