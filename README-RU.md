Skhoron-2FA

Полностью локальный TOTP-аутентификатор для Android. Нет сервера, нет аккаунта, в манифесте нет
разрешения INTERNET. Секрет после добавления остаётся только в Android Keystore как HMAC-ключ.

Лицензия: Apache License 2.0 (LICENSE, NOTICE, подробности в docs/LICENSING.md).

Состав

Папка	Что внутри	Как проверено

core/reference-python	HOTP/TOTP, разбор otpauth://, импорт Google Authenticator, зашифрованный экспорт, CLI	34 теста, запускаются
core/jvm	то же ядро на Java без зависимостей (его подключает Android-код)	524 проверки, запускаются
core/test-vectors	общие векторы для обеих реализаций (генерирует tools/gen_test_vectors.py)	используются обоими наборами
android	Keystore, BiometricPrompt, FLAG_SECURE, минимальный экран	не собирался и не запускался (нет Android SDK и Kotlin); сверен с документацией Android; статическая проверка в tools/static_check_android.py
.github/workflows	сборка неподписанного APK и проверки ядра	не запускался; описание и риски в docs/BUILD.md
docs	устройство, формат экспорта, сравнение с другими приложениями, сборка APK	


Экран Android сейчас умеет: добавить запись по otpauth://totp/... (текстом), показывать коды с
обратным отсчётом после входа по биометрии или PIN, удалить запись долгим нажатием, предложить зашифрованную
резервную копию сразу после добавления и восстановить записи из такого файла.
Не умеет: сканировать QR, HOTP, импорт Google, поиск, режим EVERY_USE в интерфейсе.

Запуск проверок

cd core/reference-python && python3 -m unittest discover -s tests      # нужен пакет cryptography >= 46  
java tools/run-jvm-tests.java                                          # нужен JDK 17+; запускать из корня проекта

Сборка APK: docs/BUILD.md (GitHub Actions выдаёт неподписанный APK, подпись ставится у вас локально).

Код для одной записи без установки:

cd core/reference-python  
python3 -m skhoron2fa code "otpauth://totp/RFC:test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8" --time 59  
# 94287082 (ещё 1 с)