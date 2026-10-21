# SPDX-License-Identifier: Apache-2.0
"""Командная строка: python -m skhoron2fa <команда>."""
import argparse
import getpass
import sys
import time

from . import migration, otpauth, vault
from .otp import hotp, seconds_remaining, totp


def _read_lines(path: str) -> list:
    with open(path, encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="skhoron2fa")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("code", help="показать код для otpauth:// URI")
    p.add_argument("uri")
    p.add_argument("--time", type=int, help="unix-время вместо текущего")

    p = sub.add_parser("export", help="otpauth-список -> зашифрованный файл")
    p.add_argument("source")
    p.add_argument("target")

    p = sub.add_parser("import", help="зашифрованный файл -> otpauth-список (stdout)")
    p.add_argument("source")

    p = sub.add_parser("migrate", help="otpauth-migration:// (Google) -> otpauth-список (stdout)")
    p.add_argument("uri")

    args = parser.parse_args(argv)

    if args.cmd == "code":
        entry = otpauth.parse(args.uri)
        now = args.time if args.time is not None else int(time.time())
        if entry.type == "totp":
            code = totp(entry.secret, now, entry.period, entry.digits, entry.algorithm)
            print("%s (ещё %d с)" % (code, seconds_remaining(now, entry.period)))
        else:
            print(hotp(entry.secret, entry.counter, entry.digits, entry.algorithm))
    elif args.cmd == "export":
        entries = [otpauth.parse(line) for line in _read_lines(args.source)]
        password = getpass.getpass("Пароль экспорта: ")
        if password != getpass.getpass("Повторите пароль: "):
            print("Пароли не совпали", file=sys.stderr)
            return 1
        with open(args.target, "w", encoding="utf-8") as fh:
            fh.write(vault.encrypt_entries(entries, password))
        print("Записей: %d" % len(entries))
    elif args.cmd == "import":
        with open(args.source, encoding="utf-8") as fh:
            entries = vault.decrypt_entries(fh.read(), getpass.getpass("Пароль: "))
        sys.stdout.write(vault.to_otpauth_list(entries))
    elif args.cmd == "migrate":
        sys.stdout.write(vault.to_otpauth_list(migration.decode_uri(args.uri)))
    return 0


if __name__ == "__main__":
    sys.exit(main())