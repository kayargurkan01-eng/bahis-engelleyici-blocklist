"""Kaynak ve çıktı dosyası ayrıştırıcıları.

- plain: satır başına domain (ShadowWhisperer, tr-manuel, allowlist)
- hosts: `0.0.0.0 domain` biçimi (StevenBlack gambling-only)
- patterns: `kök<TAB>min<TAB>max` — Kotlin `NumberedBrandRule` kurallarıyla aynı
- packages: birebir Android paket adı
"""

from __future__ import annotations

import re

# Kotlin NumberedBrandRule ile AYNI olmalı.
MIN_ROOT_LENGTH = 4
MAX_DIGITS = 6
GENERIC_ROOTS = frozenset({
    "bets", "casino", "casinos", "bahis", "slot", "slots", "poker",
    "bingo", "iddaa", "kumar", "rulet", "canlibahis", "sportsbet",
})
_ROOT_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")

_PACKAGE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+")
_MAX_PACKAGE_LENGTH = 255

_HOSTS_IGNORED = frozenset({
    "localhost", "localhost.localdomain", "local", "broadcasthost",
    "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
    "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0",
})


class ParseError(ValueError):
    pass


def decode_text(data: bytes, name: str) -> str:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ParseError(f"{name}: geçerli UTF-8 değil") from e
    if text.startswith("﻿"):
        text = text[1:]
    return text


def parse_plain(text: str) -> list[str]:
    """Yorum (`#`) ve boş satırları atar; her satırın ilk alanını döner."""
    out: list[str] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        out.append(line.split()[0])
    return out


def parse_hosts(text: str) -> list[str]:
    """`IP domain [domain...]` satırları; localhost benzeri girdiler atılır."""
    out: list[str] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2 or parts[0] not in ("0.0.0.0", "127.0.0.1", "::", "::1"):
            continue
        for host in parts[1:]:
            if host.lower() not in _HOSTS_IGNORED:
                out.append(host)
    return out


def _data_lines(text: str, name: str):
    if "\r" in text:
        raise ParseError(f"{name}: yalnızca LF satır sonu kullanılmalı")
    for no, line in enumerate(text.split("\n"), start=1):
        if not line or line.startswith("#"):
            continue
        if line != line.strip():
            raise ParseError(f"{name} satır {no}: baş/son boşluk")
        yield no, line


def _strict_int(s: str) -> int | None:
    if not s or len(s) > 2 or not all("0" <= c <= "9" for c in s):
        return None
    if len(s) > 1 and s[0] == "0":
        return None
    return int(s)


def validate_rule(root: str, min_digits: int, max_digits: int) -> None:
    """Kotlin NumberedBrandRule init bloğunun aynısı."""
    if len(root) < MIN_ROOT_LENGTH:
        raise ParseError(f"Kök çok kısa: '{root}'")
    if any(c not in _ROOT_CHARS for c in root):
        raise ParseError(f"Kök kanonik değil: '{root}'")
    if not ("a" <= root[-1] <= "z"):
        raise ParseError(f"Kök harfle bitmeli: '{root}'")
    if root in GENERIC_ROOTS:
        raise ParseError(f"Genel kelime kök olamaz: '{root}'")
    if min_digits < 1:
        raise ParseError("minDigits >= 1 olmalı")
    if not (min_digits <= max_digits <= MAX_DIGITS):
        raise ParseError(f"Geçersiz rakam aralığı: {min_digits}..{max_digits}")


def parse_patterns(text: str, name: str = "patterns.txt") -> list[tuple[str, int, int]]:
    rules: set[tuple[str, int, int]] = set()
    for no, line in _data_lines(text, name):
        parts = line.split("\t")
        if len(parts) != 3:
            raise ParseError(f"{name} satır {no}: 3 sekmeyle ayrılmış alan bekleniyordu")
        mn, mx = _strict_int(parts[1]), _strict_int(parts[2])
        if mn is None or mx is None:
            raise ParseError(f"{name} satır {no}: rakam alanı geçersiz")
        try:
            validate_rule(parts[0], mn, mx)
        except ParseError as e:
            raise ParseError(f"{name} satır {no}: {e}") from e
        rules.add((parts[0], mn, mx))
    return sorted(rules)


def canonical_patterns(rules: list[tuple[str, int, int]]) -> bytes:
    return "".join(f"{r}\t{a}\t{b}\n" for r, a, b in sorted(set(rules))).encode("utf-8")


def parse_packages(text: str, name: str = "packages.txt") -> list[str]:
    pkgs: set[str] = set()
    for no, line in _data_lines(text, name):
        if len(line) > _MAX_PACKAGE_LENGTH or not _PACKAGE_NAME.fullmatch(line):
            raise ParseError(f"{name} satır {no}: geçersiz paket adı")
        pkgs.add(line)
    return sorted(pkgs)


def canonical_packages(pkgs: list[str]) -> bytes:
    return "".join(f"{p}\n" for p in sorted(set(pkgs))).encode("utf-8")
