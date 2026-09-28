"""Domain normalizasyonu — ana repodaki Kotlin `DomainNormalizer`,
`PublicSuffixBoundary` ve `DomainMatcher.canonicalListEntry` ile birebir.

Java `IDN.toASCII` IDNA2003 uygular. Burada da Python'un yerleşik IDNA2003
codec'i (`str.encode("idna")`) kullanılır; üçüncü parti `idna` paketi
(IDNA2008) KULLANILMAZ. STD3 kuralları, sondaki kanonik ASCII kontrolüyle
sağlanır (yalnız a-z 0-9 '-', etiket başı/sonu tire yok). Parity
`golden/vectors.json` ile Kotlin tarafında da test edilir.
"""

from __future__ import annotations

MAX_HOST_LENGTH = 253
MAX_LABEL_LENGTH = 63

COMMON_PREFIXES = ("www.", "m.", "mobile.")

# Kotlin: PublicSuffixBoundary.TURKEY_SECOND_LEVEL ile AYNI olmalı.
TURKEY_SECOND_LEVEL = (
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "bel.tr", "k12.tr",
    "av.tr", "dr.tr", "gen.tr", "biz.tr", "info.tr", "web.tr", "tv.tr",
    "pol.tr", "tsk.tr", "mil.tr", "bbs.tr", "name.tr", "tel.tr", "kep.tr",
    "nc.tr", "gov.nc.tr",
)
_MULTI_LABEL_SUFFIXES = frozenset(TURKEY_SECOND_LEVEL)

_LDH = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")


def _is_kotlin_whitespace(c: str) -> bool:
    # Kotlin Char.isWhitespace(): Character.isWhitespace || Character.isSpaceChar.
    # Liste dosyalarında pratikte yalnız ASCII boşluklar görülür; Python isspace()
    # bunları ve Unicode boşluklarını kapsar.
    return c.isspace() or c in "   "


def _strip(raw: str) -> str:
    start, end = 0, len(raw)
    while start < end and _is_kotlin_whitespace(raw[start]):
        start += 1
    while end > start and _is_kotlin_whitespace(raw[end - 1]):
        end -= 1
    while end > start and raw[end - 1] == ".":
        end -= 1
    return raw[start:end]


def is_canonical_ascii(s: str) -> bool:
    if not s or len(s) > MAX_HOST_LENGTH:
        return False
    for label in s.split("."):
        if not label or len(label) > MAX_LABEL_LENGTH:
            return False
        if label[0] == "-" or label[-1] == "-":
            return False
        if any(c not in _LDH for c in label):
            return False
    return True


def normalize(raw: str) -> str | None:
    """Kanonik ASCII host ya da geçersizse None (Kotlin `DomainNormalizer.normalize`)."""
    s = _strip(raw)
    if not s:
        return None
    if is_canonical_ascii(s):
        return s
    lowered = s.lower()
    if lowered.isascii():
        ascii_host = lowered
    else:
        try:
            ascii_host = lowered.encode("idna").decode("ascii").lower()
        except (UnicodeError, ValueError):
            return None
    ascii_host = ascii_host.rstrip(".")
    return ascii_host if is_canonical_ascii(ascii_host) else None


def strip_common_prefix(host: str) -> str | None:
    """Kotlin `DomainNormalizer.stripCommonPrefix`."""
    for prefix in COMMON_PREFIXES:
        if len(host) > len(prefix) and host.startswith(prefix):
            rest = host[len(prefix):]
            return rest if rest.find(".") > 0 else None
    return None


def is_public_suffix(host: str) -> bool:
    """Kotlin `PublicSuffixBoundary.DEFAULT.isPublicSuffix(host, 0)`."""
    if "." not in host:
        return True
    return host in _MULTI_LABEL_SUFFIXES


def canonical_list_entry(raw: str) -> str | None:
    """Liste girdisinin matcher'a yazılacak kanonik hali (Kotlin
    `DomainMatcher.canonicalListEntry`): normalize → ortak önek atma (kalan
    public suffix değilse) → public suffix girdileri atılır."""
    host = normalize(raw)
    if host is None:
        return None
    stripped = strip_common_prefix(host)
    canonical = stripped if stripped is not None and not is_public_suffix(stripped) else host
    if is_public_suffix(canonical):
        return None
    return canonical
