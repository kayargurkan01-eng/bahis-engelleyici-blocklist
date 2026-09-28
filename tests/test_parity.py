"""Normalizasyon, liste kanonikleştirme ve xxHash64 — Kotlin parity."""

import json
import struct
from pathlib import Path

import pytest

from golden.generate import render
from src.hash64 import build_binary, decode, encode_sorted, hash_signed, hash_unsigned, to_signed
from src.normalize import canonical_list_entry, normalize, strip_common_prefix

GOLDEN = Path(__file__).resolve().parent.parent / "golden" / "vectors.json"


def test_golden_file_is_current():
    # golden/vectors.json Python uygulamasıyla güncel; Kotlin aynı dosyayı test eder.
    assert GOLDEN.read_bytes() == render()


def test_golden_vectors_normalize():
    data = json.loads(GOLDEN.read_text())
    for case in data["normalize"]:
        assert normalize(case["input"]) == case["expected"], case["input"]
    for case in data["listCanonical"]:
        assert canonical_list_entry(case["input"]) == case["expected"], case["input"]


@pytest.mark.parametrize("raw,expected", [
    ("  OrnekBahis.COM \t", "ornekbahis.com"),
    ("site.com...", "site.com"),
    ("bücher.com", "xn--bcher-kva.com"),
    ("ŞANS.COM.TR", "xn--ans-rza.com.tr"),
    ("xn--bcher-kva.com", "xn--bcher-kva.com"),
    ("gecersiz_domain.com", None),
    ("site.com:443", None),
    ("site.com/yol", None),
    ("a..b.com", None),
    ("-x-.com", None),
    ("ü" * 70 + ".com", None),
    ("", None),
])
def test_normalize(raw, expected):
    assert normalize(raw) == expected


def test_prefixes():
    assert strip_common_prefix("www.site.com") == "site.com"
    assert strip_common_prefix("m.site.com") == "site.com"
    assert strip_common_prefix("mobile.site.com") == "site.com"
    assert strip_common_prefix("www.com") is None
    assert strip_common_prefix("mail.site.com") is None
    assert canonical_list_entry("www.com.tr") == "www.com.tr"
    assert canonical_list_entry("www.ornek.tr") == "ornek.tr"
    assert canonical_list_entry("com.tr") is None


def test_xxhash_reference_vectors():
    assert hash_unsigned("") == 0xEF46DB3751D8E999
    assert hash_unsigned("a") == 0xD24EC4F1A98C6E5B
    assert hash_unsigned("abc") == 0x44BC2CF5AD770999
    # M2 Kotlin Hash64Test ile aynı değerler.
    assert hash_signed("site.com") == to_signed(0xE8F2B2D514EBCB08)
    assert hash_signed("site.com") < 0  # high-bit set


def test_hash_rejects_non_ascii():
    with pytest.raises(UnicodeEncodeError):
        hash_unsigned("bücher.com")


def test_unsigned_to_signed():
    assert to_signed(0) == 0
    assert to_signed((1 << 63) - 1) == (1 << 63) - 1
    assert to_signed(1 << 63) == -(1 << 63)
    assert to_signed((1 << 64) - 1) == -1
    with pytest.raises(ValueError):
        to_signed(1 << 64)
    with pytest.raises(ValueError):
        to_signed(-1)


def test_signed_ordering_and_little_endian():
    data, count = build_binary({"site.com", "abc.test", "b.site.com"})
    values = decode(data)
    assert count == 3
    assert values == sorted(values)  # signed artan
    assert len(set(values)) == 3
    # İlk kayıt LE int64 olarak okunmalı.
    assert struct.unpack("<q", data[:8])[0] == values[0]
    # Unsigned sırayla signed sıra farklıdır: negatif değerler başta.
    assert values[0] < 0


def test_encode_rejects_unsorted_or_duplicate():
    with pytest.raises(ValueError):
        encode_sorted([1, -1])
    with pytest.raises(ValueError):
        encode_sorted([5, 5])
    assert encode_sorted([]) == b""
    assert encode_sorted([-1, 1]) == b"\xff" * 8 + b"\x01" + b"\x00" * 7


def test_binary_roundtrip():
    hashes = sorted({hash_signed(h) for h in ["a.test", "b.test", "c.test", "site.com"]})
    assert decode(encode_sorted(hashes)) == hashes
    with pytest.raises(ValueError):
        decode(b"\x00" * 12)
