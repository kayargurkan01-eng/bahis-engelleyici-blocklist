import pytest

from src.parsers import (
    ParseError,
    canonical_packages,
    canonical_patterns,
    decode_text,
    parse_hosts,
    parse_packages,
    parse_patterns,
    parse_plain,
)


def test_plain_parser():
    text = "# yorum\n\nornek.test\n  ikinci.test  # satır sonu yorumu\nucuncu.test extra\n"
    assert parse_plain(text) == ["ornek.test", "ikinci.test", "ucuncu.test"]


def test_hosts_parser():
    text = (
        "# yorum\n127.0.0.1 localhost\n0.0.0.0 0.0.0.0\n::1 ip6-localhost\n"
        "0.0.0.0 a.test b.test # yorum\n127.0.0.1 c.test\n1.2.3.4 yanlis-ip.test\nbozuk-satir\n"
    )
    assert parse_hosts(text) == ["a.test", "b.test", "c.test"]


def test_patterns_canonical_sorted_dedup():
    rules = parse_patterns("# yorum\nzetamarka\t1\t4\n\nalfamarka\t2\t3\nzetamarka\t1\t4\n")
    assert rules == [("alfamarka", 2, 3), ("zetamarka", 1, 4)]
    assert canonical_patterns(rules) == b"alfamarka\t2\t3\nzetamarka\t1\t4\n"
    assert canonical_patterns([]) == b""


@pytest.mark.parametrize("line", [
    "bet\t1\t4", "casino\t1\t4", "bahis\t1\t4", "slots\t1\t4",   # genel/kısa kök
    "Ornekmarka\t1\t4", "ornekmarka1\t1\t4",                     # kanonik değil / rakamla bitiyor
    "ornekmarka\t0\t4", "ornekmarka\t4\t2", "ornekmarka\t1\t7",  # aralık
    "ornekmarka 1 4", "ornekmarka\t1", "ornekmarka\t1\t4\tx",    # biçim
    "ornekmarka\t01\t4", "ornekmarka\t+1\t4", "^ornek.*$\t1\t4", # regex / sayı
    " ornekmarka\t1\t4",
])
def test_invalid_patterns_rejected(line):
    with pytest.raises(ParseError):
        parse_patterns(line + "\n")


def test_patterns_crlf_rejected():
    with pytest.raises(ParseError):
        parse_patterns("ornekmarka\t1\t4\r\n")


def test_packages_canonical():
    pkgs = parse_packages("# yorum\ncom.z.app\n\ncom.a.app\ncom.z.app\n")
    assert pkgs == ["com.a.app", "com.z.app"]
    assert canonical_packages(pkgs) == b"com.a.app\ncom.z.app\n"
    assert canonical_packages([]) == b""


@pytest.mark.parametrize("line", ["tekparca", "com..x", "com.ornek.*", "com.1a.b", "com.a b", " com.a.b"])
def test_invalid_packages_rejected(line):
    with pytest.raises(ParseError):
        parse_packages(line + "\n")


def test_decode_text():
    assert decode_text("﻿a.test\n".encode(), "x") == "a.test\n"
    with pytest.raises(ParseError):
        decode_text(b"\xc3\x28", "x")
