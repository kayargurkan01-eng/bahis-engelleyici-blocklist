"""golden/vectors.json üreticisi.

Beklenen değerler Python uygulamasından üretilir; aynı dosyanın birebir
kopyası ana repoda (core/data/src/test/resources/golden/vectors.json)
Kotlin `DomainNormalizer` / `DomainMatcher.canonicalListEntry` / `Hash64`
testlerine girer. Böylece iki taraf aynı dosyaya karşı doğrulanır.

  python -m golden.generate          # dosyayı yazar
  python -m golden.generate --check  # dosya güncel mi (CI/test)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from src.hash64 import hash_signed, hash_unsigned
from src.normalize import canonical_list_entry, normalize

PATH = Path(__file__).with_name("vectors.json")

NORMALIZE_INPUTS = [
    # ascii / büyük harf / boşluk / sondaki nokta
    "ornek.com", "OrnekBahis.COM", "BITCOIN.COM", "  site.com \t", "\nsite.com\n",
    "site.com.", "site.com...",
    # IDN
    "bücher.com", "BÜCHER.COM", "şans.com.tr", "ŞANS.COM.TR", "İstanbul.com",
    "ığüşöç.test", "ＢＵＣＨＥＲ.com", "ß.com", "例え.テスト",
    "bad。com", "a​b.com",
    # zaten punycode
    "xn--bcher-kva.com", "ab--cd.com",
    # geçersiz
    "gecersiz_domain.com", "site.com:443", "site.com/yol", "https://site.com", "site com",
    "-bad-.com", "bad-.com", "a..b.com", ".site.com", "", "   ", "...", "xn--.com",
    "ü" * 70 + ".com", "a" * 64 + ".com", ("a" * 60 + ".") * 5 + "com", "bad\u0000.com",
    # önekler (normalize öneki ATMAZ)
    "www.site.com", "m.site.com", "mobile.site.com",
    # diğer
    "1.2.3.4", "localhost",
]

LIST_INPUTS = [
    "www.site.com", "m.site.com", "mobile.site.com", "WWW.Site.COM.", "mail.site.com",
    "wwwsite.com", "www.site.com.tr", "www.com.tr", "m.gov.tr", "www.com",
    "com", "com.tr", "tr", "gov.nc.tr", "a.gov.nc.tr",
    "ornek.tr", "www.ornek.tr", "a.b.site.com.tr", "bücher.com", "www.bücher.com",
    "gecersiz_domain.com", "", "localhost",
]

HASH_INPUTS = [
    "", "a", "abc", "site.com", "b.site.com", "xn--bcher-kva.com",
    "Nobody inspects the spammish repetition",
    "0123456789abcdef0123456789abcdef0123",
    "cok-uzun-bir-alt-alan-adi.ornek-engelli-bir-site.test",
]


def build() -> dict:
    hashes = []
    for s in HASH_INPUTS:
        u = hash_unsigned(s)
        hashes.append({"input": s, "unsigned": f"0x{u:016x}", "signed": hash_signed(s)})
    if not any(h["signed"] < 0 for h in hashes):
        raise SystemExit("En az bir negatif (high-bit) hash vektörü gerekli")
    return {
        "formatVersion": 1,
        "description": "Python pipeline ile Kotlin motoru arasindaki parity vektorleri. Elle degistirmeyin; golden/generate.py uretir.",
        "normalize": [{"input": s, "expected": normalize(s)} for s in NORMALIZE_INPUTS],
        "listCanonical": [{"input": s, "expected": canonical_list_entry(s)} for s in LIST_INPUTS],
        "hash": hashes,
    }


def render() -> bytes:
    return (json.dumps(build(), indent=2, ensure_ascii=True) + "\n").encode("ascii")


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        if PATH.read_bytes() != render():
            raise SystemExit("golden/vectors.json güncel değil: python -m golden.generate")
        print("golden/vectors.json güncel.")
    else:
        PATH.write_bytes(render())
        print(f"Yazıldı: {PATH}")
