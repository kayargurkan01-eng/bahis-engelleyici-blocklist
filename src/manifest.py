"""manifest.json v1 — ana repodaki Kotlin `BlocklistManifestParser` şemasıyla birebir.

Parser bilinmeyen alanı reddettiği için bu şemaya alan EKLENMEZ; yeni alan
gerekirse formatVersion artırılır. Çıktı deterministiktir: sabit anahtar
sırası, 2 boşluk girinti, ASCII (\\u kaçışlı), LF, tek sonda satır sonu.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

FORMAT_VERSION = 1
HASH_ALGORITHM = "xxhash64-seed0"
BYTE_ORDER = "little-endian"
SORT_ORDER = "signed-int64-ascending"

FILES = {
    "blocklist": "blocklist.bin",
    "allowlist": "allowlist.bin",
    "patterns": "patterns.txt",
    "packages": "packages.txt",
}
MANIFEST_FILE = "manifest.json"

_TOP_KEYS = [
    "formatVersion", "version", "releaseTag", "generatedAt", "pipelineVersion",
    "hashAlgorithm", "byteOrder", "sortOrder", "artifacts", "sources",
]
_SHA = re.compile(r"[0-9a-f]{64}")
_TAG = re.compile(r"[A-Za-z0-9._-]{1,64}")


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def version_of(generated_at: datetime) -> int:
    return int(generated_at.astimezone(timezone.utc).strftime("%Y%m%d%H%M"))


def build_manifest(
    *,
    generated_at: datetime,
    pipeline_version: str,
    artifacts: dict,
    sources: list[dict],
) -> dict:
    """artifacts: {"blocklist": {"count", "bytes", "sha256"}, ..., "patterns": {"count", "sha256"}, ...}"""
    version = version_of(generated_at)

    def binary(name):
        a = artifacts[name]
        return {"file": FILES[name], "count": a["count"], "bytes": a["bytes"], "sha256": a["sha256"]}

    def text(name):
        a = artifacts[name]
        return {"file": FILES[name], "count": a["count"], "sha256": a["sha256"]}

    manifest = {
        "formatVersion": FORMAT_VERSION,
        "version": version,
        "releaseTag": f"list-{version}",
        "generatedAt": iso(generated_at),
        "pipelineVersion": pipeline_version,
        "hashAlgorithm": HASH_ALGORITHM,
        "byteOrder": BYTE_ORDER,
        "sortOrder": SORT_ORDER,
        "artifacts": {
            "blocklist": binary("blocklist"),
            "allowlist": binary("allowlist"),
            "patterns": text("patterns"),
            "packages": text("packages"),
        },
        "sources": [
            {
                "name": s["name"],
                "url": s["url"],
                "license": s["license"],
                "fetchedAt": s["fetchedAt"],
                "commit": s.get("commit"),
                "etag": s.get("etag"),
                "lastModified": s.get("lastModified"),
            }
            for s in sources
        ],
    }
    validate(manifest)
    return manifest


def dumps(manifest: dict) -> bytes:
    return (json.dumps(manifest, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def validate(m: dict) -> None:
    """Kotlin parser'ın reddedeceği bir manifest üretilmesin diye aynı kurallar."""
    if list(m.keys()) != _TOP_KEYS:
        raise ValueError("Manifest üst anahtarları/sırası şemaya uymuyor")
    if m["formatVersion"] != FORMAT_VERSION or m["hashAlgorithm"] != HASH_ALGORITHM:
        raise ValueError("Sabit alanlar hatalı")
    if m["byteOrder"] != BYTE_ORDER or m["sortOrder"] != SORT_ORDER:
        raise ValueError("Sabit alanlar hatalı")
    if not isinstance(m["version"], int) or m["version"] <= 0:
        raise ValueError("version pozitif tam sayı olmalı")
    if not _TAG.fullmatch(m["releaseTag"]):
        raise ValueError("releaseTag geçersiz")
    arts = m["artifacts"]
    if list(arts.keys()) != ["blocklist", "allowlist", "patterns", "packages"]:
        raise ValueError("artifacts anahtarları hatalı")
    for name, a in arts.items():
        if a["file"] != FILES[name] or not _SHA.fullmatch(a["sha256"]):
            raise ValueError(f"{name} girdisi hatalı")
        if not isinstance(a["count"], int) or a["count"] < 0:
            raise ValueError(f"{name}.count hatalı")
        if name in ("blocklist", "allowlist") and a["bytes"] != a["count"] * 8:
            raise ValueError(f"{name}.bytes ≠ count×8")
    for s in m["sources"]:
        if not s["url"].startswith("https://"):
            raise ValueError("Kaynak URL'si HTTPS olmalı")
        for key in ("name", "license", "fetchedAt"):
            if not s[key] or len(s[key]) > 512:
                raise ValueError(f"source.{key} hatalı")


def content_shas(m: dict) -> tuple[str, str, str, str]:
    """İçerik değişikliği karşılaştırması için 4 artifact SHA'sı (zaman alanları hariç)."""
    a = m["artifacts"]
    return (a["blocklist"]["sha256"], a["allowlist"]["sha256"], a["patterns"]["sha256"], a["packages"]["sha256"])


EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def release_asset_names(directory) -> list[str]:
    """Release'e yüklenecek dosyalar.

    GitHub Releases 0 baytlık dosya kabul etmez (HTTP 400 Bad Content-Length).
    Bu yüzden boş VERİ dosyaları yüklenmez; `.sig` dosyaları (her zaman 64 bayt)
    her zaman yüklenir. Uygulama, manifestte boyutu 0 (bin: bytes == 0;
    txt: sha256 == EMPTY_SHA256) olan dosyayı indirmez, boş kabul eder ve
    imzasını yine doğrular.
    """
    from pathlib import Path

    d = Path(directory)
    names = []
    for name in [*FILES.values(), MANIFEST_FILE]:
        if (d / name).stat().st_size > 0:
            names.append(name)
        names.append(f"{name}.sig")
    return names


if __name__ == "__main__":
    import sys

    if len(sys.argv) == 3 and sys.argv[1] == "assets":
        print("\n".join(release_asset_names(sys.argv[2])))
    else:
        print("kullanım: python -m src.manifest assets <dizin>", file=sys.stderr)
        sys.exit(2)
