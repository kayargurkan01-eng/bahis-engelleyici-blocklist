"""Liste üretimi.

kaynaklar → ayrıştır → normalize → ortak önek → geçersiz/public suffix at →
tekilleştir → (allowlist ile birebir eşleşenleri blocklist'ten çıkar) →
xxHash64 → signed int64 → signed artan sıra → LE ikili dosya.

Allowlist ayrıca `allowlist.bin` olarak üretilir; uygulama çalışma anında
allowlist'i blocklist'ten ÖNCE uygular (daha spesifik allowlist girdisi
üst domain engelini ezebilir), bu yüzden build-time silme onun yerini tutmaz.

Kullanım:
  python -m src.build --out output                       # üretim (ağdan indirir)
  python -m src.build --out output --offline tests/fixtures/upstream
  Seçenekler: --generated-at 2026-09-28T01:00:00Z (veya SOURCE_DATE_EPOCH),
              --previous-manifest <dosya>, --sources-dir sources
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import PIPELINE_VERSION
from .hash64 import build_binary
from .manifest import FILES, MANIFEST_FILE, build_manifest, content_shas, dumps, iso
from .normalize import canonical_list_entry
from .parsers import (
    canonical_packages,
    canonical_patterns,
    decode_text,
    parse_hosts,
    parse_packages,
    parse_patterns,
    parse_plain,
)
from .sources import PRODUCTION_SOURCES, Fetched, Source, SourceError, check_forbidden, fetch

MAX_DROP_RATIO = 0.30


class BuildError(RuntimeError):
    pass


@dataclass
class BuildResult:
    files: dict[str, bytes]
    manifest: dict
    report: dict = field(default_factory=dict)


def _canonical_set(entries: list[str]) -> tuple[set[str], int]:
    out: set[str] = set()
    invalid = 0
    for e in entries:
        c = canonical_list_entry(e)
        if c is None:
            invalid += 1
        else:
            out.add(c)
    return out, invalid


def build(
    upstreams: list[tuple[Source, Fetched]],
    local: dict[str, bytes],
    generated_at: datetime,
) -> BuildResult:
    """Saf fonksiyon: aynı girdi + aynı zaman → byte-for-byte aynı çıktı."""
    check_forbidden([s for s, _ in upstreams])
    report: dict = {"sources": []}
    block: set[str] = set()

    for source, fetched in upstreams:
        text = decode_text(fetched.data, source.name)
        raw = parse_plain(text) if source.fmt == "plain" else parse_hosts(text)
        if not raw:
            raise BuildError(f"Kaynak boş: {source.name}")
        if len(raw) < source.min_entries:
            raise BuildError(f"Kaynak beklenenden küçük: {source.name} ({len(raw)} < {source.min_entries})")
        canonical, invalid = _canonical_set(raw)
        overlap = len(canonical & block)
        block |= canonical
        report["sources"].append({
            "name": source.name, "raw": len(raw), "canonical": len(canonical),
            "invalid": invalid, "overlapWithPrevious": overlap,
        })

    tr, tr_invalid = _canonical_set(parse_plain(decode_text(local["tr-manuel.txt"], "tr-manuel.txt")))
    report["trManuel"] = {"canonical": len(tr), "invalid": tr_invalid, "overlapWithPrevious": len(tr & block)}
    block |= tr

    allow, allow_invalid = _canonical_set(parse_plain(decode_text(local["allowlist.txt"], "allowlist.txt")))
    removed = block & allow
    block -= removed
    report["allowlist"] = {"canonical": len(allow), "invalid": allow_invalid, "removedFromBlocklist": len(removed)}

    patterns = parse_patterns(decode_text(local["patterns.txt"], "patterns.txt"))
    packages = parse_packages(decode_text(local["packages.txt"], "packages.txt"))

    block_bin, block_count = build_binary(block)
    allow_bin, allow_count = build_binary(allow)
    files = {
        FILES["blocklist"]: block_bin,
        FILES["allowlist"]: allow_bin,
        FILES["patterns"]: canonical_patterns(patterns),
        FILES["packages"]: canonical_packages(packages),
    }

    def sha(name):
        return hashlib.sha256(files[FILES[name]]).hexdigest()

    manifest = build_manifest(
        generated_at=generated_at,
        pipeline_version=PIPELINE_VERSION,
        artifacts={
            "blocklist": {"count": block_count, "bytes": len(block_bin), "sha256": sha("blocklist")},
            "allowlist": {"count": allow_count, "bytes": len(allow_bin), "sha256": sha("allowlist")},
            "patterns": {"count": len(patterns), "sha256": sha("patterns")},
            "packages": {"count": len(packages), "sha256": sha("packages")},
        },
        sources=[
            {
                "name": s.name, "url": s.url, "license": s.license,
                "fetchedAt": iso(f.fetched_at), "commit": f.commit,
                "etag": f.etag, "lastModified": f.last_modified,
            }
            for s, f in upstreams
        ],
    )
    files[MANIFEST_FILE] = dumps(manifest)
    report["final"] = {
        "blocklist": block_count, "allowlist": allow_count,
        "patterns": len(patterns), "packages": len(packages),
        "bytes": {name: len(data) for name, data in files.items()},
    }
    return BuildResult(files=files, manifest=manifest, report=report)


def content_changed(new: dict, previous: dict | None) -> bool:
    """Yalnız 4 artifact SHA'sı karşılaştırılır; generatedAt/fetchedAt sahte değişiklik yaratmaz."""
    return previous is None or content_shas(new) != content_shas(previous)


def check_drop(new: dict, previous: dict | None) -> None:
    if previous is None:
        return
    old = previous["artifacts"]["blocklist"]["count"]
    cur = new["artifacts"]["blocklist"]["count"]
    if old > 0 and cur < old * (1 - MAX_DROP_RATIO):
        raise BuildError(
            f"Blocklist {old} → {cur} (%{100 * (old - cur) / old:.1f} düşüş). "
            f"%{int(MAX_DROP_RATIO * 100)} üstü düşüşte otomatik yayın yapılmaz; elle inceleyin."
        )


def resolve_generated_at(arg: str | None) -> datetime:
    if arg:
        return datetime.strptime(arg, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc)
    # Sürüm dakika hassasiyetinde; saniye sıfırlanır.
    return datetime.now(timezone.utc).replace(second=0, microsecond=0)


def load_offline(directory: Path, generated_at: datetime) -> list[tuple[Source, Fetched]]:
    """Çevrimdışı mod: `<dir>/sources.json` kaynak tanımları + yerel dosyalar (test/CI)."""
    spec = json.loads((directory / "sources.json").read_text(encoding="utf-8"))
    out = []
    for item in spec:
        s = Source(
            name=item["name"], url=item["url"], license=item["license"],
            fmt=item["fmt"], min_entries=item["min_entries"],
        )
        data = (directory / item["file"]).read_bytes()
        out.append((s, Fetched(data=data, fetched_at=generated_at, etag=None, last_modified=None, commit=item.get("commit"))))
    return out


def read_local(sources_dir: Path) -> dict[str, bytes]:
    return {name: (sources_dir / name).read_bytes() for name in ("tr-manuel.txt", "allowlist.txt", "patterns.txt", "packages.txt")}


def _github_output(values: dict) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            for k, v in values.items():
                f.write(f"{k}={v}\n")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--offline")
    ap.add_argument("--sources-dir", default="sources")
    ap.add_argument("--generated-at")
    ap.add_argument("--previous-manifest")
    args = ap.parse_args(argv)

    started = time.monotonic()
    generated_at = resolve_generated_at(args.generated_at)
    if args.offline:
        upstreams = load_offline(Path(args.offline), generated_at)
    else:
        check_forbidden(PRODUCTION_SOURCES)
        upstreams = [(s, fetch(s)) for s in PRODUCTION_SOURCES]

    result = build(upstreams, read_local(Path(args.sources_dir)), generated_at)

    previous = None
    if args.previous_manifest and Path(args.previous_manifest).is_file():
        previous = json.loads(Path(args.previous_manifest).read_text(encoding="utf-8"))

    changed = content_changed(result.manifest, previous)
    if changed:
        check_drop(result.manifest, previous)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, data in result.files.items():
        (out / name).write_bytes(data)
    result.report["changed"] = changed
    result.report["previousVersion"] = previous["version"] if previous else None
    result.report["buildSeconds"] = round(time.monotonic() - started, 2)
    (out / "build_report.json").write_text(json.dumps(result.report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(json.dumps(result.report, indent=2, ensure_ascii=False))
    print(f"releaseTag={result.manifest['releaseTag']} changed={changed}")
    _github_output({"changed": str(changed).lower(), "tag": result.manifest["releaseTag"]})
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (BuildError, SourceError, ValueError) as e:
        print(f"HATA: {e}", file=sys.stderr)
        sys.exit(1)
