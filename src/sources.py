"""Üretim kaynakları, yasaklı kaynak koruması ve güvenli indirme.

YALNIZCA lisans kökeni temiz kaynaklar (bkz. THIRD_PARTY_NOTICES.md).
HaGeZi, Turk-AdFilter ve BlockListProject (güncel gambling listesi HaGeZi'yi
upstream olarak kullanır) GPL / provenance kuralı gereği YASAKTIR.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

USER_AGENT = (
    "bahis-engelleyici-blocklist/1.0 "
    "(+https://github.com/kayargurkan01-eng/bahis-engelleyici-blocklist)"
)
TIMEOUT_SECONDS = 30
MAX_SOURCE_BYTES = 50 * 1024 * 1024

# Küçük harfe çevrilmiş ad/URL içinde geçerse kaynak reddedilir.
FORBIDDEN_TOKENS = ("hagezi", "turk-adfilter", "turkadfilter", "turk_adfilter", "blocklistproject")


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    license: str
    fmt: str  # "plain" | "hosts"
    min_entries: int
    # Commit bilgisi için (GitHub API); yoksa None.
    github_repo: str | None = None
    github_path: str | None = None
    github_ref: str = "master"


PRODUCTION_SOURCES: tuple[Source, ...] = (
    Source(
        name="ShadowWhisperer/BlockLists Gambling",
        url="https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Gambling",
        license="Unlicense",
        fmt="plain",
        min_entries=5000,
        github_repo="ShadowWhisperer/BlockLists",
        github_path="Lists/Gambling",
    ),
    Source(
        name="StevenBlack/hosts gambling-only",
        url="https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts",
        license="MIT",
        fmt="hosts",
        min_entries=3000,
        github_repo="StevenBlack/hosts",
        github_path="alternates/gambling-only/hosts",
    ),
)


class SourceError(RuntimeError):
    pass


def check_forbidden(sources) -> None:
    """Yasaklı kaynak varsa SourceError. Yalnız üretim kaynak yapılandırmasına uygulanır."""
    for s in sources:
        haystack = f"{s.name} {s.url} {s.github_repo or ''}".lower()
        for token in FORBIDDEN_TOKENS:
            if token in haystack:
                raise SourceError(f"Yasaklı kaynak ({token}): {s.name}")
        if not s.url.startswith("https://"):
            raise SourceError(f"HTTPS olmayan kaynak: {s.name}")
        if s.fmt not in ("plain", "hosts"):
            raise SourceError(f"Bilinmeyen biçim: {s.fmt}")


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise SourceError(f"HTTPS olmayan yönlendirme reddedildi: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_opener = urllib.request.build_opener(_HttpsOnlyRedirect())


@dataclass(frozen=True)
class Fetched:
    data: bytes
    fetched_at: datetime
    etag: str | None
    last_modified: str | None
    commit: str | None


def http_get(url: str, accept: str = "*/*") -> tuple[bytes, dict]:
    if not url.startswith("https://"):
        raise SourceError(f"HTTPS zorunlu: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    try:
        with _opener.open(req, timeout=TIMEOUT_SECONDS) as resp:
            if resp.status != 200:
                raise SourceError(f"HTTP {resp.status}: {url}")
            data = resp.read(MAX_SOURCE_BYTES + 1)
            if len(data) > MAX_SOURCE_BYTES:
                raise SourceError(f"Kaynak çok büyük: {url}")
            return data, dict(resp.headers)
    except urllib.error.HTTPError as e:
        raise SourceError(f"HTTP {e.code}: {url}") from e
    except urllib.error.URLError as e:
        raise SourceError(f"Bağlantı hatası: {url}: {e.reason}") from e


def _latest_commit(source: Source) -> str | None:
    if not source.github_repo:
        return None
    api = (
        f"https://api.github.com/repos/{source.github_repo}/commits"
        f"?path={source.github_path}&sha={source.github_ref}&per_page=1"
    )
    try:
        data, _ = http_get(api, accept="application/vnd.github+json")
        items = json.loads(data)
        return items[0]["sha"] if items else None
    except (SourceError, ValueError, KeyError, IndexError):
        # Commit bilgisi yalnız kayıt amaçlıdır; alınamazsa fetch zamanı yeterli.
        return None


def fetch(source: Source) -> Fetched:
    data, headers = http_get(source.url)
    if not data.strip():
        raise SourceError(f"Boş kaynak: {source.name}")
    return Fetched(
        data=data,
        fetched_at=datetime.now(timezone.utc).replace(microsecond=0),
        etag=headers.get("ETag"),
        last_modified=headers.get("Last-Modified"),
        commit=_latest_commit(source),
    )


if __name__ == "__main__":
    # CI: `python -m src.sources --check-config`
    if sys.argv[1:] == ["--check-config"]:
        check_forbidden(PRODUCTION_SOURCES)
        print(f"Kaynak yapılandırması temiz ({len(PRODUCTION_SOURCES)} kaynak).")
    else:
        print("kullanım: python -m src.sources --check-config", file=sys.stderr)
        sys.exit(2)
