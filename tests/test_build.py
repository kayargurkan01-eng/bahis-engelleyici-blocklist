import hashlib
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.build import BuildError, build, check_drop, content_changed, load_offline, main, read_local
from src.hash64 import decode, hash_signed
from src.manifest import FILES, MANIFEST_FILE
from src.normalize import normalize
from src.sources import PRODUCTION_SOURCES, Fetched, Source, SourceError, check_forbidden

FIX = Path(__file__).resolve().parent / "fixtures"
T0 = datetime(2026, 9, 28, 1, 0, tzinfo=timezone.utc)


def fixture_build(generated_at=T0):
    return build(load_offline(FIX / "upstream", generated_at), read_local(FIX / "local"), generated_at)


def test_fixture_build_contents():
    r = fixture_build()
    block = set(decode(r.files["blocklist.bin"]))
    allow = set(decode(r.files["allowlist.bin"]))

    def h(d):
        return hash_signed(d)

    for d in ["ornek-engelli.test", "ikinci-engelli.test", "ucuncu.test", normalize("bücher-bahis.test"),
              "ortak.test", "hosts-engelli.test", "hosts-ikinci.test", "alt.kumar.com.tr", "ornek.tr", "tr-manuel.test"]:
        assert h(d) in block, d
    # Geçersiz, public suffix, localhost girdileri yok.
    assert h("com.tr") not in block and h("localhost") not in block
    # Allowlist ile birebir eşleşen blocklist'ten çıkar; allowlist ayrı artifact.
    assert h("guvenli.test") not in block
    assert allow == {h("guvenli.test"), h("yardim.ornek-engelli.test")}
    assert r.files["patterns.txt"] == b"ikincimarka\t2\t3\nornekmarka\t1\t4\n"
    assert r.files["packages.txt"] == b"com.ornek.test.bahis\ncom.ornek.test.ikinci\n"


def test_report_counts_and_overlap():
    r = fixture_build()
    plain, hosts = r.report["sources"]
    assert plain["raw"] == 8 and plain["invalid"] == 2  # gecersiz_domain, com.tr
    assert hosts["overlapWithPrevious"] == 1  # ortak.test
    assert r.report["allowlist"]["removedFromBlocklist"] == 1


def test_manifest_counts_and_hashes():
    r = fixture_build()
    m = r.manifest
    for name in ("blocklist", "allowlist"):
        data = r.files[FILES[name]]
        a = m["artifacts"][name]
        assert a["bytes"] == len(data) == a["count"] * 8
        assert a["sha256"] == hashlib.sha256(data).hexdigest()
    for name in ("patterns", "packages"):
        assert m["artifacts"][name]["sha256"] == hashlib.sha256(r.files[FILES[name]]).hexdigest()
    assert m["artifacts"]["patterns"]["count"] == 2
    assert m["artifacts"]["packages"]["count"] == 2
    assert m["version"] == 202609280100 and m["releaseTag"] == "list-202609280100"
    assert m["generatedAt"] == "2026-09-28T01:00:00Z"


def test_manifest_schema_exact():
    m = json.loads(fixture_build().files[MANIFEST_FILE])
    assert list(m) == ["formatVersion", "version", "releaseTag", "generatedAt", "pipelineVersion",
                       "hashAlgorithm", "byteOrder", "sortOrder", "artifacts", "sources"]
    assert (m["formatVersion"], m["hashAlgorithm"], m["byteOrder"], m["sortOrder"]) == \
        (1, "xxhash64-seed0", "little-endian", "signed-int64-ascending")
    assert list(m["artifacts"]) == ["blocklist", "allowlist", "patterns", "packages"]
    assert list(m["artifacts"]["blocklist"]) == ["file", "count", "bytes", "sha256"]
    assert list(m["artifacts"]["patterns"]) == ["file", "count", "sha256"]
    assert list(m["sources"][0]) == ["name", "url", "license", "fetchedAt", "commit", "etag", "lastModified"]


def test_manifest_bytes_canonical():
    data = fixture_build().files[MANIFEST_FILE]
    assert data.endswith(b"}\n") and not data.endswith(b"\n\n")
    assert b"\r" not in data
    data.decode("ascii")


def test_deterministic_double_build():
    a, b = fixture_build(), fixture_build()
    assert a.files == b.files


def test_content_change_detection_ignores_timestamps():
    a = fixture_build(T0)
    b = fixture_build(datetime(2026, 9, 29, 1, 0, tzinfo=timezone.utc))
    assert a.files[MANIFEST_FILE] != b.files[MANIFEST_FILE]
    assert not content_changed(b.manifest, a.manifest)
    assert content_changed(b.manifest, None)
    changed = json.loads(json.dumps(a.manifest))
    changed["artifacts"]["packages"]["sha256"] = "0" * 64
    assert content_changed(b.manifest, changed)


def test_drop_guard():
    r = fixture_build()
    prev = json.loads(json.dumps(r.manifest))
    count = r.manifest["artifacts"]["blocklist"]["count"]
    prev["artifacts"]["blocklist"]["count"] = int(count / 0.69) + 1  # >%30 düşüş
    with pytest.raises(BuildError):
        check_drop(r.manifest, prev)
    prev["artifacts"]["blocklist"]["count"] = int(count / 0.71)  # <%30 düşüş
    check_drop(r.manifest, prev)
    prev["artifacts"]["blocklist"]["count"] = 1  # artış: koruma yok
    check_drop(r.manifest, prev)
    check_drop(r.manifest, None)


def test_empty_upstream_rejected():
    ups = load_offline(FIX / "upstream", T0)
    s, f = ups[0]
    empty = [(s, replace(f, data=b"# sadece yorum\n"))] + ups[1:]
    with pytest.raises(BuildError, match="boş"):
        build(empty, read_local(FIX / "local"), T0)


def test_too_small_upstream_rejected():
    ups = load_offline(FIX / "upstream", T0)
    s, f = ups[0]
    strict = [(replace(s, min_entries=1000), f)] + ups[1:]
    with pytest.raises(BuildError, match="küçük"):
        build(strict, read_local(FIX / "local"), T0)


@pytest.mark.parametrize("name,url", [
    ("hagezi gambling", "https://example.test/list"),
    ("iyi-kaynak", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/x"),
    ("HaGeZi", "https://example.test/x"),
    ("Turk-AdFilter", "https://example.test/x"),
    ("x", "https://example.test/turk-adfilter/list"),
    ("BlockListProject gambling", "https://example.test/x"),
    ("x", "https://blocklistproject.github.io/Lists/gambling.txt"),
    ("http-kaynak", "http://example.test/x"),
])
def test_forbidden_sources_rejected(name, url):
    bad = Source(name=name, url=url, license="?", fmt="plain", min_entries=1)
    with pytest.raises(SourceError):
        check_forbidden([bad])
    ups = load_offline(FIX / "upstream", T0)
    with pytest.raises(SourceError):
        build([(bad, ups[0][1])] + ups[1:], read_local(FIX / "local"), T0)


def test_production_config_is_clean():
    check_forbidden(PRODUCTION_SOURCES)
    names = {s.url for s in PRODUCTION_SOURCES}
    assert names == {
        "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Gambling",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts",
    }


def test_production_local_sources_parse():
    # Repodaki üretim dosyaları (şimdilik yalnız yorum) geçerli olmalı.
    local = read_local(Path(__file__).resolve().parent.parent / "sources")
    ups = load_offline(FIX / "upstream", T0)
    build(ups, local, T0)


def test_cli_offline_and_previous(tmp_path):
    out1 = tmp_path / "a"
    assert main(["--out", str(out1), "--offline", str(FIX / "upstream"), "--sources-dir", str(FIX / "local"),
                 "--generated-at", "2026-09-28T01:00:00Z"]) == 0
    report = json.loads((out1 / "build_report.json").read_text())
    assert report["changed"] is True
    out2 = tmp_path / "b"
    assert main(["--out", str(out2), "--offline", str(FIX / "upstream"), "--sources-dir", str(FIX / "local"),
                 "--generated-at", "2026-09-29T01:00:00Z", "--previous-manifest", str(out1 / "manifest.json")]) == 0
    assert json.loads((out2 / "build_report.json").read_text())["changed"] is False
