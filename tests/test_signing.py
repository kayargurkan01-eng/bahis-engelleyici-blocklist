import base64
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.build import build, load_offline, read_local
from src.signing import (
    PRIVATE_KEY_ENV,
    SIGNED_FILES,
    SigningError,
    fingerprint,
    load_private_key_from_env,
    public_key_from_b64,
    public_raw,
    sign_dir,
    verify_bytes,
    verify_dir,
)

FIX = Path(__file__).resolve().parent / "fixtures"
T0 = datetime(2026, 9, 28, 1, 0, tzinfo=timezone.utc)

# TEST ONLY — sabit test anahtarı. Üretimde ASLA kullanılmaz; üretim anahtarı
# yalnız GitHub Actions secret'ındadır.
TEST_ONLY_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
TEST_ONLY_OTHER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))


def write_build(tmp_path: Path) -> Path:
    r = build(load_offline(FIX / "upstream", T0), read_local(FIX / "local"), T0)
    for name, data in r.files.items():
        (tmp_path / name).write_bytes(data)
    return tmp_path


def test_sign_and_verify(tmp_path):
    d = write_build(tmp_path)
    sign_dir(d, TEST_ONLY_KEY)
    for name in SIGNED_FILES:
        assert len((d / f"{name}.sig").read_bytes()) == 64
    verify_dir(d, TEST_ONLY_KEY.public_key())


def test_signature_is_over_exact_bytes(tmp_path):
    d = write_build(tmp_path)
    sign_dir(d, TEST_ONLY_KEY)
    data = bytearray((d / "blocklist.bin").read_bytes())
    data[0] ^= 1
    (d / "blocklist.bin").write_bytes(bytes(data))
    with pytest.raises(SigningError, match="blocklist.bin"):
        verify_dir(d, TEST_ONLY_KEY.public_key())


def test_empty_file_is_signed(tmp_path):
    d = write_build(tmp_path)
    (d / "packages.txt").write_bytes(b"")
    sign_dir(d, TEST_ONLY_KEY)
    verify_dir(d, TEST_ONLY_KEY.public_key())


def test_wrong_key_fails(tmp_path):
    d = write_build(tmp_path)
    sign_dir(d, TEST_ONLY_KEY)
    with pytest.raises(SigningError):
        verify_dir(d, TEST_ONLY_OTHER_KEY.public_key())


def test_bad_signature_length():
    with pytest.raises(SigningError):
        verify_bytes(b"x", b"", TEST_ONLY_KEY.public_key())
    with pytest.raises(SigningError):
        verify_bytes(b"x", b"\x00" * 63, TEST_ONLY_KEY.public_key())


def test_private_key_from_env(monkeypatch):
    raw = bytes(range(32))
    monkeypatch.setenv(PRIVATE_KEY_ENV, base64.b64encode(raw).decode())
    key = load_private_key_from_env()
    assert public_raw(key.public_key()) == public_raw(TEST_ONLY_KEY.public_key())
    monkeypatch.setenv(PRIVATE_KEY_ENV, "")
    with pytest.raises(SigningError):
        load_private_key_from_env()
    monkeypatch.setenv(PRIVATE_KEY_ENV, base64.b64encode(b"kisa").decode())
    with pytest.raises(SigningError):
        load_private_key_from_env()


def test_error_messages_never_contain_key(monkeypatch):
    secret = base64.b64encode(bytes(range(31))).decode()  # 31 bayt: geçersiz
    monkeypatch.setenv(PRIVATE_KEY_ENV, secret)
    with pytest.raises(SigningError) as e:
        load_private_key_from_env()
    assert secret not in str(e.value)


def test_public_key_b64_and_fingerprint():
    b64 = base64.b64encode(public_raw(TEST_ONLY_KEY.public_key())).decode()
    pub = public_key_from_b64(b64 + "\n")
    assert len(fingerprint(pub)) == 64
    with pytest.raises(SigningError):
        public_key_from_b64(base64.b64encode(b"x" * 31).decode())


def test_committed_public_key_and_fingerprint():
    root = Path(__file__).resolve().parent.parent / "signing"
    pub = public_key_from_b64((root / "public_key.b64").read_text())
    assert fingerprint(pub) == (root / "public_key.fingerprint").read_text().strip()
