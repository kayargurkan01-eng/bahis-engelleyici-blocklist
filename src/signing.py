"""Ed25519 imzalama / doğrulama (`cryptography` paketi).

Anahtar biçimi: ham 32 baytlık Ed25519 anahtarı, base64.
- Özel anahtar YALNIZCA `BLOCKLIST_ED25519_PRIVATE_KEY_B64` ortam değişkeninden
  okunur; hiçbir zaman yazdırılmaz, dosyaya yazılmaz, argüman olarak verilmez.
- Genel anahtar `signing/public_key.b64` (gizli değildir).
- Her `<dosya>.sig`, dosyanın TAM baytları üzerinde 64 baytlık ham imzadır.

Komutlar:
  python -m src.signing sign   <dir>             (özel anahtar env'den)
  python -m src.signing verify <dir> <pubkey.b64>
  python -m src.signing verify-file <dosya> <imza> <pubkey.b64>
  python -m src.signing keygen <pubkey-out>      (YALNIZ key-setup iş akışı;
      özel anahtarı stdout'a yazar, çağıran taraf doğrudan `gh secret set`e borular)
"""

from __future__ import annotations

import base64
import hashlib
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .manifest import FILES, MANIFEST_FILE

SIGNED_FILES = [FILES["blocklist"], FILES["allowlist"], FILES["patterns"], FILES["packages"], MANIFEST_FILE]
PRIVATE_KEY_ENV = "BLOCKLIST_ED25519_PRIVATE_KEY_B64"
SIGNATURE_BYTES = 64


class SigningError(RuntimeError):
    pass


def load_private_key_from_env() -> Ed25519PrivateKey:
    value = os.environ.get(PRIVATE_KEY_ENV, "")
    if not value:
        raise SigningError(f"{PRIVATE_KEY_ENV} tanımlı değil")
    try:
        raw = base64.b64decode(value.strip(), validate=True)
    except ValueError:
        raise SigningError("Özel anahtar base64 değil") from None
    if len(raw) != 32:
        raise SigningError("Özel anahtar 32 bayt olmalı")
    return Ed25519PrivateKey.from_private_bytes(raw)


def public_key_from_b64(text: str) -> Ed25519PublicKey:
    raw = base64.b64decode(text.strip(), validate=True)
    if len(raw) != 32:
        raise SigningError("Genel anahtar 32 bayt olmalı")
    return Ed25519PublicKey.from_public_bytes(raw)


def public_raw(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fingerprint(pub: Ed25519PublicKey) -> str:
    """Ham 32 baytlık genel anahtarın SHA-256'sı (hex)."""
    return hashlib.sha256(public_raw(pub)).hexdigest()


def sign_dir(directory: Path, key: Ed25519PrivateKey) -> None:
    for name in SIGNED_FILES:
        data = (directory / name).read_bytes()
        (directory / f"{name}.sig").write_bytes(key.sign(data))


def verify_bytes(data: bytes, signature: bytes, pub: Ed25519PublicKey) -> None:
    if len(signature) != SIGNATURE_BYTES:
        raise SigningError("İmza 64 bayt olmalı")
    try:
        pub.verify(signature, data)
    except InvalidSignature:
        raise SigningError("İmza geçersiz") from None


def verify_dir(directory: Path, pub: Ed25519PublicKey) -> None:
    for name in SIGNED_FILES:
        try:
            verify_bytes((directory / name).read_bytes(), (directory / f"{name}.sig").read_bytes(), pub)
        except SigningError as e:
            raise SigningError(f"{name}: {e}") from None


def _main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "sign":
        key = load_private_key_from_env()
        sign_dir(Path(argv[1]), key)
        print(f"İmzalandı: {len(SIGNED_FILES)} dosya. Genel anahtar parmak izi: {fingerprint(key.public_key())}")
        return 0
    if len(argv) == 3 and argv[0] == "verify":
        pub = public_key_from_b64(Path(argv[2]).read_text())
        verify_dir(Path(argv[1]), pub)
        print(f"İmzalar geçerli ({len(SIGNED_FILES)} dosya). Parmak izi: {fingerprint(pub)}")
        return 0
    if len(argv) == 4 and argv[0] == "verify-file":
        pub = public_key_from_b64(Path(argv[3]).read_text())
        verify_bytes(Path(argv[1]).read_bytes(), Path(argv[2]).read_bytes(), pub)
        print(f"İmza geçerli: {argv[1]}")
        return 0
    if len(argv) == 2 and argv[0] == "keygen":
        if sys.stdout.isatty():
            print("keygen çıktısı terminale yazılmaz; yalnız bir boruya verilebilir.", file=sys.stderr)
            return 2
        key = Ed25519PrivateKey.generate()
        pub = key.public_key()
        # Kendi kendine test: imzala → doğrula.
        verify_bytes(b"key-setup-self-test", key.sign(b"key-setup-self-test"), pub)
        Path(argv[1]).write_text(base64.b64encode(public_raw(pub)).decode("ascii") + "\n")
        raw = key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )
        sys.stdout.write(base64.b64encode(raw).decode("ascii"))
        sys.stdout.flush()
        print(f"Genel anahtar parmak izi (SHA-256): {fingerprint(pub)}", file=sys.stderr)
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(_main(sys.argv[1:]))
    except SigningError as e:
        print(f"HATA: {e}", file=sys.stderr)
        sys.exit(1)
