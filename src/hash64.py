"""xxHash64 (seed 0) — ana repodaki Kotlin `Hash64` ile birebir.

`xxhash` paketi (BSD-2-Clause) unsigned 64-bit döner; Kotlin `Long` signed
64-bit olduğundan two's-complement dönüşümü yapılır ve sıralama SIGNED
int64 artan yapılır.
"""

from __future__ import annotations

import struct

import xxhash

_TWO_63 = 1 << 63
_TWO_64 = 1 << 64


def to_signed(unsigned: int) -> int:
    if not 0 <= unsigned < _TWO_64:
        raise ValueError("64-bit unsigned aralık dışı")
    return unsigned - _TWO_64 if unsigned >= _TWO_63 else unsigned


def hash_unsigned(host: str) -> int:
    # Kanonik host her zaman ASCII'dir; ASCII olmayan girdi hata vermelidir.
    return xxhash.xxh64_intdigest(host.encode("ascii"), 0)


def hash_signed(host: str) -> int:
    return to_signed(hash_unsigned(host))


def encode_sorted(signed_hashes: list[int]) -> bytes:
    """Biçim v1: signed artan, tekrarsız, LITTLE-ENDIAN int64 kayıtlar, başlıksız."""
    for a, b in zip(signed_hashes, signed_hashes[1:]):
        if a >= b:
            raise ValueError("Hash dizisi signed artan ve tekrarsız değil")
    return struct.pack(f"<{len(signed_hashes)}q", *signed_hashes)


def decode(data: bytes) -> list[int]:
    if len(data) % 8:
        raise ValueError("Boyut 8'in katı değil")
    return list(struct.unpack(f"<{len(data) // 8}q", data))


def build_binary(hosts: set[str]) -> tuple[bytes, int]:
    hashes = sorted({hash_signed(h) for h in hosts})
    if len(hashes) != len(hosts):
        # 64-bit çakışma: pratikte olmaz; olursa sessizce geçme.
        raise ValueError("64-bit hash çakışması tespit edildi")
    return encode_sorted(hashes), len(hashes)
