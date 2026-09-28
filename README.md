# bahis-engelleyici-blocklist

Kumar ve bahis engelleyici Android uygulaması için **imzalı engel listesi hattı**.
Sunucu yok: GitHub Actions her gün listeyi üretir, Ed25519 ile imzalar ve
GitHub Releases'a yükler. Uygulama listeyi token/kimlik bilgisi olmadan indirir,
imzayı doğrulamadan hiçbir şeyi kullanmaz.

Kaynaklar ve lisanslar: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) ·
Anahtar: [KEY_ROTATION.md](KEY_ROTATION.md)

## Çıktılar (her release'de)

| Dosya | İçerik |
|---|---|
| `blocklist.bin` + `.sig` | Engellenen domain hash'leri |
| `allowlist.bin` + `.sig` | İzinli domain hash'leri (uygulamada blocklist'ten ÖNCE uygulanır) |
| `patterns.txt` + `.sig` | Numaralı marka aileleri: `kök<TAB>min<TAB>max` |
| `packages.txt` + `.sig` | Uygulama paket adları (birebir) |
| `manifest.json` + `.sig` | Sürüm, sayılar, SHA-256'lar, kaynaklar |

Uygulama önce `releases/latest/download/manifest.json` (+ `.sig`) indirir,
imzayı doğrular, sonra diğer dosyaları manifestteki **değişmez** `releaseTag`
üzerinden (`releases/download/<releaseTag>/...`) indirir.

## Biçim v1

- `.bin`: başlıksız; her kayıt 8 bayt **little-endian two's-complement int64**;
  **signed artan** sıralı; tekrarsız; boyut = `count × 8`.
- Hash: **xxHash64, seed 0**, kanonik ASCII domain baytları üzerinde.
- Kanonik domain: trim → küçük harf → sondaki nokta(lar) atılır → IDN → Punycode
  (IDNA2003, Java `IDN.toASCII(USE_STD3_ASCII_RULES)` ile aynı) → yalnız
  `a-z 0-9 -` → `www.`/`m.`/`mobile.` öneki atılır (kalan public suffix değilse)
  → public suffix girdileri (`com`, `com.tr`, ...) atılır.
- `.sig`: dosyanın tam baytları üzerinde 64 baytlık ham Ed25519 imzası.
- Python ↔ Kotlin uyumu `golden/vectors.json` ile iki repoda da test edilir.

## Geliştirme

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m pytest
python -m src.build --out output --offline tests/fixtures/upstream --sources-dir tests/fixtures/local --generated-at 2026-09-28T01:00:00Z
python -m golden.generate --check
python -m src.sources --check-config
```

Kaynak dosyalarına (`sources/`) yalnızca **elle doğrulanmış** veri eklenir.
