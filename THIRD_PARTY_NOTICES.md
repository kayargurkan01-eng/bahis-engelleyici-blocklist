# Üçüncü Taraf Bildirimleri

Bu repo, kumar/bahis engelleyici uygulaması için engel listesi üretir. Üretim
çıktısı (`blocklist.bin`) aşağıdaki kaynaklardan **türetilmiş veridir**: domain
adları normalize edilir, 64-bit hash'e çevrilir ve yalnızca hash olarak dağıtılır.

Her sürümün `manifest.json` dosyası, kullanılan kaynakların URL'sini, lisansını,
alınma zamanını (`fetchedAt`) ve mümkünse upstream commit'ini (`commit`), `ETag`
ve `Last-Modified` bilgisini içerir.

## Üretim kaynakları (yalnızca bunlar)

### 1. ShadowWhisperer/BlockLists — Gambling
- Kaynak URL: https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Gambling
- Repo: https://github.com/ShadowWhisperer/BlockLists
- Lisans: **Unlicense** (kamu malı), https://github.com/ShadowWhisperer/BlockLists/blob/master/LICENSE
- Provenance: Repo README'si listelerin sahibinin kendi script'i ve elle
  eklemeleriyle üretildiğini ve başka listelerin birleştirilmediğini belirtir
  ("Lists are made from a custom script and manual additions. I will not merge
  other lists.").

### 2. StevenBlack/hosts — `gambling-only`
- Kaynak URL: https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts
- Repo: https://github.com/StevenBlack/hosts
- Lisans: **MIT**, Copyright © Steven Black, https://github.com/StevenBlack/hosts/blob/master/license.txt
- Yalnızca `alternates/gambling-only` varyantı kullanılır. Unified/base hosts
  varyantları (reklam, zararlı yazılım vb. kaynakları içerenler) **kullanılmaz**.
- Provenance: `gambling-only` bir birleştiricidir (aggregator). Readme'sinde
  listelenen alt kaynaklar ve lisansları:
  - BigDargon hostsVN gambling extension — **MIT**, Copyright (c) BigDargon
    - https://github.com/bigdargon/hostsVN
    - https://raw.githubusercontent.com/bigdargon/hostsVN/master/extensions/gambling/hosts-VN
  - Sinfonietta gambling hosts — **MIT**, Copyright (c) 2016 Sinfonietta
    - https://github.com/Sinfonietta/hostfiles
    - https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/gambling-hosts

MIT lisans metni (her MIT kaynak için geçerli; telif sahipleri yukarıda):

> Permission is hereby granted, free of charge, to any person obtaining a copy of
> this software and associated documentation files (the "Software"), to deal in
> the Software without restriction, including without limitation the rights to
> use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
> the Software, and to permit persons to whom the Software is furnished to do so,
> subject to the following conditions: The above copyright notice and this
> permission notice shall be included in all copies or substantial portions of the
> Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

### 3. Bu reponun kendi dosyaları
`sources/tr-manuel.txt`, `sources/allowlist.txt`, `sources/patterns.txt`,
`sources/packages.txt`: elle doğrulanmış kendi verimiz.

## Kullanılmayan kaynaklar ve nedeni

- **HaGeZi DNS blocklists**: GPL-3.0. Proje kuralı gereği GPL veri kullanılmaz.
- **Turk-AdFilter**: GPL. Aynı neden.
- **BlockListProject (gambling)**: Güncel gambling listesi HaGeZi gambling
  listesini upstream olarak kullanır. GPL/provenance kuralımız gereği üretim
  kaynağı değildir (provenance temizlenene kadar).

Bu kaynaklar `src/sources.py` içindeki `FORBIDDEN_TOKENS` ile CI seviyesinde
yasaklıdır; üretim kaynak yapılandırmasına eklenirse build ve testler başarısız olur.

## Yazılım bağımlılıkları (pipeline)

| Paket | Sürüm | Lisans |
|---|---|---|
| xxhash (python-xxhash) | 4.0.1 | BSD-2-Clause |
| cryptography | 50.0.1 | Apache-2.0 OR BSD-3-Clause |
| pytest (yalnız test) | 9.1.1 | MIT |

xxHash algoritması: Yann Collet, BSD-2-Clause.
