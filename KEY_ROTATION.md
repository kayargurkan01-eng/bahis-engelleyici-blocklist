# İmza Anahtarı ve Rotasyon Prosedürü

## Mevcut anahtar

- Algoritma: Ed25519 (ham 32 baytlık anahtarlar, base64)
- Genel anahtar: [`signing/public_key.b64`](signing/public_key.b64)
- Genel anahtar parmak izi (ham 32 baytın SHA-256'sı): `signing/public_key.fingerprint`
- Özel anahtar: **yalnızca** bu reponun GitHub Actions secret'ında,
  `BLOCKLIST_ED25519_PRIVATE_KEY_B64`. Repoda, logda, artifact'ta veya başka bir
  yerde kopyası YOKTUR.
- Anahtar GitHub'ın runner'ında, tek seferlik geçici `key-setup` iş akışıyla
  üretildi. Özel anahtar üretildiği boru hattından doğrudan `gh secret set`'e
  (stdin) aktarıldı; hiçbir insan veya yapay zekâ ajanı değerini görmedi.
  İş akışı ve geçici `KEY_SETUP_TOKEN` işlemden sonra kaldırıldı.

## Bilinmesi gerekenler

1. **Genel anahtar uygulamaya gömülüdür.** Uygulama yalnızca bu anahtarla
   imzalanmış listeleri kabul eder.
2. **Anahtar rotasyonu normal liste güncellemesi DEĞİLDİR.** Yeni anahtarla
   imzalanan listeyi eski uygulamalar reddeder ve eski (doğrulanmış) listeyle
   çalışmaya devam eder. Yeni anahtar → uygulama güncellemesi gerekir.
3. **Özel anahtar kaybolursa** (secret silinirse) aynı güven köküyle yeni liste
   üretilemez. Kurtarma yolu yalnızca yeni anahtar + uygulama güncellemesidir.
   Bu yüzden secret'ı silmeyin, üzerine yazmayın.
4. **Özel anahtar sızdırılırsa** (compromise) bu özel olay müdahalesidir:
   saldırgan geçerli görünen liste yayınlayabilir.

## Planlı rotasyon adımları

1. Uygulamaya **yeni genel anahtarı ek olarak** gömün (eski + yeni, ikisi de
   kabul) ve bu sürümü yayınlayın. Kullanıcıların çoğu güncelleyene kadar bekleyin.
2. Yeni anahtarı key-setup yöntemiyle (geçici, tek repo, yalnız "Secrets:
   Read and write" izinli, 1 günlük fine-grained token) GitHub runner'ında
   üretin ve **yeni bir secret adına** yazın. Özel anahtar hiçbir zaman
   terminale, sohbete, loga veya dosyaya çıkmamalıdır.
3. `release.yml`'yi yeni secret'ı kullanacak şekilde değiştirin, `signing/`
   altındaki genel anahtarı ve parmak izini güncelleyin.
4. Sonraki bir uygulama sürümünde eski genel anahtarı kaldırın.
5. Eski secret'ı silin, geçici token'ı revoke edin, key-setup iş akışını kaldırın.

## Sızıntı (compromise) durumunda

1. `release.yml` zamanlanmış çalışmasını hemen devre dışı bırakın.
2. Sızan anahtarla yayınlanmış şüpheli release'leri silin.
3. Uygulamada sızan anahtarı kaldırıp yeni anahtarı gömen acil sürüm yayınlayın.
4. Yeni anahtarı yukarıdaki yöntemle üretin; olayı `docs/` altında kayda geçirin.
