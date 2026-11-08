# YARA (vendored)

- Kaynak: https://github.com/VirusTotal/yara
- Sürüm: v4.5.8 (commit 84b0e3c, 2026-07-28)
- Lisans: BSD-3-Clause (bkz. LICENSE)
- Yalnızca `libyara` alındı; kullanılmayan modüller (dex, dotnet, cuckoo, magic) çıkarıldı.
  `hash` modülü macOS CommonCrypto ile derlenir (OpenSSL gerekmez). Kaynak kodda değişiklik yok.
- `build_libyara.sh`: statik kütüphaneyi derler (app/build.sh çağırır, sonucu önbelleğe alır).

permwatch bu motorla Apple'ın XProtect imzalarını (/Library/Apple/System/Library/CoreServices/
XProtect.bundle/Contents/Resources/XProtect.yara ve XPScripts.yr) çalıştırır. İmzalar depoya
konmaz; her taramada Mac'teki güncel sürümleri okunur.
