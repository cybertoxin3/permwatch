**Türkçe** · [English](GELISTIRME_en.md) · [Русский](GELISTIRME_ru.md)

# permwatch

[![build](https://github.com/cybertoxin3/permwatch/actions/workflows/build.yml/badge.svg)](https://github.com/cybertoxin3/permwatch/actions/workflows/build.yml)

macOS için Endpoint Security tabanlı izin ve kalıcılık denetleyicisi. Şimdilik CLI çekirdeği.

| Çıktıdaki `event` | ES olayı | Ne yakalar | macOS |
|---|---|---|---|
| `exec` | `NOTIFY_EXEC` | Süreç başlatma. Apple binary'leri filtreli, LOLBin'ler ve `DYLD_*` ortam değişkeni içerenler her zaman gösterilir | 10.15+ |
| `btm_launch_item_add` | `NOTIFY_BTM_LAUNCH_ITEM_ADD` | Yeni login item, LaunchAgent, LaunchDaemon | 13+ |
| `btm_launch_item_remove` | `NOTIFY_BTM_LAUNCH_ITEM_REMOVE` | Kalıcılık öğesinin silinmesi (iz temizleme) | 13+ |
| `quarantine_removed` | `NOTIFY_DELETEEXTATTR` | `com.apple.quarantine` silinmesi (Gatekeeper atlatma) | 10.15+ |
| `gatekeeper_user_override` | `NOTIFY_GATEKEEPER_USER_OVERRIDE` | Kullanıcı engellenen uygulama için "Yine de Aç" dedi | 15+ |
| `tcc_modify` | `NOTIFY_TCC_MODIFY` | TCC izni verildi, geri alındı veya değişti (servis, uygulama, sebep) | 15.4+ |

Her süreç için şunlar yazılır: `pid`, `ppid`, `responsible_pid`, yol, `signing_id`, `team_id`,
`signature` (`apple` / `developer` / `adhoc` / `unsigned`), ham `cs_flags` ve `cdhash`.
cdhash'i VirusTotal gibi servislerde arayabilirsin.

Çıktı JSON Lines formatında, her satır bir olay. Geçersiz UTF-8 byte'ları `\ufffd` olarak yazılır,
böylece `jq` hiçbir satırda hata vermez.

### Neden `eslogger` değil?

macOS 13+ ile gelen `eslogger` aynı olayları ham JSON olarak basar. permwatch'ın farkı şunlar:
gürültü filtresi (platform binary'leri atılır ama LOLBin'ler tutulur), yalnızca quarantine'e
indirgenmiş xattr olayları, `DYLD_*` enjeksiyon tespiti, sadeleştirilmiş şema ve
yol haritasındaki depolama, kural ve arayüz katmanları. Doğrulama için çıktıyı `eslogger` ile
karşılaştırabilirsin:

```sh
sudo eslogger btm_launch_item_add tcc_modify | jq .
```

## macOS uygulaması

`app/` klasöründe SwiftUI arayüzü var. Xcode gerekmez, Command Line Tools yeterli:

```sh
make app                          # app/build/permwatch.app
open app/build/permwatch.app
```

- Uygulama demo verisiyle açılır. **Dosya → Olay Kaydını Aç…** ile CLI'ın ürettiği bir
  `events.jsonl` açılabilir; dosya büyüdükçe uygulama da güncellenir ve yüksek riskli
  olaylarda bildirim gönderir.
- Arayüz sistem diline göre açılır (13 dil). Çeviriler `app/i18n/<dil>.tsv` dosyalarında;
  derleme sırasında her dilde bütün anahtarların ve yer tutucuların olduğu kontrol edilir.
- Kural motoru `app/Sources/Analyzer.swift` içinde.

## Derleme ve test

```sh
make            # derler ve entitlement ile ad-hoc imzalar
make test       # JSON escape unit testleri (ES gerektirmez, her Mac'te çalışır)
```

## Neden ana Mac'te çalışmıyor?

`com.apple.developer.endpoint-security.client` kısıtlı bir entitlement. SIP açıkken
ad-hoc imzalı binary'yi AMFI öldürür (exit 137 / SIGKILL). İki çözüm var:

1. **Test için:** SIP ve AMFI kapalı bir macOS VM (aşağıda).
2. **Dağıtım için:** Apple'dan ES entitlement'ı istersin, Developer ID ile imzalar
   ve notarize edersin. (Talep gönderildi, inceleniyor.)

## VM test ortamı (Apple Silicon, UTM)

1. UTM'yi kur, "Virtualize → macOS" ile bir VM oluştur (macOS 15.4+ olsun ki TCC_MODIFY çalışsın).
2. VM'i kurtarma modunda aç (UTM'de VM'e sağ tık → *Boot into Recovery Mode*).
3. Kurtarma terminalinde:
   ```sh
   csrutil disable
   ```
4. Normal açılıştan sonra VM içinde:
   ```sh
   sudo nvram boot-args="amfi_get_out_of_my_way=1"
   sudo reboot
   ```
5. Terminal'e **Full Disk Access** ver (Sistem Ayarları → Gizlilik ve Güvenlik).
6. Projeyi VM'e kopyala, `xcode-select --install`, sonra `make && sudo ./permwatch`.

> ⚠️ Bu ayarlar VM'in güvenliğini ciddi şekilde zayıflatır. Ana makinende yapma.
> Malware örneklerini de sadece bu VM'de, snapshot alarak çalıştır.

## Olayları tetiklemek

```sh
# Terminal 1
sudo ./permwatch | tee events.jsonl | jq .

# Terminal 2 (sudo olmadan)
./tests/trigger.sh
```

`trigger.sh` zararsız şekilde şunları yapar: LOLBin çalıştırma (`osascript`, `curl`),
`DYLD_INSERT_LIBRARIES` ile exec, quarantine ekleyip silme, test LaunchAgent'ı yükleyip kaldırma.
TCC ve Gatekeeper olaylarını elle nasıl tetikleyeceğini de yazar.

## Yol haritası

- [x] ES istemcisi: EXEC, BTM add/remove, TCC_MODIFY, quarantine silme, Gatekeeper override
- [x] LOLBin izin listesi, `DYLD_*` tespiti, ad-hoc imza ayrımı, cdhash
- [x] JSON escape unit testleri, GitHub Actions derlemesi
- [ ] Hassas dosya erişimi: ayrı bir `es_client` üzerinde inverted muting ile `NOTIFY_OPEN`
      (LaunchAgents, TCC.db, Keychains, `~/.zshrc`, tarayıcı cookie'leri)
- [ ] Enjeksiyon: `NOTIFY_GET_TASK`, `NOTIFY_REMOTE_THREAD_CREATE`
- [ ] Yetki ve uzaktan erişim: `NOTIFY_SUDO`, `NOTIFY_AUTHORIZATION_PETITION`,
      `NOTIFY_SCREENSHARING_ATTACH`, `NOTIFY_OPENSSH_LOGIN`, `NOTIFY_XP_MALWARE_DETECTED`,
      `NOTIFY_PROFILE_ADD`
- [ ] Süreç soy ağacı (`Safari → zsh → curl → osascript`)
- [ ] JSON kural dosyası (Sigma benzeri) ve SQLite depolama
- [ ] System Extension + XPC + SwiftUI arayüzü
- [ ] Lite sürüm: CoreAudio süreç nesneleriyle mikrofon geçmişi (App Store)
