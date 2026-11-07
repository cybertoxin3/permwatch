<div align="center">

**Türkçe** · [English](README_en.md) · [Русский](README_ru.md)

# permwatch

**Mac'inde hangi uygulamanın neye eriştiğini gör.**

Kamera, mikrofon, ekran kaydı, başlangıç öğeleri.<br>
Her izin değişikliğinin kaydını tutar, şüpheli olanları anında haber verir.

[![build](https://github.com/cybertoxin3/permwatch/actions/workflows/build.yml/badge.svg)](https://github.com/cybertoxin3/permwatch/actions/workflows/build.yml)
![macOS](https://img.shields.io/badge/macOS-13%2B-black?logo=apple)
![Durum](https://img.shields.io/badge/durum-geli%C5%9Ftirme%20a%C5%9Famas%C4%B1nda-orange)

</div>

---

## İzin verdin ve unuttun

"Ekran kaydına izin ver." "Erişilebilirlik izni gerekiyor." "Girişte açılsın mı?"

Her gün onlarca kez "Tamam"a basıyoruz. Peki hangi uygulamaya ne zaman ne izni verdin?
Hangisi kendini sessizce başlangıca ekledi? macOS bu soruların cevabını sana göstermiyor.

**permwatch gösteriyor.**

<p align="center">
  <img src="docs/images/timeline.png" alt="permwatch zaman çizelgesi" width="900">
</p>

## Bir senaryo

İnternetten ücretsiz bir PDF dönüştürücü indiriyorsun. Açıyorsun, birkaç izin istiyor, "Tamam" diyorsun.
Her şey normal görünüyor.

permwatch ise arka planda şunları görüyor:

| Saat | Ne oldu |
|---|---|
| 13:46 | İndirilen uygulamanın **karantina etiketi silindi**, yani Gatekeeper atlatıldı |
| 13:47 | **İmzasız** bir uygulama İndirilenler'den ilk kez çalıştı |
| 13:48 | Bir dakika içinde hem **Erişilebilirlik** hem **Ekran Kaydı** izni aldı |
| 13:49 | Gizli bir klasördeki bir programı **başlangıca ekledi** |
| 03:12 | Gece yarısı, sen uyurken **o gizli program çalıştı** |

Tek tek bakınca masum görünen bu adımlar, birlikte bakınca tanıdık bir saldırı zinciri oluşturuyor.
permwatch zinciri birleştirir ve sana tek bir net uyarı gösterir.

<p align="center">
  <img src="docs/images/alert.png" alt="permwatch bildirimi ve menü çubuğu" width="900">
</p>

## Neler yapar

- 🕒 **Zaman çizelgesi:** Her izin değişikliği, her yeni başlangıç öğesi, tarihi ve sorumlusuyla birlikte
- 🚨 **Akıllı uyarılar:** İmzasız uygulamalar, gece yarısı etkinlikleri, Gatekeeper atlatma denemeleri
- 🔍 **Uygulama görünümü:** Bir uygulamanın sahip olduğu bütün izinler tek bir kartta
- 🧬 **İmza kontrolü:** Apple mı, tanınmış bir geliştirici mi, yoksa kimliği belirsiz bir kaynak mı?
- 📍 **Menü çubuğunda:** Göze batmadan çalışır, gerektiğinde konuşur

<p align="center">
  <img src="docs/images/apps.png" alt="permwatch uygulama görünümü" width="900">
</p>

## Gizliliğin sende kalır

permwatch **hiçbir veriyi dışarı göndermez.** Analytics, hesap ya da bulut yok.
Bütün kayıtlar senin Mac'inde kalır. Bir gizlilik aracının başka türlü olmasını zaten beklemezdin.

## Nasıl çalışır

permwatch, Apple'ın güvenlik yazılımları için sunduğu resmi **Endpoint Security** altyapısını kullanır.
Çekirdek C ile yazılmıştır, yalnızca **gözlemler** ve hiçbir zaman sistemin işleyişine müdahale etmez.

## Durum

permwatch aktif geliştirme aşamasında.

- ✅ Olayları yakalayan çekirdek motor (komut satırı)
- ⏳ Apple Endpoint Security izni: başvuru yapıldı, inceleniyor
- 🛠 macOS uygulaması ve arayüz: tasarım aşamasında

> Yukarıdaki görseller tasarım önizlemesidir. Senaryodaki "Konvertix" uygulaması temsilidir.

Geliştiriciysen ve çekirdeği denemek istiyorsan: **[Geliştirici rehberi →](docs/GELISTIRME.md)**

---

<div align="center">
<sub>macOS güvenliğini merak eden biri tarafından, meraklılar için yapıldı.</sub>
</div>
