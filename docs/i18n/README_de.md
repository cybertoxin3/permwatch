<div align="center">

[Türkçe](README_tr.md) · [English](../../README.md) · [Русский](README_ru.md) · **Deutsch** · [Français](README_fr.md) · [Español](README_es.md) · [Português](README_pt.md) · [Italiano](README_it.md) · [Українська](README_uk.md) · [日本語](README_ja.md) · [简体中文](README_zh.md) · [한국어](README_ko.md) · [العربية](README_ar.md)

<img src="../images/icon.png" width="128" alt="permwatch">

# permwatch

**Sieh, worauf jede App auf deinem Mac zugreifen kann.**

Kamera, Mikrofon, Bildschirmaufnahme, Anmeldeobjekte.<br>
permwatch protokolliert jede Änderung an Berechtigungen und warnt dich sofort, wenn etwas verdächtig ist.

[![build](https://github.com/cybertoxin3/permwatch/actions/workflows/build.yml/badge.svg)](https://github.com/cybertoxin3/permwatch/actions/workflows/build.yml)
![macOS](https://img.shields.io/badge/macOS-13%2B-black?logo=apple)
![Status](https://img.shields.io/badge/Status-in%20Entwicklung-orange)

</div>

---

## Erlaubt und vergessen

„Bildschirmaufnahme erlauben.“ „Zugriff auf Bedienungshilfen erforderlich.“ „Beim Anmelden öffnen?“

Wir klicken jeden Tag dutzende Male auf „OK“. Aber welcher App hast du wann welche Berechtigung gegeben?
Welche hat sich still und leise in den Autostart eingetragen? macOS zeigt dir die Antworten nicht.

**permwatch schon.**

<p align="center">
  <img src="../images/timeline_de.png" alt="permwatch Zeitleiste" width="900">
</p>

## Ein Szenario

Du lädst einen kostenlosen PDF-Konverter herunter. Du öffnest ihn, er fragt nach ein paar Berechtigungen, du klickst „OK“.
Alles wirkt normal.

permwatch sieht im Hintergrund dagegen Folgendes:

| Uhrzeit | Was passiert ist |
|---|---|
| 13:46 | Das **Quarantäne-Flag** der heruntergeladenen App **wurde entfernt**, Gatekeeper also umgangen |
| 13:47 | Eine **unsignierte** App startete zum ersten Mal aus dem Downloads-Ordner |
| 13:48 | Innerhalb einer Minute erhielt sie **Bedienungshilfen** und **Bildschirmaufnahme** |
| 13:49 | Sie **trug ein Programm aus einem versteckten Ordner in den Autostart ein** |
| 03:12 | Mitten in der Nacht, während du schliefst, **lief dieses versteckte Programm** |

Einzeln wirkt jeder Schritt harmlos. Zusammen ergeben sie eine bekannte Angriffskette.
permwatch verbindet die Punkte und zeigt dir eine einzige, klare Warnung.

<p align="center">
  <img src="../images/alert_de.png" alt="permwatch Mitteilung und Menüleiste" width="900">
</p>

## Was es kann

- 🕒 **Zeitleiste:** Jede Berechtigungsänderung und jedes neue Startobjekt, mit Datum und verantwortlichem Prozess
- 🚨 **Intelligente Warnungen:** Unsignierte Apps, nächtliche Aktivität, Versuche, Gatekeeper zu umgehen
- 🔍 **App-Ansicht:** Alle Berechtigungen einer App auf einer Karte
- 🧬 **Signaturprüfung:** Apple, ein bekannter Entwickler oder eine unbekannte Quelle?
- 📍 **In der Menüleiste:** Bleibt im Hintergrund und meldet sich, wenn es darauf ankommt

<p align="center">
  <img src="../images/apps_de.png" alt="permwatch App-Ansicht" width="900">
</p>

## Deine Privatsphäre bleibt bei dir

permwatch **sendet keinerlei Daten.** Keine Analysen, kein Konto, keine Cloud.
Alle Aufzeichnungen bleiben auf deinem Mac. Von einem Datenschutz-Tool würdest du nichts anderes erwarten.

## So funktioniert es

permwatch nutzt **Endpoint Security**, Apples offizielle Schnittstelle für Sicherheitssoftware.
Der Kern ist in C geschrieben. Er **beobachtet** nur und greift nie in dein System ein.

## Status

permwatch befindet sich in aktiver Entwicklung.

- ✅ Kern, der Ereignisse erfasst (Kommandozeile)
- ⏳ Endpoint-Security-Berechtigung von Apple: beantragt, in Prüfung
- 🛠 macOS-App und Oberfläche: in Gestaltung

> Die Bilder oben sind Designvorschauen. „Konvertix“ im Szenario ist eine erfundene App.

Entwickler und möchtest den Kern ausprobieren? **[Entwicklerhandbuch (Englisch) →](../GELISTIRME_en.md)**

---

<div align="center">
<sub>Gemacht von jemandem, der sich für macOS-Sicherheit begeistert, für alle Neugierigen.</sub>
</div>
