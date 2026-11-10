<div align="center">

[Türkçe](docs/i18n/README_tr.md) · **English** · [Русский](docs/i18n/README_ru.md) · [Deutsch](docs/i18n/README_de.md) · [Français](docs/i18n/README_fr.md) · [Español](docs/i18n/README_es.md) · [Português](docs/i18n/README_pt.md) · [Italiano](docs/i18n/README_it.md) · [Українська](docs/i18n/README_uk.md) · [日本語](docs/i18n/README_ja.md) · [简体中文](docs/i18n/README_zh.md) · [한국어](docs/i18n/README_ko.md) · [العربية](docs/i18n/README_ar.md)

<img src="docs/images/icon.png" width="128" alt="permwatch">

# permwatch

**See what every app on your Mac can access.**

Camera, microphone, screen recording, login items.<br>
permwatch keeps a record of every permission change and alerts you the moment something looks off.

[![build](https://github.com/cybertoxin3/permwatch/actions/workflows/build.yml/badge.svg)](https://github.com/cybertoxin3/permwatch/actions/workflows/build.yml)
![macOS](https://img.shields.io/badge/macOS-14%2B-black?logo=apple)
[![version](https://img.shields.io/github/v/release/cybertoxin3/permwatch?label=version)](https://github.com/cybertoxin3/permwatch/releases/latest)


[![Download for macOS](https://img.shields.io/badge/%E2%AC%87%EF%B8%8F_Download%20for%20macOS-0A84FF?style=for-the-badge&logo=apple&logoColor=white)](https://github.com/cybertoxin3/permwatch/releases/latest)

<sub>Apple Silicon & Intel · macOS 14 or later · free</sub><br>
<sub>Open the zip and drag **permwatch** to your Applications folder.</sub>

</div>
 
---

## 🖥️ Knows who is watching your screen

Zoom, Teams, Meet, Discord, AnyDesk, a screen recorder: whatever is recording or sharing your screen, permwatch names it in a small indicator at the top of the screen. It reads this from macOS itself, so it works for any app without a list.

It stays out of the way: joining a class or a meeting is unaffected. But if a share you haven't marked "I know this" is running and you start typing into a **password field** (on any site or app), or open a banking, payment or government site, a full-screen warning stops you before the other side sees your details. One button stops the share; afterwards permwatch tells you what to do.

<p align="center">
  <img src="docs/images/share_en.png" alt="permwatch screen share warning" width="760">
</p>

## You clicked "Allow" and forgot

"Allow screen recording." "Accessibility access required." "Open at login?"

We click "OK" dozens of times a day. But which app did you give which permission, and when?
Which one quietly added itself to startup? macOS doesn't show you the answers.

**permwatch does.**

<p align="center">
  <img src="docs/images/timeline_en.png" alt="permwatch timeline" width="900">
</p>

## A scenario

You download a free PDF converter. You open it, it asks for a few permissions, you click "OK".
Everything looks normal.

Meanwhile, permwatch sees this in the background:

| Time | What happened |
|---|---|
| 13:46 | The downloaded app's **quarantine flag was removed**, bypassing Gatekeeper |
| 13:47 | An **unsigned** app ran from Downloads for the first time |
| 13:48 | Within a minute it got both **Accessibility** and **Screen Recording** access |
| 13:49 | It **added a program from a hidden folder to startup** |
| 03:12 | At midnight, while you were asleep, **that hidden program ran** |

Each step looks harmless on its own. Put together, they form a familiar attack chain.
permwatch connects the dots and gives you one clear alert.

<p align="center">
  <img src="docs/images/alert_en.png" alt="permwatch notification and menu bar" width="900">
</p>

## What it does

- 🐞 **Malware scan:** Checks your apps, login items, running programs and downloads with **Apple's XProtect signatures** and **Elastic Security's open macOS malware rules**, using the open-source YARA engine. A quick scan takes about 10 seconds. Anything found can be quarantined together with the login items that start it: it can no longer run, and you can restore it if it was a false alarm.
- 🛡️ **Real-time protection:** New or changed files in Applications, Downloads, login items and the folders where malware hides are scanned within seconds. Your documents are watched for ransomware (many files suddenly encrypted), and the responsible program is paused if it is unsigned. Connections to servers on known malware lists (abuse.ch) are flagged, and you decide whether to block them.
- 🧭 **Simple and up to date:** a short welcome guide, a simple mode that shows only what most people need (Advanced mode for the rest), updates that arrive inside the app with a progress bar, and **Help › Report a Problem**, which opens an email with the technical details already filled in.
- 🛡 **Overview and one-click check:** Opens with a clear verdict. "Check My Mac" runs the malware scan and checks for browser hijacking (extensions that can read every site, forced browser policies, changed search engine or start page), traffic interception (trusted root certificates, configuration profiles, proxies, unknown DNS, VPN configurations), remote access (Screen Sharing, SSH, TeamViewer/AnyDesk/ToDesk-style tools), VPN and DNS leaks, Safari extensions and spyware-like permission combinations. Every finding has a fix button.
- 💡 **Recommendations:** One screen that explains every finding in plain language and offers a one-click fix. It finds permissions left behind by deleted apps and permissions in apps you haven't opened for months.
- 🕒 **Timeline:** Every permission change and every new startup item, with its date and the process responsible
- 🚨 **Alerts:** Unsigned startup programs, suspicious permission patterns, Gatekeeper bypasses, and a small pop-up at the top of the screen when something new appears
- 🔍 **Apps:** All the permissions an app holds, on a single card. Revoke a permission or move the app to the Trash.
- 🧠 **Running apps:** A task manager that flags programs running from odd places, pretending to be system processes, or whose file was deleted
- 🌐 **Network:** Which app is connected where, with warnings for unsigned programs
- 📦 **Packet capture:** Like Wireshark, but every packet shows the app that sent it and a plain-language explanation. It spots trackers, unencrypted connections and passwords sent in clear text. Captures are saved as .pcap files you can open in Wireshark. Any server can be blocked with one click using the built-in macOS firewall.
- ⬇️ **Downloads:** Checks downloaded apps and installers anywhere on your Mac, including USB disks, with Gatekeeper
- 🎙 **Microphone and camera:** Who is using them right now, and a history
- ⌨️ **Terminal:** A real terminal inside the app (tabs, colours, full-screen programs) with a menu of ready-made security commands

<p align="center">
  <img src="docs/images/scan_en.png" alt="permwatch malware scan" width="900">
</p>

<p align="center">
  <img src="docs/images/apps_en.png" alt="permwatch app view" width="900">
</p>

## What it is not

permwatch is **not a replacement for a commercial antivirus with its own research team.** Its signatures come from Apple (XProtect) and Elastic Security and its server lists from abuse.ch, so it finds what these sources know. Real-time protection works with file system events: a new file is scanned within seconds, but a program cannot be stopped *before* it starts. That needs Apple's Endpoint Security permission, which we have applied for. Connections to known malicious servers are never blocked automatically; you are asked first.

The rules are heuristics: they can raise false alarms (for example with developer tools) and can miss well-hidden malware.

## Your privacy stays with you

permwatch **sends no data anywhere.** No analytics, no account, no cloud. Details: **[PRIVACY.md](PRIVACY.md)**

## How it works

- Reads macOS's permission database and startup items (with Full Disk Access) and watches them for changes
- Optional **administrator mode** installs a small helper as a system service (SMAppService) after a one-time approval in System Settings; macOS verifies its signature. It only works while permwatch is open and takes no commands; the only input it reads is a list of IP addresses to block, which it validates.
- Packet capture uses libpcap. With administrator mode it uses Apple's PKTAP, which attaches the sending process to each packet.
- An Endpoint Security engine (C) for real-time events is ready and waiting for Apple's entitlement.

## Third-party code

- [YARA](https://github.com/VirusTotal/yara) v4.5.8 by VirusTotal (BSD-3-Clause), used to run Apple’s XProtect signatures. Vendored in `app/vendor/yara`.
- [SwiftTerm](https://github.com/migueldeicaza/SwiftTerm) v1.20.0 by Miguel de Icaza (MIT), used for the terminal. Vendored in `app/vendor/SwiftTerm`.
- [Sparkle](https://sparkle-project.org) 2.10.1 (MIT), used for signed automatic updates. Vendored in `app/vendor/Sparkle`.
- macOS malware rules from [Elastic Security protections-artifacts](https://github.com/elastic/protections-artifacts) (Elastic License 2.0). A copy ships in `app/Resources/rules/elastic` and is refreshed daily.
- Malicious server lists: [URLhaus](https://urlhaus.abuse.ch) via [malware-filter](https://gitlab.com/malware-filter/urlhaus-filter) and [Feodo Tracker](https://feodotracker.abuse.ch) by abuse.ch (CC0), downloaded daily.
- Phishing site list: [phishing-filter](https://gitlab.com/malware-filter/phishing-filter) (CC BY-SA 4.0), built from [OpenPhish](https://openphish.com), [IPThreat](https://ipthreat.net) and [PhishTank](https://phishtank.org), downloaded daily.
- VPN engines: [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) (MIT) and [Xray-core](https://github.com/XTLS/Xray-core) (MPL-2.0), built from the pinned source revisions in `app/tools/build_vpn.sh` and shipped unmodified in `Contents/Resources/vpn`.

## Status

- ✅ macOS app for Apple Silicon and Intel: malware scan with real-time protection and quarantine, ransomware protection, malicious-server check, permissions, startup items, browser and remote-access checks, network and packet capture. Updates arrive inside the app. Available in 13 languages.
- ⏳ Apple Endpoint Security entitlement: requested, under review
- ✅ Notarized by Apple

Developer and want to try the core? **[Developer guide →](docs/GELISTIRME_en.md)**

## ☕ Buy me a coffee?

permwatch is free and open source, with no ads, accounts or tracking. If it helped you, a small donation keeps it going. Please send each coin only on the network shown.

| Coin | Address |
|---|---|
| Bitcoin (BTC) · Taproot | `bc1pyuwdr40733dtzkeefj6xu3asnncwa0a67q2q6sw7fuut4zfhx8yqf2ta3l` |
| Bitcoin (BTC) · SegWit | `bc1qevw8l3pwfahysgmxy0vhv2srnk0dcyze7pggq8` |
| Monero (XMR) | `42tsRvBWbPujgVpQdNy6Ba6ovKNcPkxQBKWn1rYcENDpAPTuvQ2ejxCXcUc5KJQTdkHicn4agR7GnYroSUGQLzVhL93KmTt` |
| Ethereum (ERC-20): ETH, USDC, USDT, SHIB, LINK, UNI | `0xCD9ab39db50A830e157776a97bc9Ae21811e3177` |
| Litecoin (LTC) · SegWit | `ltc1qx40ryzy34vf5977aq5uk3rpqm7err5jvf7gcwl` |
| Litecoin (LTC) · Legacy | `LV6kxUc84QoHq7zGZBz1T38vwdcAXQPxR1` |
| Dogecoin (DOGE) | `DTtZ7oJELg9hs43o1g97qVM676H46XorAT` |
| Solana (SOL) | `5uwHKnCMFbFpob2ssypd69svUFCYZQePCwZcQfELckAD` |
| Xelis (XEL) | `xel:h2mt8pc2059rgq3x67xhndqfm8xukrn49zx2la7qmjqnwhgftc4qqasdzay` |
| Banano (BAN) | `ban_1teuphtrxw6rtr7ttr7iaxtaspm11wjqhjh6j84twcp6pcbiyb4cgzth9439` |

---

<div align="center">
<sub>Made by someone curious about macOS security, for the curious.</sub>
</div>
