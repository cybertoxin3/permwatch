<div align="center">

[Türkçe](README_tr.md) · [English](../../README.md) · [Русский](README_ru.md) · [Deutsch](README_de.md) · **Français** · [Español](README_es.md) · [Português](README_pt.md) · [Italiano](README_it.md) · [Українська](README_uk.md) · [日本語](README_ja.md) · [简体中文](README_zh.md) · [한국어](README_ko.md) · [العربية](README_ar.md)

<img src="../images/icon.png" width="128" alt="permwatch">

# permwatch

**Voyez à quoi chaque app de votre Mac peut accéder.**

Caméra, micro, enregistrement d’écran, éléments d’ouverture.<br>
permwatch garde une trace de chaque changement d’autorisation et vous alerte dès que quelque chose cloche.

[![build](https://github.com/cybertoxin3/permwatch/actions/workflows/build.yml/badge.svg)](https://github.com/cybertoxin3/permwatch/actions/workflows/build.yml)
![macOS](https://img.shields.io/badge/macOS-14%2B-black?logo=apple)
[![version](https://img.shields.io/github/v/release/cybertoxin3/permwatch?label=version)](https://github.com/cybertoxin3/permwatch/releases/latest)


[![Télécharger pour macOS](https://img.shields.io/badge/%E2%AC%87%EF%B8%8F_T%C3%A9l%C3%A9charger%20pour%20macOS-0A84FF?style=for-the-badge&logo=apple&logoColor=white)](https://github.com/cybertoxin3/permwatch/releases/latest)

<sub>Apple Silicon et Intel · macOS 14 ou plus récent · gratuit</sub><br>
<sub>Ouvre le zip et glisse **permwatch** dans le dossier Applications.</sub>

</div>

---

## Vous avez autorisé, puis oublié

« Autoriser l’enregistrement de l’écran. » « Accès à l’accessibilité requis. » « Ouvrir à la connexion ? »

Nous cliquons sur « OK » des dizaines de fois par jour. Mais quelle app a reçu quelle autorisation, et quand ?
Laquelle s’est discrètement ajoutée au démarrage ? macOS ne vous donne pas ces réponses.

**permwatch, si.**

<p align="center">
  <img src="../images/timeline_fr.png" alt="Chronologie de permwatch" width="900">
</p>

## Un scénario

Vous téléchargez un convertisseur PDF gratuit. Vous l’ouvrez, il demande quelques autorisations, vous cliquez sur « OK ».
Tout semble normal.

Pendant ce temps, permwatch voit ceci en arrière-plan :

| Heure | Ce qui s’est passé |
|---|---|
| 13:46 | Le **marqueur de quarantaine** de l’app téléchargée **a été supprimé** : Gatekeeper est contourné |
| 13:47 | Une app **non signée** s’est lancée pour la première fois depuis Téléchargements |
| 13:48 | En une minute, elle a obtenu l’**accessibilité** et l’**enregistrement de l’écran** |
| 13:49 | Elle a **ajouté au démarrage un programme caché dans un dossier invisible** |
| 03:12 | En pleine nuit, pendant que vous dormiez, **ce programme caché s’est exécuté** |

Pris un par un, ces gestes semblent anodins. Ensemble, ils forment une chaîne d’attaque bien connue.
permwatch relie les points et vous montre une seule alerte claire.

<p align="center">
  <img src="../images/alert_fr.png" alt="Notification et barre des menus de permwatch" width="900">
</p>

## Ce qu’il fait

- 🛡 **Vue d’ensemble et vérification en un clic :** un verdict clair dès l’ouverture. « Vérifier mon Mac » lance l’analyse antimalware et contrôle le détournement du navigateur, l’interception du trafic (certificats racine, profils, proxy, DNS, VPN), les fuites VPN, l’accès à distance et les combinaisons d’autorisations typiques des logiciels espions. Chaque problème a un bouton de correction.
- 🐞 **Analyse antimalware :** Vérifie tes apps, éléments d'ouverture, programmes en cours et téléchargements avec les **signatures XProtect d'Apple** et les **règles ouvertes de logiciels malveillants macOS d'Elastic Security**, grâce au moteur open source YARA. Une analyse rapide prend environ 10 secondes. Ce qui est trouvé peut être mis en quarantaine avec les éléments d'ouverture qui le lancent : il ne peut plus s'exécuter, et tu peux le restaurer en cas de fausse alerte.
- 🛡️ **Protection en temps réel :** Les fichiers nouveaux ou modifiés dans Applications, Téléchargements, les éléments d'ouverture et les dossiers où se cachent les logiciels malveillants sont analysés en quelques secondes. Tes documents sont surveillés contre les rançongiciels (beaucoup de fichiers chiffrés d'un coup) et le programme responsable est suspendu s'il n'est pas signé. Les connexions vers des serveurs figurant sur des listes connues (abuse.ch) sont signalées, et tu décides de les bloquer ou non.
- 🧭 **Simple et à jour :** un court guide de bienvenue, un mode simple qui n'affiche que l'essentiel (le reste en mode avancé), des mises à jour dans l'app avec une barre de progression, et **Aide › Signaler un problème**, qui ouvre un e-mail avec les détails techniques déjà remplis.
- 🔐 **Autorisations :** historique de chaque changement, autorisations restantes d’apps supprimées, révocation en un clic, désinstallation.
- 🌐 **Réseau :** quelle app se connecte où, capture de paquets avec noms de processus et explications claires, blocage d’un serveur via le pare-feu intégré de macOS.
- ⬇️ **Téléchargements, 🎙 micro et caméra, ⌨️ terminal** avec des commandes de sécurité prêtes à l’emploi.

<p align="center">
  <img src="../images/apps_fr.png" alt="Vue des apps dans permwatch" width="900">
</p>

## Ce qu’il n’est pas

permwatch **ne remplace pas un antivirus commercial doté de sa propre équipe de recherche.** Ses signatures viennent d'Apple (XProtect) et d'Elastic Security, ses listes de serveurs d'abuse.ch : il trouve donc ce que ces sources connaissent. La protection en temps réel s'appuie sur les événements du système de fichiers : un nouveau fichier est analysé en quelques secondes, mais un programme ne peut pas être arrêté *avant* son lancement. Il faut pour cela l'autorisation Endpoint Security d'Apple, que nous avons demandée. Les connexions vers des serveurs malveillants connus ne sont jamais bloquées automatiquement ; on te demande d'abord.

Les règles sont heuristiques : elles peuvent déclencher de fausses alertes (par exemple avec des outils de développement) et manquer des logiciels malveillants bien cachés.

## Votre vie privée reste chez vous

permwatch **n’envoie rien vous concernant.** Ni analyses, ni compte, ni cloud. Détails : **[PRIVACY.md](../../PRIVACY.md)**

## Fonctionnement

- Lit la base des autorisations de macOS et les éléments d’ouverture (avec l’accès complet au disque) et surveille les changements.
- Le **mode administrateur** optionnel s’installe comme service système (SMAppService) après une seule approbation ; macOS vérifie la signature.
- La capture de paquets utilise libpcap et PKTAP d’Apple (processus par paquet).
- Un moteur Endpoint Security (C) pour les événements en temps réel est prêt et attend l’autorisation d’Apple.

## Code tiers

- [YARA](https://github.com/VirusTotal/yara) v4.5.8 (BSD-3-Clause)
- [SwiftTerm](https://github.com/migueldeicaza/SwiftTerm) v1.20.0 (MIT)

## État

- ✅ App macOS pour Apple Silicon et Intel : analyse antimalware avec protection en temps réel et quarantaine, protection contre les rançongiciels, contrôle des serveurs malveillants, autorisations, éléments d'ouverture, contrôles du navigateur et de l'accès à distance, réseau et capture de paquets. Les mises à jour arrivent dans l'app. Disponible en 13 langues.
- ⏳ Autorisation Endpoint Security d’Apple : en cours d’examen.

Développeur et envie d’essayer le moteur ? **[Guide du développeur (en anglais) →](../GELISTIRME_en.md)**

## ☕ Tu m'offres un café ?

permwatch est gratuit et open source, sans publicité, compte ni pistage. S'il t'a aidé, un petit don permet de le faire vivre. Envoie chaque crypto uniquement sur le réseau indiqué.

| Crypto | Adresse |
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
<sub>Fait par un passionné de sécurité macOS, pour les curieux.</sub>
</div>
