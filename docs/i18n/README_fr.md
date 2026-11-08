<div align="center">

[Türkçe](README_tr.md) · [English](../../README.md) · [Русский](README_ru.md) · [Deutsch](README_de.md) · **Français** · [Español](README_es.md) · [Português](README_pt.md) · [Italiano](README_it.md) · [Українська](README_uk.md) · [日本語](README_ja.md) · [简体中文](README_zh.md) · [한국어](README_ko.md) · [العربية](README_ar.md)

<img src="../images/icon.png" width="128" alt="permwatch">

# permwatch

**Voyez à quoi chaque app de votre Mac peut accéder.**

Caméra, micro, enregistrement d’écran, éléments d’ouverture.<br>
permwatch garde une trace de chaque changement d’autorisation et vous alerte dès que quelque chose cloche.

[![build](https://github.com/cybertoxin3/permwatch/actions/workflows/build.yml/badge.svg)](https://github.com/cybertoxin3/permwatch/actions/workflows/build.yml)
![macOS](https://img.shields.io/badge/macOS-14%2B-black?logo=apple)
![statut](https://img.shields.io/badge/statut-en%20d%C3%A9veloppement-orange)

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
- 🐞 **Analyse antimalware :** apps, éléments d’ouverture, programmes en cours et téléchargements sont vérifiés avec **les signatures XProtect d’Apple** via le moteur open source YARA. Une analyse rapide prend environ 10 secondes ; les nouveaux téléchargements sont analysés automatiquement.
- 🔐 **Autorisations :** historique de chaque changement, autorisations restantes d’apps supprimées, révocation en un clic, désinstallation.
- 🌐 **Réseau :** quelle app se connecte où, capture de paquets avec noms de processus et explications claires, blocage d’un serveur via le pare-feu intégré de macOS.
- ⬇️ **Téléchargements, 🎙 micro et caméra, ⌨️ terminal** avec des commandes de sécurité prêtes à l’emploi.

<p align="center">
  <img src="../images/apps_fr.png" alt="Vue des apps dans permwatch" width="900">
</p>

## Ce qu’il n’est pas

permwatch **n’est pas un antivirus complet.** Il détecte les malwares connus des signatures d’Apple mais ne bloque pas les programmes en temps réel. Les règles sont heuristiques : fausses alertes et oublis restent possibles.

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

- ✅ App macOS en 13 langues, notarisée par Apple.
- ⏳ Autorisation Endpoint Security d’Apple : en cours d’examen.

Développeur et envie d’essayer le moteur ? **[Guide du développeur (en anglais) →](../GELISTIRME_en.md)**

---

<div align="center">
<sub>Fait par un passionné de sécurité macOS, pour les curieux.</sub>
</div>
