# Privacy

permwatch is a privacy tool, so it is strict about your data.

**Nothing about you leaves your Mac.** permwatch has no analytics, no telemetry, no account and no server.

permwatch makes only these requests by itself. Each is a plain download that carries no data about you or your Mac, and each can be turned off in Settings:

- **Update check** (Settings › Check for new versions): once a day it reads the update list (`raw.githubusercontent.com/cybertoxin3/permwatch/main/docs/appcast.xml`) with Sparkle. If there is a new version and you accept it (or turned on automatic installation), it downloads the release from GitHub. Updates are only installed if they are notarized by Apple and signed with permwatch's update key. Sparkle's optional system profile is turned off.
- **Threat lists and extra signatures** (Settings › Malicious server check and extra signatures): once a day it downloads the list of known malicious domains (`malware-filter.gitlab.io`, a mirror of abuse.ch URLhaus), the list of known malicious IP addresses (`feodotracker.abuse.ch`) and Elastic Security's macOS malware rules (`api.github.com` and `raw.githubusercontent.com`). Matching against these lists happens on your Mac; no address you visit is ever sent anywhere.

The malware scan and real-time protection run entirely on your Mac with Apple's XProtect signatures and the downloaded Elastic rules; no file or hash is uploaded.

**DNS answers (administrator mode only).** To know which domain a connection belongs to, the administrator helper reads DNS answers on this Mac while the malicious server check is on. It keeps only the latest few thousand "address → domain" pairs, in memory and in `root.json` (readable only by your user account). Nothing is written to a log and nothing leaves your Mac. Turning the check off stops it.

**Screen Share Guard.** To know which app is recording or sharing your screen, permwatch reads the macOS system log entries of the screen-capture service (`replayd`), using macOS's own `log` tool with a narrow filter; for older remote-control apps it also looks at how much data they send (`nettop`). While a share you haven't marked "I know this" is running, and only then, it checks whether macOS's secure keyboard input is on (which happens when a password field is focused) and which app turned it on; it never sees what you type. In the same situation it reads the address of the active browser tab (Safari, Chrome, Brave, Edge, Arc, Opera, Vivaldi) to recognise banking and payment sites; macOS asks your permission once per browser. Nothing is recorded except the warnings themselves (time, app name, what triggered it, actions taken), which are kept in `~/Library/Application Support/permwatch/share-incidents.json` and can be deleted in the app.

**Fake site protection.** Once a second, permwatch asks macOS whether a password field is focused (secure keyboard input). Only at that moment does it read the address of the active browser tab and compare it with local rules and the downloaded phishing list. Nothing is sent anywhere.

**Network check.** Reads the Wi-Fi security type, the default gateway and the ARP table with macOS's own tools. "Scan network" sends one small UDP packet to each address in your local /24 network; nothing else is sent.

**Password vault.** Stored only in `~/Library/Application Support/permwatch/vault.pwv`, encrypted with AES-256-GCM. The key is derived from your master password with PBKDF2-SHA256 (600,000 rounds); the master password is never stored. With Touch ID on, the vault key is also kept in your login Keychain and used only after Touch ID or your Mac password. "Leaked?" sends only the first 5 characters of the password's SHA-1 hash to Have I Been Pwned (k-anonymity), and only when you press it.

**VPN.** Connection profiles (including their private keys) are kept in your login Keychain. To connect, the administrator helper starts the bundled AmneziaWG or Xray engine, sets routes and DNS, and restores DNS when you disconnect. permwatch keeps no traffic logs. When you report a VPN payment, your mail app opens a message to the developer with the coin, transaction ID and the contact address you typed; nothing is sent until you press send.

**Quarantine.** Quarantined files are kept in `~/Library/Application Support/permwatch/Quarantine` with execution permissions removed, until you restore or delete them.

**Report a Problem** (Help menu and Settings) opens a message in your own mail app, addressed to the developer, with technical details already filled in: permwatch version, Mac model and chip, memory, free disk space, macOS version, language and region, security settings (SIP, Gatekeeper, FileVault, firewall), which permwatch permissions and protections are on, signature counts, and the date of the last scan. It never includes your user name, computer name, serial number, file names or browsing data. You see the full text before anything is sent, you can edit it, and nothing is sent unless you press Send in your mail app.

The only exception is one you trigger yourself. **"Check with VirusTotal"** opens your browser at `virustotal.com/gui/file/<SHA-256>`. Only the file's hash is in the address; the file itself is never uploaded.

## What is stored on your Mac

| What | Where | Who can read it |
|---|---|---|
| Settings, trusted apps, last scan snapshot | `~/Library/Application Support/permwatch/`, app preferences | your user account |
| Administrator-mode data (process list, connections, login items) | `/Library/Application Support/permwatch/root.json` | your user account only (0600) |
| Packet capture of the current session | `capture.pcap` in one of the folders above | your user account only (0600) |
| Saved captures (only if you choose a folder) | the folder you chose | your user account only (0600) |

**Packet captures are saved in full and nothing is masked.** That includes the data inside packets, so a capture can contain passwords that some app sent without encryption. Capture files are readable only by your user account (0600). Keep that in mind before you send a capture to someone.

Packet capture always runs as root through the administrator helper (Apple's PKTAP), so every packet is recorded with the process that sent it.

While administrator mode is capturing, a temporary live file (`packets.jsonl`) holds packet summaries. It is deleted when the capture stops.

## Permissions permwatch asks for

- **Full Disk Access:** to read macOS's permission database and to check downloads in every folder. permwatch only reads; it never changes your files.
- **Administrator password (optional):** to start the read-only helper. The helper takes no commands, verifies its own signature before it runs, and stops when permwatch quits.
- **Terminal:** the built-in terminal runs your own shell as your user. Like any program started by permwatch, it inherits permwatch's Full Disk Access, so commands run there can read every file. It never runs as root; `sudo` asks for your password as usual.
- **Notifications:** to tell you about new findings.
- **Automation (Finder):** only when you uninstall an app and macOS can't move it to the Trash directly.
