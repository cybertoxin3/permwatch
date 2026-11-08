# Privacy

permwatch is a privacy tool, so it is strict about your data.

**Nothing leaves your Mac.** permwatch has no analytics, no telemetry, no account and no server. It makes no network requests of its own.

The malware scan runs entirely on your Mac with the XProtect signatures already installed by macOS; no file or hash is uploaded.

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
