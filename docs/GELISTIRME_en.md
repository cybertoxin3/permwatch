[Türkçe](GELISTIRME.md) · **English** · [Русский](GELISTIRME_ru.md)

# permwatch

[![build](https://github.com/cybertoxin3/permwatch/actions/workflows/build.yml/badge.svg)](https://github.com/cybertoxin3/permwatch/actions/workflows/build.yml)

An Endpoint Security based permission and persistence auditor for macOS. Currently a CLI core.

| `event` in output | ES event | What it captures | macOS |
|---|---|---|---|
| `exec` | `NOTIFY_EXEC` | Process execution. Apple binaries are filtered out; LOLBins and processes with `DYLD_*` environment variables are always shown | 10.15+ |
| `btm_launch_item_add` | `NOTIFY_BTM_LAUNCH_ITEM_ADD` | New login item, LaunchAgent, LaunchDaemon | 13+ |
| `btm_launch_item_remove` | `NOTIFY_BTM_LAUNCH_ITEM_REMOVE` | Removal of a persistence item (covering tracks) | 13+ |
| `quarantine_removed` | `NOTIFY_DELETEEXTATTR` | Removal of `com.apple.quarantine` (Gatekeeper bypass) | 10.15+ |
| `gatekeeper_user_override` | `NOTIFY_GATEKEEPER_USER_OVERRIDE` | The user clicked "Open Anyway" for a blocked app | 15+ |
| `tcc_modify` | `NOTIFY_TCC_MODIFY` | A TCC permission was granted, revoked or changed (service, app, reason) | 15.4+ |

For every process it records: `pid`, `ppid`, `responsible_pid`, path, `signing_id`, `team_id`,
`signature` (`apple` / `developer` / `adhoc` / `unsigned`), raw `cs_flags` and `cdhash`.
You can look up the cdhash on services such as VirusTotal.

Output is JSON Lines, one event per line. Invalid UTF-8 bytes are written as `�`,
so `jq` never fails on a line.

### Why not `eslogger`?

`eslogger`, shipped with macOS 13+, prints the same events as raw JSON. permwatch adds:
a noise filter (platform binaries are dropped but LOLBins are kept), xattr events reduced to
quarantine removal only, `DYLD_*` injection detection, a simplified schema, and the storage,
rule and UI layers on the roadmap. To validate, compare the output with `eslogger`:

```sh
sudo eslogger btm_launch_item_add tcc_modify | jq .
```

## macOS app

The SwiftUI interface lives in `app/`. No Xcode needed, Command Line Tools are enough:

```sh
make app                          # app/build/permwatch.app
open app/build/permwatch.app
```

- The app opens with demo data. **File → Open Event Log…** opens an `events.jsonl` written by
  the CLI; the app follows the file as it grows and sends a notification for high-risk events.
- The interface follows the system language (13 languages). Translations live in
  `app/i18n/<lang>.tsv`; the build checks that every language has every key and placeholder.
- The rule engine is in `app/Sources/Analyzer.swift`.

## Build and test

```sh
make            # builds and ad-hoc signs with the entitlement
make test       # JSON escape unit tests (no ES needed, runs on any Mac)
```

## Why doesn't it run on my main Mac?

`com.apple.developer.endpoint-security.client` is a restricted entitlement. With SIP enabled,
AMFI kills an ad-hoc signed binary that carries it (exit 137 / SIGKILL). There are two options:

1. **For testing:** a macOS VM with SIP and AMFI disabled (see below).
2. **For distribution:** request the ES entitlement from Apple, then sign with Developer ID
   and notarize. (Request submitted, under review.)

## VM test environment (Apple Silicon, UTM)

1. Install UTM and create a VM with "Virtualize → macOS" (use macOS 15.4+ so TCC_MODIFY works).
2. Boot the VM into recovery mode (in UTM, right-click the VM → *Boot into Recovery Mode*).
3. In the recovery Terminal:
   ```sh
   csrutil disable
   ```
4. After a normal boot, inside the VM:
   ```sh
   sudo nvram boot-args="amfi_get_out_of_my_way=1"
   sudo reboot
   ```
5. Give Terminal **Full Disk Access** (System Settings → Privacy & Security).
6. Copy the project into the VM, run `xcode-select --install`, then `make && sudo ./permwatch`.

> ⚠️ These settings seriously weaken the VM's security. Don't do this on your main machine.
> Run malware samples only inside this VM, and take a snapshot first.

## Triggering events

```sh
# Terminal 1
sudo ./permwatch | tee events.jsonl | jq .

# Terminal 2 (without sudo)
./tests/trigger.sh
```

`trigger.sh` harmlessly does the following: runs LOLBins (`osascript`, `curl`), execs with
`DYLD_INSERT_LIBRARIES`, adds and removes a quarantine flag, loads and unloads a test LaunchAgent.
It also explains how to trigger the TCC and Gatekeeper events by hand.

## Roadmap

- [x] ES client: EXEC, BTM add/remove, TCC_MODIFY, quarantine removal, Gatekeeper override
- [x] LOLBin allowlist, `DYLD_*` detection, ad-hoc signature distinction, cdhash
- [x] JSON escape unit tests, GitHub Actions build
- [ ] Sensitive file access: `NOTIFY_OPEN` with inverted muting on a separate `es_client`
      (LaunchAgents, TCC.db, Keychains, `~/.zshrc`, browser cookies)
- [ ] Injection: `NOTIFY_GET_TASK`, `NOTIFY_REMOTE_THREAD_CREATE`
- [ ] Privilege and remote access: `NOTIFY_SUDO`, `NOTIFY_AUTHORIZATION_PETITION`,
      `NOTIFY_SCREENSHARING_ATTACH`, `NOTIFY_OPENSSH_LOGIN`, `NOTIFY_XP_MALWARE_DETECTED`,
      `NOTIFY_PROFILE_ADD`
- [ ] Process ancestry (`Safari → zsh → curl → osascript`)
- [ ] JSON rule file (Sigma-like) and SQLite storage
- [ ] System Extension + XPC + SwiftUI interface
- [ ] Lite edition: microphone history via CoreAudio process objects (App Store)
