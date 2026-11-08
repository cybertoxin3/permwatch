# Sparkle 2.10.1

Software update framework for macOS, https://sparkle-project.org (MIT, see `LICENSE`).
From the official release `Sparkle-2.10.1.tar.xz`
(SHA-256 1a856d2a9edb8e628de88121d7be04cf0e2167f8641650b78fca00b14244cf27).

- `Sparkle.framework`: embedded in permwatch.app and re-signed with permwatch's certificate by `app/build.sh`.
- `bin/generate_keys`, `bin/sign_update`: create the EdDSA update key (kept in your login keychain, never in this repo)
  and sign release archives (`app/tools/appcast.sh`).
