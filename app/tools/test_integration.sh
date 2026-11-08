#!/bin/zsh
# Bütünleşik testleri derleyip çalıştırır (önce app/build.sh çalışmış olmalı).
set -euo pipefail
cd "${0:A:h}/.."
YD=(build/.yara/*(N)); ST=(build/.swiftterm/*(N))
[[ -n "${YD[1]:-}" && -n "${ST[1]:-}" ]] || { echo "önce app/build.sh çalıştırın" >&2; exit 1 }
SRC=(Sources/*.swift(N))
SRC=(${SRC:#Sources/App.swift})
swiftc -parse-as-library -import-objc-header shared/bridge-app.h -Xcc -Ivendor/yara/libyara/include \
    -L "${YD[1]}" -lyara -I "${ST[1]}" -L "${ST[1]}" -lSwiftTerm \
    $SRC shared/Packets.swift tests/integration/main.swift -lpcap -o ../tests/test_integration
PERMWATCH_EXTRA_RULES="$PWD/Resources/rules/elastic" ../tests/test_integration
