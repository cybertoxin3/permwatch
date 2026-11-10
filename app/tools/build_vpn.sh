#!/bin/zsh
# VPN motorlarını kaynaktan derler (evrensel: Apple Silicon + Intel) → app/vendor/vpn/
#   amneziawg-go  (MIT)      https://github.com/amnezia-vpn/amneziawg-go
#   Xray-core     (MPL-2.0)  https://github.com/XTLS/Xray-core
# Sürümler sabittir; güncellemek için aşağıdaki işlemleri değiştirin.
# Gerekenler: git ve herhangi bir Go; GO_VERSION'daki derleyici kendiliğinden indirilir.
set -euo pipefail
cd "${0:A:h}/.."
AWG_REPO=https://github.com/amnezia-vpn/amneziawg-go
AWG_REV=b5928efb6ca19f0153958460c3d141f04abc5c2e      # v3.1.20260828
XRAY_REPO=https://github.com/XTLS/Xray-core
XRAY_REV=676eaf66f8f05d4d558ee7a74b4736623d3feeb9     # v26.11.9
SRC=$(mktemp -d -t permwatch-vpn)
# Go modül önbelleği salt okunurdur: silmeden önce yazılabilir yap.
trap 'chmod -R u+w "$SRC" 2>/dev/null; rm -rf "$SRC"' EXIT
# Tam sürüm adı: go.mod'daki "go 1.27" satırı tek başına indirilebilir bir araç zinciri adı değildir.
GO_VERSION=go1.27.4
export GOTOOLCHAIN=$GO_VERSION CGO_ENABLED=0 GOPATH="$SRC/gopath" GOCACHE="$SRC/gocache"
fetch() { git init -q "$SRC/$1"; git -C "$SRC/$1" fetch -q --depth 1 "$2" "$3"; git -C "$SRC/$1" checkout -q FETCH_HEAD; }
fetch awg $AWG_REPO $AWG_REV
fetch xray $XRAY_REPO $XRAY_REV
mkdir -p vendor/vpn
for A in arm64 amd64; do
    (cd "$SRC/awg" && GOOS=darwin GOARCH=$A go build -trimpath -ldflags "-s -w -buildid=" -o "$SRC/out/amneziawg-go-$A" .)
    (cd "$SRC/xray" && GOOS=darwin GOARCH=$A go build -trimpath -ldflags "-s -w -buildid=" -o "$SRC/out/xray-$A" ./main)
done
for E in amneziawg-go xray; do lipo -create "$SRC/out/$E-arm64" "$SRC/out/$E-amd64" -output vendor/vpn/$E; done
chmod 755 vendor/vpn/*
cp "$SRC/awg/LICENSE" vendor/vpn/LICENSE.amneziawg-go 2>/dev/null || true
cp "$SRC/xray/LICENSE" vendor/vpn/LICENSE.xray 2>/dev/null || true
ls -la vendor/vpn
