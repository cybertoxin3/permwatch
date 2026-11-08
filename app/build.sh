#!/bin/zsh
# permwatch.app'i Xcode olmadan (yalnızca Command Line Tools ile) derler.
# Çıktı: app/build/permwatch.app
set -euo pipefail
cd "${0:A:h}"

# iCloud ile eşitlenen klasörlerde (ör. Masaüstü) sistem dosyalara öznitelik ekler ve
# codesign bunu reddeder; bu yüzden geçici klasörde derleyip sonra kopyalıyoruz.
WORK=$(mktemp -d -t permwatch-build)
trap 'rm -rf "$WORK"' EXIT
APP="$WORK/permwatch.app"
OUT=build/permwatch.app
ARCH=${ARCH:-$(uname -m)}
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# SwiftTerm (vendor/, MIT): terminal bölümü. Ayrı modül olarak derlenir; kaynak değişmedikçe önbellekten.
ST_SRC=(vendor/SwiftTerm/Sources/**/*.swift)
ST_KEY=$(cat "${ST_SRC[@]}" | shasum | cut -c1-16)
ST_DIR=build/.swiftterm/$ARCH-$ST_KEY
if [[ ! -f "$ST_DIR/libSwiftTerm.a" ]]; then
    echo "SwiftTerm derleniyor (bir kez, yaklaşık 1 dakika)…"
    rm -rf build/.swiftterm; mkdir -p "$ST_DIR"
    swiftc -parse-as-library -O -target "$ARCH-apple-macos14" -module-name SwiftTerm -emit-library -static \
        -emit-module -emit-module-path "$ST_DIR/SwiftTerm.swiftmodule" "${ST_SRC[@]}" -o "$ST_DIR/libSwiftTerm.a"
fi

# YARA (vendor/, BSD-3): Apple'ın XProtect imzalarıyla zararlı taraması. Önbellekli statik kütüphane.
Y_KEY=$(cat vendor/yara/libyara/**/*.(c|h) vendor/yara/build_libyara.sh | shasum | cut -c1-16)
Y_DIR=build/.yara/$ARCH-$Y_KEY
if [[ ! -f "$Y_DIR/libyara.a" ]]; then
    echo "libyara derleniyor (bir kez)…"
    rm -rf build/.yara; mkdir -p "$Y_DIR"
    vendor/yara/build_libyara.sh "$PWD/vendor/yara" "$PWD/$Y_DIR" "$ARCH"
fi

# shared/: paket yakalama motoru (libpcap), hem uygulamaya hem yardımcıya derlenir.
swiftc -parse-as-library -O -target "$ARCH-apple-macos14" -import-objc-header shared/bridge-app.h \
    -Xcc -I"vendor/yara/libyara/include" -L "$Y_DIR" -lyara \
    -I "$ST_DIR" -L "$ST_DIR" -lSwiftTerm \
    Sources/*.swift shared/*.swift -lpcap -o "$APP/Contents/MacOS/permwatch"
# Yönetici modu yardımcısı (ayrı, küçük, girdisiz bir program)
swiftc -O -target "$ARCH-apple-macos14" -import-objc-header shared/bridge.h \
    helper/main.swift shared/*.swift -lpcap -o "$APP/Contents/MacOS/permwatch-root"

cp Resources/sample-events.jsonl Resources/AppIcon.icns "$APP/Contents/Resources/"
mkdir -p "$APP/Contents/Resources/rules" && cp -R Resources/rules/elastic "$APP/Contents/Resources/rules/"

# Kalıcı yönetici servisi (SMAppService.daemon): kullanıcı Sistem Ayarları'nda bir kez onaylar.
mkdir -p "$APP/Contents/Library/LaunchDaemons"
cat > "$APP/Contents/Library/LaunchDaemons/com.yusuf.permwatch.root.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.yusuf.permwatch.root</string>
    <key>BundleProgram</key><string>Contents/MacOS/permwatch-root</string>
    <key>ProgramArguments</key><array><string>permwatch-root</string><string>--daemon</string></array>
    <key>AssociatedBundleIdentifiers</key><array><string>com.yusuf.permwatch</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>ProcessType</key><string>Background</string>
</dict>
</plist>
PLIST
python3 -I tools/build_strings.py i18n "$APP/Contents/Resources"

LOCS=$(cd "$APP/Contents/Resources" && ls -d *.lproj | sed 's/\.lproj//' | sed 's/.*/<string>&<\/string>/' | tr -d '\n')
cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key><string>com.yusuf.permwatch</string>
    <key>CFBundleName</key><string>permwatch</string>
    <key>CFBundleDisplayName</key><string>permwatch</string>
    <key>CFBundleExecutable</key><string>permwatch</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>CFBundleShortVersionString</key><string>0.3.0</string>
    <key>CFBundleVersion</key><string>4</string>
    <key>CFBundleDevelopmentRegion</key><string>en</string>
    <key>CFBundleLocalizations</key><array>$LOCS</array>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSAppleEventsUsageDescription</key><string>permwatch, kaldırmak istediğin uygulamaları Çöp Sepeti'ne taşımak için Finder'ı kullanır. / permwatch uses Finder to move apps you uninstall to the Trash.</string>
</dict>
</plist>
EOF

# İmza: macOS izinleri (Tam Disk Erişimi vb.) imzanın kimliğine bağlıdır. Geçici (ad-hoc) imza her
# derlemede değişir ve macOS izni unutur; Developer ID / Apple Development sertifikası varsa onu kullan.
# Elle seçmek için: PERMWATCH_SIGN="Developer ID Application: …" ./build.sh   (geçici imza için: PERMWATCH_SIGN=-)
IDS=$(security find-identity -v -p codesigning 2>/dev/null || true)
pick() { print -r -- "$IDS" | grep -m1 -oE "\"$1: [^\"]+\"" | tr -d '"' || true }
SIGN=${PERMWATCH_SIGN:-$(pick "Developer ID Application")}
SIGN=${SIGN:-$(pick "Apple Development")}
SIGN=${SIGN:--}
# Gerçek sertifikayla: sıkılaştırılmış çalışma ortamı (notarizasyon şartı). Yayın derlemesinde
# (PERMWATCH_RELEASE=1) Apple'ın güvenli zaman damgası da eklenir.
OPTS=()
if [[ "$SIGN" != "-" ]]; then
    OPTS=(--options runtime)
    if [[ "${PERMWATCH_RELEASE:-0}" == 1 ]]; then OPTS+=(--timestamp); else OPTS+=(--timestamp=none); fi
fi
codesign --force --sign "$SIGN" "${OPTS[@]}" --identifier com.yusuf.permwatch.root "$APP/Contents/MacOS/permwatch-root"
# Çalıştırmadan önce engelleme (permwatch-guard, Endpoint Security). Apple'ın dağıtım onayı gelene kadar
# yalnızca geliştirme profiliyle, kayıtlı Mac'lerde çalışır; bu yüzden yayın derlemesine girmez.
GUARD_PROFILE=${PERMWATCH_GUARD_PROFILE:-$HOME/Library/Application Support/permwatch-dev/guard.provisionprofile}
DEV_SIGN=$(pick "Apple Development")
if [[ "${PERMWATCH_RELEASE:-0}" != 1 && -f "$GUARD_PROFILE" && -n "$DEV_SIGN" ]]; then
    G="$APP/Contents/Library/Guard/permwatch-guard.app"
    mkdir -p "$G/Contents/MacOS"
    swiftc -O -target "$ARCH-apple-macos14" -import-objc-header guard/bridge.h -Xcc -I"vendor/yara/libyara/include" \
        -L "$Y_DIR" -lyara guard/main.swift -lEndpointSecurity -lbsm -o "$G/Contents/MacOS/permwatch-guard"
    cat > "$G/Contents/Info.plist" <<GPLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>CFBundleIdentifier</key><string>com.yusuf.permwatch.guard</string>
    <key>CFBundleName</key><string>permwatch-guard</string>
    <key>CFBundleExecutable</key><string>permwatch-guard</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$(/usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" "$APP/Contents/Info.plist")</string>
    <key>CFBundleVersion</key><string>$(/usr/libexec/PlistBuddy -c "Print CFBundleVersion" "$APP/Contents/Info.plist")</string>
    <key>LSUIElement</key><true/>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
</dict></plist>
GPLIST
    cp "$GUARD_PROFILE" "$G/Contents/embedded.provisionprofile"
    TEAM=$(security cms -D -i "$GUARD_PROFILE" | plutil -extract TeamIdentifier.0 raw -)
    cat > "$WORK/guard.entitlements" <<GENT
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>com.apple.application-identifier</key><string>$TEAM.com.yusuf.permwatch.guard</string>
    <key>com.apple.developer.team-identifier</key><string>$TEAM</string>
    <key>com.apple.developer.endpoint-security.client</key><true/>
</dict></plist>
GENT
    codesign --force --sign "$DEV_SIGN" --options runtime --timestamp=none --entitlements "$WORK/guard.entitlements" "$G"
    cat > "$APP/Contents/Library/LaunchDaemons/com.yusuf.permwatch.guard.plist" <<GLD
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>Label</key><string>com.yusuf.permwatch.guard</string>
    <key>BundleProgram</key><string>Contents/Library/Guard/permwatch-guard.app/Contents/MacOS/permwatch-guard</string>
    <key>AssociatedBundleIdentifiers</key><array><string>com.yusuf.permwatch</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
</dict></plist>
GLD
    echo "koruma servisi (Endpoint Security, geliştirme profili): $DEV_SIGN"
fi
codesign --force --sign "$SIGN" "${OPTS[@]}" --entitlements permwatch.entitlements "$APP"
echo "imza: $SIGN"
mkdir -p build
rm -rf "$OUT"
ditto "$APP" "$OUT"
echo "hazır: $(pwd)/$OUT"
