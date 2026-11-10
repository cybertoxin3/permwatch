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
NATIVE=$(uname -m)
# Yayın derlemesi (PERMWATCH_RELEASE=1) ya da UNIVERSAL=1: Apple Silicon + Intel tek pakette.
if [[ -n "${ARCHS:-}" ]]; then :
elif [[ "${PERMWATCH_RELEASE:-0}" == 1 || "${UNIVERSAL:-0}" == 1 ]]; then ARCHS="arm64 x86_64"
else ARCHS=$NATIVE; fi
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

ST_SRC=(vendor/SwiftTerm/Sources/**/*.swift)
ST_KEY=$(cat "${ST_SRC[@]}" | shasum | cut -c1-16)
Y_KEY=$(cat vendor/yara/libyara/**/*.(c|h) vendor/yara/build_libyara.sh | shasum | cut -c1-16)
for ARCH in ${=ARCHS}; do
    # SwiftTerm (vendor/, MIT): terminal bölümü. Mimari başına önbellekli statik modül.
    ST_DIR=build/.swiftterm/$ARCH-$ST_KEY
    if [[ ! -f "$ST_DIR/libSwiftTerm.a" ]]; then
        echo "SwiftTerm derleniyor ($ARCH, bir kez, yaklaşık 1 dakika)…"
        rm -rf build/.swiftterm/$ARCH-*(N); mkdir -p "$ST_DIR"
        swiftc -parse-as-library -O -target "$ARCH-apple-macos14" -module-name SwiftTerm -emit-library -static \
            -emit-module -emit-module-path "$ST_DIR/SwiftTerm.swiftmodule" "${ST_SRC[@]}" -o "$ST_DIR/libSwiftTerm.a"
    fi
    # YARA (vendor/, BSD-3): zararlı taraması. Mimari başına önbellekli statik kütüphane.
    Y_DIR=build/.yara/$ARCH-$Y_KEY
    if [[ ! -f "$Y_DIR/libyara.a" ]]; then
        echo "libyara derleniyor ($ARCH, bir kez)…"
        rm -rf build/.yara/$ARCH-*(N); mkdir -p "$Y_DIR"
        vendor/yara/build_libyara.sh "$PWD/vendor/yara" "$PWD/$Y_DIR" "$ARCH"
    fi
    mkdir -p "$WORK/$ARCH"
    # shared/: paket yakalama motoru (libpcap), hem uygulamaya hem yardımcıya derlenir.
    swiftc -parse-as-library -O -target "$ARCH-apple-macos14" -import-objc-header shared/bridge-app.h \
        -Xcc -I"vendor/yara/libyara/include" -L "$Y_DIR" -lyara \
        -I "$ST_DIR" -L "$ST_DIR" -lSwiftTerm \
        -F vendor/Sparkle -framework Sparkle -Xlinker -rpath -Xlinker @executable_path/../Frameworks \
        Sources/*.swift shared/*.swift -lpcap -o "$WORK/$ARCH/permwatch"
    # Yönetici modu yardımcısı (ayrı, küçük, girdisiz bir program)
    swiftc -O -target "$ARCH-apple-macos14" -import-objc-header shared/bridge.h \
        helper/main.swift shared/*.swift -lpcap -o "$WORK/$ARCH/permwatch-root"
done
for B in permwatch permwatch-root; do
    lipo -create $(for a in ${=ARCHS}; do print -r -- "$WORK/$a/$B"; done) -output "$APP/Contents/MacOS/$B"
done
# Koruma servisi (geliştirme) yalnızca bu Mac'in mimarisinde.
ARCH=$NATIVE
Y_DIR=build/.yara/$NATIVE-$Y_KEY
if [[ ! -f "$Y_DIR/libyara.a" ]]; then mkdir -p "$Y_DIR"; vendor/yara/build_libyara.sh "$PWD/vendor/yara" "$PWD/$Y_DIR" "$NATIVE"; fi
# Sparkle (vendor/, MIT): güncellemeler (evrensel). Korumalı (sandbox) olmayan uygulamada XPC servisleri gerekmez.
mkdir -p "$APP/Contents/Frameworks"
ditto --norsrc --noextattr --noacl vendor/Sparkle/Sparkle.framework "$APP/Contents/Frameworks/Sparkle.framework"
xattr -cr "$APP/Contents/Frameworks/Sparkle.framework"
rm -rf "$APP/Contents/Frameworks/Sparkle.framework/XPCServices" "$APP/Contents/Frameworks/Sparkle.framework/Versions/B/XPCServices"

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

# Güncelleme listesi ve açık anahtar (gizli anahtar yalnızca geliştiricinin Anahtar Zinciri'nde).
# Anahtar dosyası yoksa Sparkle kapalı kalır; uygulama yalnızca yeni sürüm olduğunu haber verir.
SPARKLE_KEYS=""
if [[ -f sparkle-public-key.txt ]]; then
    SPARKLE_KEYS="<key>SUFeedURL</key><string>https://raw.githubusercontent.com/cybertoxin3/permwatch/main/docs/appcast.xml</string>
    <key>SUPublicEDKey</key><string>$(tr -d ' \n' < sparkle-public-key.txt)</string>
    <key>SUEnableAutomaticChecks</key><true/>
    <key>SUScheduledCheckInterval</key><integer>86400</integer>
    <key>SUEnableSystemProfiling</key><false/>"
fi
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
    <key>CFBundleShortVersionString</key><string>${PERMWATCH_VERSION:-0.5.0}</string>
    <key>CFBundleVersion</key><string>${PERMWATCH_BUILD:-7}</string>
    <key>CFBundleDevelopmentRegion</key><string>en</string>
    <key>CFBundleLocalizations</key><array>$LOCS</array>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
    <key>NSHighResolutionCapable</key><true/>
    $SPARKLE_KEYS
    <key>NSAppleEventsUsageDescription</key><string>permwatch, kaldırdığın uygulamaları Çöp Sepeti'ne taşımak için Finder'ı kullanır; uzaktan bağlantı açıkken banka sitesine girdiğinde seni uyarmak için tarayıcının etkin sekmesinin adresine bakar. / permwatch uses Finder to move apps you uninstall to the Trash and, while someone is connected to your Mac remotely, checks the address of the active browser tab to warn you before you use a bank site.</string>
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
# Sparkle içten dışa: yardımcı programlar, sonra çerçeve.
SF="$APP/Contents/Frameworks/Sparkle.framework/Versions/B"
codesign --force --sign "$SIGN" "${OPTS[@]}" "$SF/Autoupdate"
codesign --force --sign "$SIGN" "${OPTS[@]}" "$SF/Updater.app"
codesign --force --sign "$SIGN" "${OPTS[@]}" "$APP/Contents/Frameworks/Sparkle.framework"
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
