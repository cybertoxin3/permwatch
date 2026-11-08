#!/bin/zsh
# Sparkle güncelleme listesini (docs/appcast.xml) yeni sürümle günceller.
# Yayın zip'ini Anahtar Zinciri'ndeki EdDSA anahtarıyla imzalar; anahtar hiçbir dosyaya yazılmaz.
#
# Bir kez (anahtarı oluşturur, açık anahtarı app/sparkle-public-key.txt dosyasına yazar):
#   app/tools/appcast.sh --init
# Her yayında (notarize.sh sonunda kendiliğinden çalışır):
#   app/tools/appcast.sh build/permwatch-0.4.0.zip
set -euo pipefail
cd "${0:A:h}/.."
BIN=vendor/Sparkle/bin
if [[ "${1:-}" == "--init" ]]; then
    "$BIN/generate_keys" >/dev/null || true
    "$BIN/generate_keys" -p | tr -d ' \n' > sparkle-public-key.txt
    echo "açık anahtar: $(cat sparkle-public-key.txt)"
    exit 0
fi
ZIP=${1:?zip dosyası}
[[ -f sparkle-public-key.txt ]] || { echo "önce: app/tools/appcast.sh --init" >&2; exit 1; }
PLIST=build/permwatch.app/Contents/Info.plist
VER=$(/usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" "$PLIST")
BUILD=$(/usr/libexec/PlistBuddy -c "Print CFBundleVersion" "$PLIST")
SIG=$("$BIN/sign_update" "$ZIP")   # sparkle:edSignature="…" length="…"
URL="https://github.com/cybertoxin3/permwatch/releases/download/v$VER/$(basename "$ZIP")"
DATE=$(LC_ALL=C date -u "+%a, %d %b %Y %H:%M:%S +0000")
OUT=../docs/appcast.xml
ITEM="        <item>
            <title>permwatch $VER</title>
            <pubDate>$DATE</pubDate>
            <sparkle:version>$BUILD</sparkle:version>
            <sparkle:shortVersionString>$VER</sparkle:shortVersionString>
            <sparkle:minimumSystemVersion>14.0</sparkle:minimumSystemVersion>
            <sparkle:fullReleaseNotesLink>https://github.com/cybertoxin3/permwatch/releases/tag/v$VER</sparkle:fullReleaseNotesLink>
            <enclosure url=\"$URL\" $SIG type=\"application/octet-stream\"/>
        </item>"
# Yalnızca en yeni sürüm listede tutulur (eski sürümler zaten ona güncellenir).
cat > "$OUT" <<XML
<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
    <channel>
        <title>permwatch</title>
        <link>https://github.com/cybertoxin3/permwatch</link>
$ITEM
    </channel>
</rss>
XML
echo "appcast: $OUT ($VER, yapı $BUILD)"
