#!/bin/zsh
# permwatch'ı Apple'a notarize ettirip dağıtıma hazır .zip üretir.
#
# Bir kez (kendi Apple hesabınla, uygulamaya özel parola ile):
#   xcrun notarytool store-credentials permwatch --apple-id <apple-id> --team-id JG79HN7AT3
# Sonra her yayında:
#   app/tools/notarize.sh
set -euo pipefail
cd "${0:A:h}/.."
PROFILE=${NOTARY_PROFILE:-permwatch}
security find-identity -v -p codesigning | grep -q "Developer ID Application" || {
    echo "Developer ID Application sertifikası bulunamadı." >&2; exit 1; }
PERMWATCH_RELEASE=1 ./build.sh
VER=$(/usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" build/permwatch.app/Contents/Info.plist)
ZIP=build/permwatch-$VER.zip
rm -f "$ZIP"
ditto -c -k --keepParent build/permwatch.app "$ZIP"
xcrun notarytool submit "$ZIP" --keychain-profile "$PROFILE" --wait
xcrun stapler staple build/permwatch.app
rm -f "$ZIP"; ditto -c -k --keepParent build/permwatch.app "$ZIP"
spctl --assess --type execute -vv build/permwatch.app
echo "hazır: $(pwd)/$ZIP"
