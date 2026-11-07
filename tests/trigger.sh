#!/bin/zsh
# permwatch'ın yakaladığı olayları ZARARSIZ şekilde tetikler.
# Bir terminalde: sudo ./permwatch | jq .
# Diğerinde (sudo OLMADAN, normal kullanıcıyla): ./tests/trigger.sh
set -u
LABEL="com.permwatch.test"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
TMP="$(mktemp -d -t permwatch)"
trap 'rm -rf "$TMP"' EXIT

step() { print -P "%F{cyan}==>%f $1"; sleep 1; }

step "EXEC (LOLBin): osascript bildirimi"
/usr/bin/osascript -e 'display notification "permwatch test" with title "permwatch"'

step "EXEC (LOLBin): curl --version"
/usr/bin/curl --version >/dev/null

step "EXEC + DYLD_INSERT_LIBRARIES (var olmayan dylib; süreç yüklenemeyip çıkabilir, normal)"
DYLD_INSERT_LIBRARIES="$TMP/yok.dylib" /usr/bin/true 2>/dev/null || true

step "quarantine_removed: xattr -d com.apple.quarantine"
touch "$TMP/indirilen.bin"
/usr/bin/xattr -w com.apple.quarantine "0081;00000000;permwatch-test;" "$TMP/indirilen.bin"
/usr/bin/xattr -d com.apple.quarantine "$TMP/indirilen.bin"

step "btm_launch_item_add: test LaunchAgent yükle"
mkdir -p "$HOME/Library/LaunchAgents"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>/usr/bin/true</string></array>
</dict></plist>
EOF
launchctl bootstrap "gui/$(id -u)" "$PLIST"
sleep 2

step "btm_launch_item_remove: test LaunchAgent'ı kaldır"
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
rm -f "$PLIST"

cat <<'EOF'

Elle tetiklenmesi gerekenler:
  tcc_modify                Sistem Ayarları → Gizlilik → Mikrofon: bir uygulamanın iznini aç/kapat
  gatekeeper_user_override  İmzasız bir .app indir, açmayı dene, sonra
                            Gizlilik ve Güvenlik → "Yine de Aç"
EOF
