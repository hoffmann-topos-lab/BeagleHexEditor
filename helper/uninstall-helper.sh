#!/bin/sh
# Removes the privileged helper installed by install-helper.sh.
set -eu

BIN_DST="/usr/local/libexec/hexhelper"
SOCKET="/var/run/hexhelper.sock"
LABEL="dev.hexeditor.helper"

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run me with sudo" >&2
    exit 1
fi

case "$(uname -s)" in
Darwin)
    PLIST="/Library/LaunchDaemons/$LABEL.plist"
    launchctl bootout system "$PLIST" 2>/dev/null || true
    rm -f "$PLIST"
    ;;
Linux)
    systemctl disable --now hexhelper.service 2>/dev/null || true
    rm -f /etc/systemd/system/hexhelper.service
    systemctl daemon-reload 2>/dev/null || true
    ;;
esac

rm -f "$BIN_DST" "$SOCKET"
echo "helper removed."
