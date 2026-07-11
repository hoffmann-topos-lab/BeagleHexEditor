#!/bin/sh
# F-47 / D3 / D5 — Install the privileged helper as a root service.
#
# The helper is a small daemon that does raw /dev I/O for the unprivileged GUI
# over a Unix socket, gated by a peer-UID check and a /dev/ path whitelist. It
# needs no Apple Developer account: it is a plain LaunchDaemon (macOS) or
# systemd service (Linux), which require no code signature — only root-owned
# files with correct permissions.
#
# Usage:
#   cargo build --release -p hexed-helper   # build it first, as your user
#   sudo ./helper/install-helper.sh         # then install it, once
#
# Uninstall with ./helper/uninstall-helper.sh.

set -eu

SOCKET="/var/run/hexhelper.sock"   # /var/run -> /run on Linux, works on both
BIN_DST="/usr/local/libexec/hexhelper"
LABEL="dev.hexeditor.helper"

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run me with sudo (I install a root service)" >&2
    exit 1
fi

# The user who invoked sudo is the only one the daemon will serve.
ALLOWED_UID="${SUDO_UID:-}"
if [ -z "$ALLOWED_UID" ]; then
    echo "error: could not determine the installing user's UID (\$SUDO_UID unset)" >&2
    echo "       run this via sudo, not as a root login shell" >&2
    exit 1
fi

# Locate the freshly built binary relative to this script.
here="$(cd "$(dirname "$0")/.." && pwd)"
BIN_SRC="$here/target/release/hexhelper"
if [ ! -x "$BIN_SRC" ]; then
    echo "error: $BIN_SRC not found — build it first:" >&2
    echo "       cargo build --release -p hexed-helper" >&2
    exit 1
fi

install -d -m 755 "$(dirname "$BIN_DST")"
install -o root -m 755 "$BIN_SRC" "$BIN_DST"
echo "installed $BIN_DST (uid gate: $ALLOWED_UID)"

case "$(uname -s)" in
Darwin)
    PLIST="/Library/LaunchDaemons/$LABEL.plist"
    cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$BIN_DST</string>
        <string>--socket</string><string>$SOCKET</string>
        <string>--uid</string><string>$ALLOWED_UID</string>
    </array>
    <key>KeepAlive</key><true/>
    <key>RunAtLoad</key><true/>
</dict>
</plist>
EOF
    chown root:wheel "$PLIST"
    chmod 644 "$PLIST"
    launchctl bootout system "$PLIST" 2>/dev/null || true
    launchctl bootstrap system "$PLIST"
    echo "loaded LaunchDaemon $PLIST"
    ;;
Linux)
    UNIT="/etc/systemd/system/hexhelper.service"
    cat > "$UNIT" <<EOF
[Unit]
Description=hexed privileged disk helper (F-47)
After=local-fs.target

[Service]
ExecStart=$BIN_DST --socket $SOCKET --uid $ALLOWED_UID
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$UNIT"
    systemctl daemon-reload
    systemctl enable --now hexhelper.service
    echo "loaded systemd service $UNIT"
    ;;
*)
    echo "error: unsupported platform $(uname -s)" >&2
    exit 1
    ;;
esac

echo "done. The GUI and CLI will use the helper automatically for /dev/ access."
