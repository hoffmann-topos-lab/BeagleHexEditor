#!/usr/bin/env bash
# Monta "Beagle RE Toolkit.app" — um bundle clicável com ícone no Dock — a
# partir do binário release da GUI.
#
# Uso: packaging/macos/bundle.sh [destino]
#   destino: onde criar o .app (padrão: packaging/macos)
#
# Sem Apple Developer Program (D5): o bundle recebe apenas assinatura ad-hoc
# (`codesign -s -`), suficiente porque um binário compilado na própria máquina
# não carrega o atributo de quarentena e o Gatekeeper não intervém.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DEST="${1:-$HERE}"
APP="$DEST/Beagle RE Toolkit.app"
BIN_NAME="hexed-gui"

echo "==> Compilando release…"
( cd "$ROOT" && cargo build --release -p hexed-gui )

BIN="$ROOT/target/release/$BIN_NAME"
[ -x "$BIN" ] || { echo "binário não encontrado: $BIN" >&2; exit 1; }
[ -f "$HERE/AppIcon.icns" ] || {
	echo "AppIcon.icns ausente — rode: python3 packaging/gen-icons.py" >&2
	exit 1
}

echo "==> Montando ${APP}…"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/$BIN_NAME"
cp "$HERE/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
cp "$HERE/Info.plist" "$APP/Contents/Info.plist"

echo "==> Assinando (ad-hoc)…"
codesign --force --deep --sign - "$APP"

echo "==> Pronto: $APP"
echo "    Arraste-o para /Applications ou dê duplo clique para abrir."
