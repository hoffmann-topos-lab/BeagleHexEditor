#!/usr/bin/env sh
# Instala o hexed-gui como aplicativo clicável no Linux: binário + ícone (tema
# hicolor) + entrada de menu (.desktop). Instalação por usuário, sem root.
#
# Uso: packaging/linux/install.sh
#   PREFIX=/usr/local sudo packaging/linux/install.sh   # instalação global
#
# O nome do ícone (beagle-hex-editor), o basename do .desktop e o StartupWMClass
# batem com o app_id definido em gui/src/main.rs, para o ambiente gráfico
# associar a janela ao ícone instalado.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"

echo "==> Compilando release…"
( cd "$ROOT" && cargo build --release -p hexed-gui )

echo "==> Instalando em ${PREFIX}…"
install -Dm755 "$ROOT/target/release/hexed-gui" "$PREFIX/bin/hexed-gui"

# Ícones do tema hicolor, em cada tamanho gerado.
for png in "$HERE"/icons/hicolor/*/apps/beagle-hex-editor.png; do
	rel="${png#"$HERE"/icons/}"
	install -Dm644 "$png" "$PREFIX/share/icons/hicolor/$rel"
done

install -Dm644 "$HERE/beagle-hex-editor.desktop" \
	"$PREFIX/share/applications/beagle-hex-editor.desktop"

# Atualiza os caches, se as ferramentas existirem (silencioso caso não).
gtk-update-icon-cache -q -f "$PREFIX/share/icons/hicolor" 2>/dev/null || true
update-desktop-database -q "$PREFIX/share/applications" 2>/dev/null || true

echo "==> Instalado."
echo "    Garanta que $PREFIX/bin está no PATH."
echo "    O 'Beagle RE Toolkit' deve aparecer no menu de aplicativos."
