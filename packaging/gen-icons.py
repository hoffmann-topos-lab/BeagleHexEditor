#!/usr/bin/env python3
"""Gera todos os assets de ícone a partir de `logo.png` (raiz do repositório).

A arte-base é transformada num ladrilho de cantos arredondados (estilo macOS)
sobre fundo transparente, e depois exportada nos tamanhos exigidos por cada
plataforma:

  - gui/assets/icon-256.png            → ícone da janela (embutido no binário)
  - packaging/macos/AppIcon.icns       → ícone do bundle .app (via `iconutil`)
  - packaging/linux/icons/hicolor/…    → tema de ícones do Linux (.desktop)
  - packaging/icon/icon-master-1024.png → mestre versionado, para referência

Requer Pillow. A etapa do `.icns` exige `iconutil` (só existe no macOS); em
outras plataformas ela é pulada. Como os assets derivados são versionados, quem
apenas compila o projeto NÃO precisa rodar este script — ele existe para
regenerar os ícones caso `logo.png` mude.
"""

import os
import subprocess
import sys
import tempfile

from PIL import Image, ImageDraw

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "logo.png")

# Fração de margem transparente ao redor do ladrilho e raio dos cantos
# (0.2237 ≈ proporção do "continuous corner" das apps do macOS Big Sur+).
MARGIN_FRAC = 0.05
RADIUS_FRAC = 0.2237
MASTER = 1024


def rounded_tile(size: int) -> Image.Image:
    """Devolve um RGBA `size`×`size`: o logo como ladrilho de cantos
    arredondados centrado num canvas transparente."""
    tile = round(size * (1 - 2 * MARGIN_FRAC))
    off = (size - tile) // 2
    src = Image.open(SRC).convert("RGBA").resize((tile, tile), Image.LANCZOS)
    mask = Image.new("L", (tile, tile), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [0, 0, tile - 1, tile - 1], radius=round(tile * RADIUS_FRAC), fill=255
    )
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    canvas.paste(src, (off, off), mask)
    return canvas


def save(img: Image.Image, *parts: str) -> str:
    path = os.path.join(ROOT, *parts)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    img.save(path)
    return path


def main() -> None:
    if not os.path.exists(SRC):
        sys.exit(f"logo.png não encontrado em {SRC}")

    # Renderiza um mestre em alta resolução e reduz a partir dele (ícones
    # pequenos ficam mais nítidos do que rasterizando cada tamanho do zero).
    master = rounded_tile(MASTER)
    at = lambda s: master.resize((s, s), Image.LANCZOS)

    print(save(master, "packaging", "icon", "icon-master-1024.png"))
    print(save(at(256), "gui", "assets", "icon-256.png"))

    for s in (16, 32, 48, 64, 128, 256, 512):
        print(save(at(s), "packaging", "linux", "icons", "hicolor",
                   f"{s}x{s}", "apps", "beagle-hex-editor.png"))

    if sys.platform == "darwin":
        with tempfile.TemporaryDirectory() as tmp:
            iconset = os.path.join(tmp, "AppIcon.iconset")
            os.makedirs(iconset)
            # (tamanho base, escala) → nomes que o iconutil espera.
            for base, scale in [(16, 1), (16, 2), (32, 1), (32, 2), (128, 1),
                                (128, 2), (256, 1), (256, 2), (512, 1), (512, 2)]:
                suffix = "" if scale == 1 else "@2x"
                name = f"icon_{base}x{base}{suffix}.png"
                at(base * scale).save(os.path.join(iconset, name))
            out = os.path.join(ROOT, "packaging", "macos", "AppIcon.icns")
            os.makedirs(os.path.dirname(out), exist_ok=True)
            subprocess.run(["iconutil", "-c", "icns", iconset, "-o", out], check=True)
            print(out)
    else:
        print("pulando AppIcon.icns (não é macOS)")

    print("ícones gerados.")


if __name__ == "__main__":
    main()
