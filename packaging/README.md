# Empacotamento e ícones

O ícone do programa vem de `logo.png` (raiz do repositório). Ele aparece em dois
lugares:

1. **Topo da janela** (barra de título / Dock / barra de tarefas) — embutido no
   binário da GUI (`gui/assets/icon-256.png`, carregado por `load_icon()` em
   `gui/src/main.rs` via `ViewportBuilder::with_icon`).
2. **Ícone clicável** do aplicativo — no macOS via bundle `.app`, no Linux via
   tema de ícones `hicolor` + entrada `.desktop`.

## Regenerar os ícones

Só é necessário se `logo.png` mudar. Requer [Pillow](https://python-pillow.org/)
(`pip install pillow`); a etapa `.icns` exige `iconutil` (só macOS).

```sh
python3 packaging/gen-icons.py
```

Gera (todos versionados, para quem só compila não precisar do Pillow):

- `gui/assets/icon-256.png` — ícone da janela;
- `packaging/macos/AppIcon.icns` — ícone do bundle macOS;
- `packaging/linux/icons/hicolor/<n>x<n>/apps/beagle-hex-editor.png` — Linux;
- `packaging/icon/icon-master-1024.png` — mestre de referência.

A arte é transformada num ladrilho de cantos arredondados (estilo macOS) sobre
fundo transparente.

## macOS — bundle `.app` clicável

```sh
packaging/macos/bundle.sh            # cria packaging/macos/Beagle RE Toolkit.app
```

Compila a GUI em release, monta o `.app` (binário + `AppIcon.icns` + `Info.plist`)
e assina ad-hoc (`codesign -s -`). Sem Apple Developer Program (D5): como o
binário é compilado localmente, ele não recebe o atributo de quarentena e o
Gatekeeper não intervém. Arraste o `.app` para `/Applications`.

## Linux — aplicativo no menu

```sh
packaging/linux/install.sh                       # instala em ~/.local
PREFIX=/usr/local sudo packaging/linux/install.sh  # instalação global
```

Instala o binário, os ícones no tema `hicolor` e o `beagle-hex-editor.desktop`,
e atualiza os caches de ícone/desktop. O `Icon=`, o basename do `.desktop` e o
`StartupWMClass` batem com o `app_id` definido em `gui/src/main.rs`, para o
ambiente gráfico associar a janela ao ícone.
