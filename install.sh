#!/usr/bin/env bash
# Instalador de Hackviero para Kali Linux, Debian, Ubuntu y derivadas.
# Instala el comando `hackviero` de forma aislada (sin tocar los paquetes del sistema).
set -euo pipefail

cd "$(dirname "$0")"

verde=$'\033[1;32m'; rojo=$'\033[1;31m'; gris=$'\033[0;90m'; fin=$'\033[0m'
ok()  { printf '%s[+]%s %s\n' "$verde" "$fin" "$*"; }
err() { printf '%s[-]%s %s\n' "$rojo" "$fin" "$*" >&2; }

if ! command -v python3 >/dev/null 2>&1; then
    err "No se encontró python3. Instálalo con:  sudo apt install python3 python3-venv"
    exit 1
fi

if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)'; then
    err "Hackviero necesita Python 3.9 o superior (tienes $(python3 -V 2>&1))."
    exit 1
fi

if command -v pipx >/dev/null 2>&1 && [ "${HACKVIERO_NO_PIPX:-0}" != "1" ]; then
    ok "Instalando con pipx..."
    pipx install --force .
    pipx ensurepath >/dev/null 2>&1 || true
else
    destino="${HACKVIERO_HOME:-$HOME/.local/share/hackviero}"
    bin_dir="${HACKVIERO_BIN:-$HOME/.local/bin}"
    ok "Creando un entorno aislado en $destino"
    if ! python3 -m venv "$destino/venv" 2>/dev/null; then
        err "No se pudo crear el entorno virtual. Instálalo con:  sudo apt install python3-venv"
        exit 1
    fi
    "$destino/venv/bin/python" -m pip install --quiet --upgrade pip
    "$destino/venv/bin/python" -m pip install --quiet .
    mkdir -p "$bin_dir"
    ln -sf "$destino/venv/bin/hackviero" "$bin_dir/hackviero"
    case ":$PATH:" in
        *":$bin_dir:"*) ;;
        *) printf '%s    Añade %s a tu PATH:  echo '\''export PATH="$HOME/.local/bin:$PATH"'\'' >> ~/.bashrc  (o ~/.zshrc)%s\n' "$gris" "$bin_dir" "$fin" ;;
    esac
fi

ok "Listo. Ejecuta:  hackviero"
