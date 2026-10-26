#!/bin/sh
# pan-ngfw-load installer - copies pan-ngfw-load into PREFIX, creates a private Python venv there and links the
# 'pan-ngfw-load' command into BINDIR. Nothing outside PREFIX and BINDIR is touched.
#
#   ./install.sh                         per-user: ~/.local/share/pan-ngfw-load, ~/.local/bin/pan-ngfw-load
#   ./install.sh --prefix /opt/pan-ngfw-load --bindir /usr/local/bin    system-wide (run as root,
#                                         then run pan-ngfw-load as a dedicated user, see docs/SETUP.md)
#   ./install.sh --tsf-only              only the tech-support-file analyser: no live collector, no
#                                         setup wizard, no cron/firewall access needed
#   ./install.sh --yes                   do not ask before installing the Python packages
#   PYTHON=python3.11 ./install.sh       use a specific interpreter (when python3 is older than 3.10)
set -eu

PREFIX="$HOME/.local/share/pan-ngfw-load"
BINDIR="$HOME/.local/bin"
ASSUME_YES=0
TSF_ONLY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --bindir) BINDIR="$2"; shift 2 ;;
        --yes|-y) ASSUME_YES=1; shift ;;
        --tsf-only) TSF_ONLY=1; shift ;;
        -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

SRC="$(cd "$(dirname "$0")" && pwd)"
confirm() { [ "$ASSUME_YES" = 1 ] && return 0; printf '%s [y/N] ' "$1"; read -r a; [ "$a" = y ] || [ "$a" = Y ]; }

# --- OS-specific hints -------------------------------------------------------------
os_hint() {
    os_id=""; os_ver=""
    if [ -r /etc/os-release ]; then . /etc/os-release; os_id="${ID:-}"; os_ver="${VERSION_ID:-}"; fi
    [ "$(uname -s)" = Darwin ] && os_id=macos
    [ "$(uname -s)" = FreeBSD ] && os_id=freebsd
    echo "Detected OS: ${PRETTY_NAME:-$os_id $os_ver}"
    echo "Install Python 3.10+ with venv support and cron, for example:"
    case "$os_id" in
        ubuntu)
            case "$os_ver" in
                20.04|18.04) echo "  sudo add-apt-repository ppa:deadsnakes/ppa && sudo apt update"
                             echo "  sudo apt install python3.11 python3.11-venv cron"
                             echo "  then: PYTHON=python3.11 ./install.sh" ;;
                *)           echo "  sudo apt install python3 python3-venv cron" ;;
            esac ;;
        debian|raspbian)
            case "$os_ver" in
                10|11) echo "  Debian $os_ver ships Python < 3.10 - upgrade to Debian 12, or build Python with pyenv" ;;
                *)     echo "  sudo apt install python3 python3-venv cron" ;;
            esac ;;
        rhel|rocky|almalinux|centos|ol)
            echo "  sudo dnf install python3.11 cronie && sudo systemctl enable --now crond"
            echo "  then: PYTHON=python3.11 ./install.sh      (RHEL 8.8+/9 AppStream; python3 itself is 3.6/3.9)" ;;
        fedora)
            echo "  sudo dnf install python3 cronie && sudo systemctl enable --now crond" ;;
        opensuse-leap|sles)
            echo "  sudo zypper install python311 cron"
            echo "  then: PYTHON=python3.11 ./install.sh" ;;
        opensuse-tumbleweed)
            echo "  sudo zypper install python3 cron" ;;
        arch|manjaro|endeavouros)
            echo "  sudo pacman -S python cronie && sudo systemctl enable --now cronie" ;;
        alpine)
            echo "  sudo apk add python3 py3-pip cronie build-base   (build-base in case wheels must compile)"
            echo "  sudo rc-update add cronie && sudo rc-service cronie start" ;;
        gentoo)
            echo "  sudo emerge dev-lang/python sys-process/cronie" ;;
        macos)
            echo "  brew install python@3.12      (cron is built in; or use launchd)"
            echo "  then: PYTHON=python3.12 ./install.sh" ;;
        freebsd)
            echo "  sudo pkg install python311 py311-sqlite3      (cron is built in)"
            echo "  then: PYTHON=python3.11 ./install.sh" ;;
        *)
            echo "  use your package manager to install Python >= 3.10 (with the venv module) and cron" ;;
    esac
    echo "Details: docs/SETUP.md"
}

# --- Python -------------------------------------------------------------------
PY="${PYTHON:-$(command -v python3 || true)}"
if [ -z "$PY" ] || ! command -v "$PY" >/dev/null 2>&1; then
    echo "Python interpreter ${PYTHON:-python3} not found." >&2; os_hint >&2; exit 1
fi
PY="$(command -v "$PY")"
if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
    echo "Python 3.10+ required, found $("$PY" -V 2>&1)." >&2; os_hint >&2; exit 1
fi

if [ "$(id -u)" = 0 ] && [ "$PREFIX" = "$HOME/.local/share/pan-ngfw-load" ]; then
    echo "Note: running as root installs into root's home. For servers, a system-wide install"
    echo "      with a dedicated service user is recommended (docs/SETUP.md, section 2)."
    echo
fi
if [ "$TSF_ONLY" = 1 ]; then EDITION="TSF-only (tech support file analyser)"; else EDITION="full (TSF analyser + live collector)"; fi
echo "pan-ngfw-load install"
echo "  edition  $EDITION"
echo "  source   $SRC"
echo "  prefix   $PREFIX"
echo "  command  $BINDIR/pan-ngfw-load"
echo "  python   $("$PY" -V 2>&1) ($PY)"

# --- files ----------------------------------------------------------------------
mkdir -p "$PREFIX" "$BINDIR"
if [ "$SRC" != "$PREFIX" ]; then
    for item in pan_ngfw_load bin contrib docs requirements.txt README.md LICENSE install.sh; do
        [ -e "$SRC/$item" ] || continue
        rm -rf "${PREFIX:?}/$item"
        cp -R "$SRC/$item" "$PREFIX/$item"
    done
    find "$PREFIX/pan_ngfw_load" -name '__pycache__' -type d -prune -exec rm -rf {} +
fi
if [ "$TSF_ONLY" = 1 ]; then
    # leave out everything that talks to a firewall: API collector, setup wizard, cron/systemd examples
    rm -rf "$PREFIX/pan_ngfw_load/collect" "$PREFIX/pan_ngfw_load/wizard.py" "$PREFIX/contrib"
fi
chmod +x "$PREFIX/bin/pan-ngfw-load"

# --- venv -----------------------------------------------------------------------
VENV="$PREFIX/.venv"
venv_ok() { [ -x "$VENV/bin/python" ] && "$VENV/bin/python" -m pip --version >/dev/null 2>&1; }

# repair a venv left without pip (e.g. by an interrupted earlier run)
if [ -x "$VENV/bin/python" ] && ! venv_ok; then
    echo "Existing venv has no pip - repairing"
    "$VENV/bin/python" -m ensurepip --upgrade >/dev/null 2>&1 || rm -rf "$VENV"
fi

if ! venv_ok; then
    rm -rf "$VENV"
    if ! { "$PY" -m venv "$VENV" >/dev/null 2>&1 && venv_ok; }; then
        rm -rf "$VENV"
        echo
        echo "Creating a venv failed - the venv/ensurepip module is missing."
        os_hint
        echo "Then run ./install.sh again (recommended)."
        echo
        echo "Alternative without root: create the venv without pip and bootstrap pip from"
        echo "https://bootstrap.pypa.io/get-pip.py (downloaded with Python itself, no curl needed)."
        confirm "Download get-pip.py and use that?" || exit 1
        tmp="$(mktemp -d)"
        trap 'rm -rf "$tmp"' EXIT
        if ! { "$PY" -m venv --without-pip "$VENV" \
               && "$PY" -c 'import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])' \
                        https://bootstrap.pypa.io/get-pip.py "$tmp/get-pip.py" \
               && "$VENV/bin/python" -I "$tmp/get-pip.py" -q && venv_ok; }; then
            rm -rf "$VENV"
            echo "Bootstrapping pip failed (no internet access?). Install the venv package (see above) and retry." >&2
            exit 1
        fi
    fi
fi

# --- packages -------------------------------------------------------------------
echo
echo "Python packages to install into $PREFIX/.venv (from PyPI, plus their dependencies):"
grep -v '^#' "$PREFIX/requirements.txt" | sed '/^$/d; s/^/  /'
echo "(offline/air-gapped host: see 'Offline installation' in docs/SETUP.md)"
if confirm "Install them now?"; then
    "$PREFIX/.venv/bin/python" -m pip install -q --upgrade pip
    "$PREFIX/.venv/bin/python" -m pip install -q -r "$PREFIX/requirements.txt"
else
    echo "skipped - pan-ngfw-load will not run until they are installed:"
    echo "  $PREFIX/.venv/bin/python -m pip install -r $PREFIX/requirements.txt"
fi

ln -sf "$PREFIX/bin/pan-ngfw-load" "$BINDIR/pan-ngfw-load"
echo
if [ "$TSF_ONLY" = 1 ]; then
    echo "Installed (TSF-only). Next step:  pan-ngfw-load tsf <techsupport.tgz>"
    echo "Reports go to ~/pan-ngfw-load/reports/<hostname>/ (change with -o, or report_dir in a config file)."
else
    echo "Installed. Next steps:  pan-ngfw-load init   (live)   or   pan-ngfw-load tsf <file.tgz>   (offline)"
fi
case ":$PATH:" in *":$BINDIR:"*) ;; *) echo "(add $BINDIR to PATH, or call $BINDIR/pan-ngfw-load)";; esac
