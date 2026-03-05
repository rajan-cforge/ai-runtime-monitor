#!/usr/bin/env bash
# AI Runtime Monitor — One-Shot Installer
# Usage:
#   ./install.sh              # Basic install (dashboard + monitoring)
#   ./install.sh --with-proxy # Also install mitmproxy for deep API capture
set -euo pipefail

BOLD='\033[1m'
GREEN='\033[32m'
YELLOW='\033[33m'
CYAN='\033[36m'
RED='\033[31m'
RESET='\033[0m'

info()  { printf "${CYAN}▸${RESET} %s\n" "$*"; }
ok()    { printf "${GREEN}✓${RESET} %s\n" "$*"; }
warn()  { printf "${YELLOW}⚠${RESET} %s\n" "$*"; }
fail()  { printf "${RED}✗${RESET} %s\n" "$*"; exit 1; }

# ── Parse args ──────────────────────────────────────────────
EXTRAS=""
for arg in "$@"; do
  case "$arg" in
    --with-proxy) EXTRAS="[watch]" ;;
    --help|-h)
      echo "Usage: ./install.sh [--with-proxy]"
      echo "  --with-proxy  Also install mitmproxy for deep API capture"
      exit 0 ;;
    *) fail "Unknown option: $arg" ;;
  esac
done

echo ""
printf "${BOLD}AI Runtime Monitor — Installer${RESET}\n"
echo "────────────────────────────────────────"
echo ""

# ── 1. Find Python 3.9+ ────────────────────────────────────
info "Checking for Python 3.9+..."

PYTHON=""
for candidate in python3 python; do
  if command -v "$candidate" &>/dev/null; then
    ver=$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0.0")
    major=${ver%%.*}
    minor=${ver#*.}
    if [ "$major" -ge 3 ] && [ "$minor" -ge 9 ]; then
      PYTHON="$candidate"
      break
    fi
  fi
done

[ -z "$PYTHON" ] && fail "Python 3.9+ not found. Install from https://python.org"
ok "Found $PYTHON ($($PYTHON --version 2>&1))"

# ── 2. Find pip ────────────────────────────────────────────
info "Checking for pip..."

PIP=""
for candidate in pip3 pip; do
  if command -v "$candidate" &>/dev/null; then
    PIP="$candidate"
    break
  fi
done

if [ -z "$PIP" ]; then
  info "pip not found, trying ensurepip..."
  $PYTHON -m ensurepip --upgrade 2>/dev/null || fail "Could not install pip. Try: $PYTHON -m ensurepip --upgrade"
  PIP="$PYTHON -m pip"
fi
ok "Found pip"

# ── 3. Install the package ─────────────────────────────────
info "Installing ai-runtime-monitor${EXTRAS:+ with extras: $EXTRAS}..."

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
$PIP install -e "${SCRIPT_DIR}${EXTRAS}" 2>&1 | tail -5
echo ""
ok "Package installed"

# ── 4. Detect scripts directory & ensure PATH ──────────────
info "Checking PATH for installed scripts..."

SCRIPTS_DIR=""

# Check if ai-monitor is already on PATH
if command -v ai-monitor &>/dev/null; then
  ok "ai-monitor is already on PATH"
else
  # Find where pip installed the scripts
  for dir in \
    "$HOME/.local/bin" \
    "$HOME/Library/Python/3.12/bin" \
    "$HOME/Library/Python/3.11/bin" \
    "$HOME/Library/Python/3.10/bin" \
    "$HOME/Library/Python/3.9/bin"; do
    if [ -f "$dir/ai-monitor" ]; then
      SCRIPTS_DIR="$dir"
      break
    fi
  done

  if [ -z "$SCRIPTS_DIR" ]; then
    # Try to find it via pip show
    SCRIPTS_DIR=$($PIP show ai-runtime-monitor 2>/dev/null | grep -i "^Location:" | head -1 | sed 's/Location: //' | sed 's|/lib/python.*/site-packages||')
    SCRIPTS_DIR="${SCRIPTS_DIR}/bin"
    [ ! -f "$SCRIPTS_DIR/ai-monitor" ] && SCRIPTS_DIR=""
  fi

  if [ -n "$SCRIPTS_DIR" ]; then
    warn "Scripts installed to $SCRIPTS_DIR (not on PATH)"
    info "Adding to shell profile..."

    MARKER="# Added by ai-runtime-monitor installer"
    EXPORT_LINE="export PATH=\"$SCRIPTS_DIR:\$PATH\"  $MARKER"

    # Detect shell profile
    PROFILE=""
    if [ -n "${ZSH_VERSION:-}" ] || [ "$(basename "$SHELL")" = "zsh" ]; then
      PROFILE="$HOME/.zshrc"
    elif [ -n "${BASH_VERSION:-}" ] || [ "$(basename "$SHELL")" = "bash" ]; then
      PROFILE="$HOME/.bashrc"
      # macOS bash uses .bash_profile for login shells
      [ -f "$HOME/.bash_profile" ] && PROFILE="$HOME/.bash_profile"
    fi

    if [ -n "$PROFILE" ]; then
      # Only add if not already present
      if ! grep -qF "$MARKER" "$PROFILE" 2>/dev/null; then
        echo "" >> "$PROFILE"
        echo "$EXPORT_LINE" >> "$PROFILE"
        ok "Added PATH to $PROFILE"
      else
        ok "PATH entry already in $PROFILE"
      fi

      # Source it for current session
      export PATH="$SCRIPTS_DIR:$PATH"
    else
      warn "Could not detect shell profile. Add this to your shell config:"
      echo "  export PATH=\"$SCRIPTS_DIR:\$PATH\""
    fi
  else
    warn "Could not locate installed scripts directory"
    echo "  Try running: $PYTHON -m claude_monitoring.monitor --help"
  fi
fi

# ── 5. Verify installation ─────────────────────────────────
echo ""
info "Verifying installation..."

if command -v ai-monitor &>/dev/null; then
  ok "ai-monitor command is available"
else
  warn "ai-monitor not found in current PATH"
  echo "  Open a new terminal or run: source ${PROFILE:-~/.zshrc}"
fi

if command -v claude-watch &>/dev/null; then
  ok "claude-watch command is available"
fi

# ── 6. Summary ──────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────"
printf "${BOLD}${GREEN}Installation complete!${RESET}\n"
echo ""
echo "  Quick start:"
printf "    ${CYAN}ai-monitor --start${RESET}       Start monitoring + dashboard\n"
printf "    ${CYAN}ai-monitor --status${RESET}      Check if running\n"
printf "    ${CYAN}ai-monitor --stop${RESET}        Stop monitoring\n"
echo ""
echo "  Dashboard: http://localhost:9081"
echo ""
if [ -n "${SCRIPTS_DIR:-}" ]; then
  printf "  ${YELLOW}Note:${RESET} If commands aren't found, open a new terminal\n"
  printf "  or run: ${CYAN}source ${PROFILE:-~/.zshrc}${RESET}\n"
  echo ""
fi
