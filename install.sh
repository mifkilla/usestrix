#!/usr/bin/env bash
# usestrix installer. Copies one file and checks prerequisites.
set -euo pipefail

BIN="${HOME}/.local/bin"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/usestrix.py"
DST="${BIN}/usestrix"

green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
red() { printf '\033[0;31m%s\033[0m\n' "$*"; }

echo "usestrix installer"
echo

[ -f "$SRC" ] || { red "usestrix.py not found next to this script"; exit 1; }

# --- python ---------------------------------------------------------------
PY=""
for cand in python3 python; do
  if command -v "$cand" >/dev/null 2>&1; then
    if "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)'; then
      PY="$(command -v "$cand")"
      break
    fi
  fi
done
[ -n "$PY" ] || { red "Python 3.9+ is required"; exit 1; }
green "python: $PY ($("$PY" -V 2>&1))"

# prefer an interpreter that already has rich, purely for looks
if ! "$PY" -c 'import rich' >/dev/null 2>&1; then
  for cand in "${HOME}/.local/share/pipx/venvs/strix-agent/bin/python" \
              /usr/local/bin/python3 /opt/homebrew/bin/python3; do
    if [ -x "$cand" ] && "$cand" -c 'import rich' >/dev/null 2>&1; then
      PY="$cand"
      green "using interpreter with rich: $PY"
      break
    fi
  done
fi
"$PY" -c 'import rich' >/dev/null 2>&1 \
  && green "rich: available (pretty interface)" \
  || yellow "rich: missing - plain text interface. Install with: pip install rich"

# --- install --------------------------------------------------------------
mkdir -p "$BIN"
{ echo "#!${PY}"; tail -n +2 "$SRC"; } > "$DST"
chmod 755 "$DST"
green "installed: $DST"

"$PY" -m py_compile "$DST" && green "syntax: ok"

# --- prerequisites, reported but not fatal --------------------------------
echo
echo "prerequisites:"
if command -v strix >/dev/null 2>&1; then
  green "  strix: $(strix --version 2>&1 | head -1)"
else
  for c in "${HOME}/.local/bin/strix" \
           "${HOME}/.local/share/pipx/venvs/strix-agent/bin/strix"; do
    [ -x "$c" ] && { green "  strix: found at $c"; break; }
  done
  command -v strix >/dev/null 2>&1 || [ -x "${HOME}/.local/bin/strix" ] \
    || yellow "  strix: not found. Install with: pipx install strix-agent"
fi

docker info >/dev/null 2>&1 \
  && green "  docker: daemon responds" \
  || yellow "  docker: not responding. Strix needs it for its sandbox"

if [ -f "${HOME}/.strix/env" ] || [ -n "${STRIX_LLM:-}" ]; then
  green "  strix config: present"
else
  yellow "  strix config: no ~/.strix/env and no \$STRIX_LLM"
  echo "    create ~/.strix/env (chmod 600) with:"
  echo "      export STRIX_LLM=openrouter/deepseek/deepseek-v4.1-flash"
  echo "      export LLM_API_KEY=sk-or-..."
fi

# --- PATH -----------------------------------------------------------------
echo
case ":${PATH}:" in
  *":${BIN}:"*) green "PATH: ${BIN} is already there" ;;
  *) yellow "PATH: ${BIN} is not in \$PATH"
     echo "    add to your shell profile:"
     echo "      export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac

echo
green "done. run: usestrix"
