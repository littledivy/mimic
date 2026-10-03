#!/usr/bin/env sh
# One-command install for mimic. Installs uv if missing, then mimic (isolated).
set -e

if ! command -v uv >/dev/null 2>&1; then
  echo "installing uv…"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi

# Install from the current directory if run inside the repo, else from PyPI.
#
# `capture` and `vault` are not optional extras in practice: `mimic learn` and
# `mimic gen` read the capture's bodies, which needs mitmproxy importable, and
# `mimic profile save` encrypts, which needs cryptography. Shipping without
# them installs a mimic whose documented first journey stops at `mimic hosts`.
# `fingerprint` stays opt-in — the default transport is plain requests.
if [ -f "pyproject.toml" ] && grep -q 'name = "mimic-client"' pyproject.toml 2>/dev/null; then
  uv tool install ".[capture,vault]" --reinstall
else
  uv tool install "mimic-client[capture,vault]" --reinstall
fi

echo
echo "installed. next:"
echo "  mimic doctor      # check setup"
echo "  mimic record      # start capture, follow the iPhone steps"
