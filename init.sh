#!/bin/bash
# Sprint 47.3 — GitHub App private-key resolution (first-match-wins):
#   1. GITHUB_APP_PRIVATE_KEY_PATH (preferred — Kubernetes Secret mount)
#   2. GITHUB_APP_PRIVATE_KEY_B64  (base64-encoded env var fallback)
#   3. GITHUB_APP_PRIVATE_KEY      (DEPRECATED — uses @@ → newline expansion)
# Hard error if none is set.
set -euo pipefail

HOME_DIR="${HOME_DIR:-$HOME}"
TARGET="$HOME_DIR/.github_app.pem"

if [[ -n "${GITHUB_APP_PRIVATE_KEY_PATH:-}" && -r "$GITHUB_APP_PRIVATE_KEY_PATH" ]]; then
    cp "$GITHUB_APP_PRIVATE_KEY_PATH" "$TARGET"
elif [[ -n "${GITHUB_APP_PRIVATE_KEY_B64:-}" ]]; then
    printf '%s' "$GITHUB_APP_PRIVATE_KEY_B64" | base64 -d > "$TARGET"
elif [[ -n "${GITHUB_APP_PRIVATE_KEY:-}" ]]; then
    # DEPRECATED legacy path — @@ literal as newline separator. See
    # docs/configuration.rst (Sprint 47.3) for migration guidance.
    echo "$GITHUB_APP_PRIVATE_KEY" | sed 's/@@/\n/g' > "$TARGET"
else
    echo "init.sh: no GitHub App private key source set" >&2
    echo "  expected GITHUB_APP_PRIVATE_KEY_PATH or _B64 or (legacy) the var itself" >&2
    exit 1
fi

chmod 600 "$TARGET"
echo "HOME -> $HOME_DIR"
sha256sum "$TARGET"
