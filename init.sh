#!/bin/bash

GITHUB_APP_PRIVATE_KEY=$(echo "$GITHUB_APP_PRIVATE_KEY" | sed 's/@@/\n/g')


echo "$GITHUB_APP_PRIVATE_KEY" > "$HOME/.github_app.pem"

echo "HOME -> $HOME"

cat "$HOME/.github_app.pem" | sha256sum