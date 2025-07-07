#!/bin/bash

FOLDER="$1"
SERVICE="$2"

# Exit on error
set -e

# Save SSH key to a temp file
KEY_FILE=$(mktemp)
echo "$SSH_KEY" > "$KEY_FILE"
chmod 600 "$KEY_FILE"

# Run SSH commands
ssh -i "$KEY_FILE" -o StrictHostKeyChecking=no ubuntu@129.153.2.131 << EOF
  echo "✅ Connected to server"
  cd "$FOLDER"
  git pull origin main
  sudo systemctl restart "$SERVICE"
  exit
EOF

# Clean up
rm -f "$KEY_FILE"
