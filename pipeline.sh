#!/bin/bash

# Usage: ./deploy.sh <folder_path> <service_name>
# Example: ./deploy.sh /home/ubuntu/myapp myapp.service

FOLDER="$1"
SERVICE="$2"

# Exit on any error
set -e

ssh -i <(echo "$SSH_KEY") -o StrictHostKeyChecking=no ubuntu@your.server.ip << EOF
  cd "$FOLDER"
  git pull origin main
  sudo systemctl restart "$SERVICE"
  exit
EOF