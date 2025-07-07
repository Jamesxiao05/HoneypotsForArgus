#!/bin/bash

# Usage: ./pipeline.sh <folder_path> <service_name>
# Example: ./pipeline.sh /home/ubuntu/myapp myapp.service

FOLDER="$1"
SERVICE="$2"

# Exit on any error
set -e

echo "Starting deployment pipeline..."

# First, pull the latest changes locally
echo "Pulling latest changes..."
git pull origin main

# Then deploy to remote server if SSH_KEY is configured
if [ -n "$SSH_KEY" ]; then
  echo "Deploying to remote server..."
  ssh -i <(echo "$SSH_KEY") -o StrictHostKeyChecking=no ubuntu@your.server.ip << EOF
    cd "$FOLDER"
    git pull origin main
    sudo systemctl restart "$SERVICE"
    exit
EOF
else
  echo "SSH_KEY not configured, skipping remote deployment"
fi

echo "Pipeline completed successfully!"