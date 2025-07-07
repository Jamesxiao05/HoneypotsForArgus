
#!/bin/bash

# Auto-deployment script that checks for git changes and runs the pipeline

echo "Checking for git updates..."

# Fetch latest changes from remote
git fetch origin main

# Check if there are any new commits
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

if [ "$LOCAL" != "$REMOTE" ]; then
    echo "New changes detected! Running deployment pipeline..."
    ./pipeline.sh HoneypotsForArgus honeypot.service
else
    echo "No new changes detected."
fi
