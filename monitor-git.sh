
#!/bin/bash

# Monitor git changes and auto-deploy
# Run this script in a loop to continuously monitor for changes

while true; do
    echo "$(date): Checking for git updates..."
    
    # Fetch latest changes
    git fetch origin main
    
    # Check if there are new commits
    LOCAL=$(git rev-parse HEAD)
    REMOTE=$(git rev-parse origin/main)
    
    if [ "$LOCAL" != "$REMOTE" ]; then
        echo "$(date): New changes detected! Running deployment pipeline..."
        ./pipeline.sh HoneypotsForArgus honeypot.service
        
        # Wait a bit longer after deployment
        sleep 300
    else
        echo "$(date): No changes detected."
    fi
    
    # Check every 60 seconds
    sleep 60
done
