#!/bin/bash
# Uninstall Gmail MCP LaunchAgent

LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
PLIST_NAME="com.gmail-mcp.plist"

echo "Uninstalling Gmail MCP LaunchAgent..."

# Unload if loaded
launchctl unload "$LAUNCH_AGENTS_DIR/$PLIST_NAME" 2>/dev/null || true

# Remove plist
rm -f "$LAUNCH_AGENTS_DIR/$PLIST_NAME"

echo "Done! LaunchAgent removed."
echo "Note: The server may still be running. To kill it: lsof -ti:3100 | xargs kill"
