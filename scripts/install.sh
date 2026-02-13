#!/bin/bash
# Install Gmail MCP LaunchAgent

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
PLIST_NAME="com.gmail-mcp.plist"

# Find node path
NODE_PATH=$(which node)
if [ -z "$NODE_PATH" ]; then
    echo "Error: node not found in PATH"
    exit 1
fi

echo "Gmail MCP LaunchAgent Installer"
echo "================================"
echo "Repo directory: $REPO_DIR"
echo "Node path: $NODE_PATH"
echo ""

# Build if needed
if [ ! -f "$REPO_DIR/dist/index.js" ]; then
    echo "Building project..."
    cd "$REPO_DIR" && npm run build
fi

# Create LaunchAgents directory if needed
mkdir -p "$LAUNCH_AGENTS_DIR"

# Generate plist with correct paths
echo "Installing LaunchAgent..."
sed -e "s|__NODE_PATH__|$NODE_PATH|g" \
    -e "s|__INSTALL_DIR__|$REPO_DIR|g" \
    -e "s|__HOME__|$HOME|g" \
    "$REPO_DIR/com.gmail-mcp.plist" > "$LAUNCH_AGENTS_DIR/$PLIST_NAME"

# Unload if already loaded
launchctl unload "$LAUNCH_AGENTS_DIR/$PLIST_NAME" 2>/dev/null || true

# Load the agent
launchctl load "$LAUNCH_AGENTS_DIR/$PLIST_NAME"

echo ""
echo "Done! Gmail MCP server installed and running."
echo ""
echo "To check status:  curl http://localhost:3100/health"
echo "To view logs:     tail -f ~/.config/gmail-mcp/stderr.log"
echo "To uninstall:     ./scripts/uninstall.sh"
