# Gmail MCP Server

An MCP (Model Context Protocol) server that provides Claude with access to your Gmail, featuring a full OAuth 2.1 authorization server with dynamic client registration.

## Features

- Full OAuth 2.1 Authorization Server (RFC 8414, RFC 7591, RFC 9728)
- Dynamic Client Registration - Claude Code auto-registers
- PKCE Support (RFC 7636)
- First-class "Authenticate" button in Claude Code's `/mcp` menu
- Gmail tools: list, read, search, mark read/unread, get threads

## Setup

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Build:**
   ```bash
   npm run build
   ```

3. **Start the server:**
   ```bash
   npm start
   ```
   The server runs on `http://localhost:3100`

4. **Configure Claude Code** (`~/.mcp.json`):
   ```json
   {
     "mcpServers": {
       "gmail": {
         "type": "sse",
         "url": "http://localhost:3100/sse"
       }
     }
   }
   ```

5. **Authenticate via Claude Code:**
   - Run `/mcp` in Claude Code
   - Click "Authenticate" on the gmail server
   - Complete Google OAuth in your browser

## Auto-Start on Login (macOS)

Run the install script to set up the LaunchAgent:

```bash
./scripts/install.sh
```

This will:
- Detect your node installation
- Generate a plist with correct paths
- Install to `~/Library/LaunchAgents/`
- Start the server immediately

To uninstall:
```bash
./scripts/uninstall.sh
```

## Available Tools

| Tool | Description |
|------|-------------|
| `list_emails` | List emails from inbox with optional filters |
| `read_email` | Read full email content by ID |
| `search_emails` | Search using Gmail query syntax |
| `mark_as_read` | Mark an email as read |
| `mark_as_unread` | Mark an email as unread |
| `list_labels` | List all Gmail labels |
| `get_thread` | Get all emails in a conversation |

## Gmail Search Syntax

The `search_emails` and `list_emails` tools support Gmail's query syntax:

- `is:unread` - Unread emails
- `from:someone@example.com` - From specific sender
- `subject:invoice` - Subject contains "invoice"
- `has:attachment` - Has attachments
- `after:2024/01/01` - After a date
- `before:2024/12/31` - Before a date
- `label:important` - Has specific label

## Architecture

```
┌─────────────────┐      ┌──────────────────────────────────────┐
│   Claude Code   │◄────►│         Gmail MCP Server             │
│                 │ SSE  │                                      │
│  /mcp menu      │      │  ┌─────────────────────────────────┐ │
│  shows          │      │  │ OAuth 2.1 Authorization Server  │ │
│  "Authenticate" │      │  │  - Dynamic client registration  │ │
│                 │      │  │  - PKCE support                 │ │
└─────────────────┘      │  │  - Token management             │ │
                         │  └──────────────┬──────────────────┘ │
                         │                 │                    │
                         │  ┌──────────────▼──────────────────┐ │
                         │  │      Google OAuth Proxy         │ │
                         │  │  - Redirects to Google          │ │
                         │  │  - Stores Google tokens         │ │
                         │  └──────────────┬──────────────────┘ │
                         │                 │                    │
                         │  ┌──────────────▼──────────────────┐ │
                         │  │        Gmail API Tools          │ │
                         │  │  - list, read, search, etc.     │ │
                         │  └─────────────────────────────────┘ │
                         └──────────────────────────────────────┘
```

## Development

```bash
npm run build   # Compile TypeScript
npm start       # Run server
```

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check & status |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 metadata |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata |
| `POST /oauth/register` | Dynamic client registration |
| `GET /oauth/authorize` | Authorization endpoint |
| `POST /oauth/token` | Token endpoint |
| `GET /sse` | MCP SSE endpoint (protected) |
