# Gmail MCP Server

An MCP (Model Context Protocol) server that provides Claude with access to your Gmail, featuring a full OAuth 2.1 authorization server with dynamic client registration.

## Features

- Full OAuth 2.1 Authorization Server (RFC 8414, RFC 7591, RFC 9728)
- Dynamic Client Registration - Claude Code auto-registers
- PKCE Support (RFC 7636)
- First-class "Authenticate" button in Claude Code's `/mcp` menu
- Gmail tools: list, read, search, send, reply, draft, archive, trash, labels, attachments

## Prerequisites

Node.js 18+ is required. Install via [nodejs.org](https://nodejs.org) or:

```bash
brew install node
```

## Setup

1. **Clone and install dependencies:**
   ```bash
   git clone <repo-url> gmail-mcp
   cd gmail-mcp
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
   The server runs on `http://localhost:3100` by default. Override with `PORT=3200 npm start`.

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

   > **Note:** Google will show an "This app isn't verified" warning screen. This is normal for apps that haven't gone through Google's verification process. To proceed:
   > 1. Click **Advanced**
   > 2. Click **Go to gmail-mcp (unsafe)**
   > 3. Review the requested permissions (read and modify Gmail) and click **Allow**
   >
   > Your credentials are stored locally on your machine and are never sent to any third-party server.

## Configuration

Google OAuth credentials are built in — no setup required. On first use, you'll be prompted to authorize your Gmail through Google's consent screen.

User-specific config files are stored in `~/.config/gmail-mcp/`:

| File | Description |
|------|-------------|
| `credentials.json` | *Optional* — Override the built-in Google OAuth credentials with your own |
| `token.json` | Your Google OAuth tokens (auto-generated after authorization) |
| `clients.json` | Registered MCP clients (auto-generated) |
| `access_tokens.json` | Issued access tokens (auto-generated) |

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

Logs are written to `~/.config/gmail-mcp/stdout.log` and `stderr.log`.

## Available Tools

| Tool | Description |
|------|-------------|
| `list_emails` | List emails from inbox with optional filters |
| `read_email` | Read full email content by ID |
| `search_emails` | Search using Gmail query syntax |
| `send_email` | Compose and send a new email |
| `reply_to_email` | Reply to an existing email |
| `draft_email` | Create a draft without sending |
| `mark_as_read` | Mark an email as read |
| `mark_as_unread` | Mark an email as unread |
| `archive_email` | Archive an email (remove from inbox) |
| `trash_email` | Move an email to trash |
| `add_label` | Add a label to an email |
| `remove_label` | Remove a label from an email |
| `list_labels` | List all Gmail labels |
| `get_thread` | Get all emails in a conversation |
| `get_attachment` | Download an email attachment |

## Gmail Search Syntax

The `search_emails` and `list_emails` tools support Gmail's query syntax:

- `is:unread` - Unread emails
- `from:someone@example.com` - From specific sender
- `subject:invoice` - Subject contains "invoice"
- `has:attachment` - Has attachments
- `after:2025/01/01` - After a date
- `before:2025/12/31` - Before a date
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
npm run auth    # Standalone Google OAuth (alternative to browser flow)
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
