#!/usr/bin/env node
/**
 * Gmail MCP Server with Full OAuth 2.1 Authorization Server
 *
 * Implements:
 * - RFC 8414: OAuth 2.0 Authorization Server Metadata
 * - RFC 9728: OAuth 2.0 Protected Resource Metadata
 * - RFC 7591: OAuth 2.0 Dynamic Client Registration
 * - PKCE (RFC 7636)
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { google, gmail_v1 } from 'googleapis';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import express, { Request, Response } from 'express';
import crypto from 'crypto';

const CONFIG_DIR = join(homedir(), '.config', 'gmail-mcp');
mkdirSync(CONFIG_DIR, { recursive: true });
const CREDENTIALS_PATH = join(CONFIG_DIR, 'credentials.json');
const TOKEN_PATH = join(CONFIG_DIR, 'token.json');
const CLIENTS_PATH = join(CONFIG_DIR, 'clients.json');
const TOKENS_PATH = join(CONFIG_DIR, 'access_tokens.json');

const PORT = parseInt(process.env.PORT || '3100', 10);
const SERVER_URL = `http://localhost:${PORT}`;

// Default Google OAuth credentials (Desktop app — safe to embed, see Google's public client docs).
// Users can override by placing their own credentials.json in ~/.config/gmail-mcp/
const DEFAULT_GOOGLE_CREDENTIALS = {
  client_id: '52009412064-k1u1a1n7k0hdaolgtkjnm9q03iq945ds.apps.googleusercontent.com',
  client_secret: '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',
  redirect_uris: ['http://localhost:3000/callback'],
  auth_uri: 'https://accounts.google.com/o/oauth2/auth',
  token_uri: 'https://oauth2.googleapis.com/token',
};

const GOOGLE_SCOPES = [
  'https://www.googleapis.com/auth/gmail.readonly',
  'https://www.googleapis.com/auth/gmail.modify',
];

// ============================================================================
// OAuth Storage (in-memory + file persistence)
// ============================================================================

interface RegisteredClient {
  client_id: string;
  client_secret?: string;
  redirect_uris: string[];
  client_name?: string;
  created_at: number;
}

interface AuthorizationCode {
  code: string;
  client_id: string;
  redirect_uri: string;
  code_challenge?: string;
  code_challenge_method?: string;
  expires_at: number;
}

interface AccessToken {
  token: string;
  client_id: string;
  expires_at: number;
}

// In-memory stores
const registeredClients = new Map<string, RegisteredClient>();
const authorizationCodes = new Map<string, AuthorizationCode>();
const accessTokens = new Map<string, AccessToken>();
const pendingAuths = new Map<string, { client_id: string; redirect_uri: string; state?: string; code_challenge?: string; code_challenge_method?: string; expires_at: number }>();

// Load persisted clients
function loadClients() {
  if (existsSync(CLIENTS_PATH)) {
    try {
      const data = JSON.parse(readFileSync(CLIENTS_PATH, 'utf-8'));
      for (const client of data.clients || []) {
        registeredClients.set(client.client_id, client);
      }
    } catch {}
  }
}

// Save clients to disk
function saveClients() {
  const clients = Array.from(registeredClients.values());
  writeFileSync(CLIENTS_PATH, JSON.stringify({ clients }, null, 2));
}

// Load persisted tokens
function loadTokens() {
  if (existsSync(TOKENS_PATH)) {
    try {
      const data = JSON.parse(readFileSync(TOKENS_PATH, 'utf-8'));
      for (const token of data.tokens || []) {
        if (Date.now() < token.expires_at) {
          accessTokens.set(token.token, token);
        }
      }
    } catch {}
  }
}

// Save tokens to disk
function saveTokens() {
  const tokens = Array.from(accessTokens.values());
  writeFileSync(TOKENS_PATH, JSON.stringify({ tokens }, null, 2));
}

// Initialize
loadClients();
loadTokens();

// ============================================================================
// Google OAuth Helpers
// ============================================================================

function getGoogleCredentials() {
  if (existsSync(CREDENTIALS_PATH)) {
    try {
      const credentials = JSON.parse(readFileSync(CREDENTIALS_PATH, 'utf-8'));
      const creds = credentials.installed || credentials.web;
      if (creds?.client_id && creds?.client_secret) return creds;
    } catch {}
  }
  return DEFAULT_GOOGLE_CREDENTIALS;
}

function getGoogleOAuth2Client() {
  const { client_id, client_secret } = getGoogleCredentials();
  return new google.auth.OAuth2(
    client_id,
    client_secret,
    `${SERVER_URL}/google/callback`
  );
}

function isGoogleAuthenticated(): boolean {
  if (!existsSync(TOKEN_PATH)) return false;
  try {
    const tokens = JSON.parse(readFileSync(TOKEN_PATH, 'utf-8'));
    // Need either a valid access token or a refresh token to obtain one
    if (tokens.refresh_token) return true;
    if (tokens.access_token && tokens.expiry_date && Date.now() < tokens.expiry_date) return true;
    return false;
  } catch {
    return false;
  }
}

function getGmailClient(): gmail_v1.Gmail {
  if (!existsSync(TOKEN_PATH)) {
    throw new Error('Not authenticated with Google. Re-authenticate via Claude Code /mcp menu.');
  }

  const tokens = JSON.parse(readFileSync(TOKEN_PATH, 'utf-8'));
  const oauth2Client = getGoogleOAuth2Client();
  oauth2Client.setCredentials(tokens);

  // Persist refreshed tokens so they survive server restarts
  oauth2Client.on('tokens', (newTokens) => {
    try {
      const existing = existsSync(TOKEN_PATH)
        ? JSON.parse(readFileSync(TOKEN_PATH, 'utf-8'))
        : {};
      writeFileSync(TOKEN_PATH, JSON.stringify({ ...existing, ...newTokens }, null, 2));
      console.log('Google tokens refreshed and saved to disk');
    } catch (err) {
      console.error('Failed to persist refreshed Google tokens:', err);
    }
  });

  return google.gmail({ version: 'v1', auth: oauth2Client });
}

// ============================================================================
// Crypto Helpers
// ============================================================================

function generateId(length = 32): string {
  return crypto.randomBytes(length).toString('hex');
}

function generateSecret(): string {
  return crypto.randomBytes(32).toString('base64url');
}

function hashCodeChallenge(verifier: string): string {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

// ============================================================================
// Tool Definitions
// ============================================================================

const tools: Tool[] = [
  {
    name: 'list_emails',
    description: 'List emails from Gmail inbox. Returns email IDs, subjects, senders, dates, and snippets.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        maxResults: { type: 'number', description: 'Maximum number of emails to return (default: 20, max: 100)' },
        query: { type: 'string', description: 'Gmail search query (e.g., "is:unread", "from:example@gmail.com")' },
        labelIds: { type: 'array', items: { type: 'string' }, description: 'Filter by label IDs (e.g., ["INBOX", "UNREAD"])' },
      },
    },
  },
  {
    name: 'read_email',
    description: 'Read the full content of an email by its ID.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        emailId: { type: 'string', description: 'The ID of the email to read' },
      },
      required: ['emailId'],
    },
  },
  {
    name: 'search_emails',
    description: 'Search emails using Gmail query syntax.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        query: { type: 'string', description: 'Gmail search query' },
        maxResults: { type: 'number', description: 'Maximum number of results (default: 20)' },
      },
      required: ['query'],
    },
  },
  {
    name: 'mark_as_read',
    description: 'Mark an email as read.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        emailId: { type: 'string', description: 'The ID of the email to mark as read' },
      },
      required: ['emailId'],
    },
  },
  {
    name: 'mark_as_unread',
    description: 'Mark an email as unread.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        emailId: { type: 'string', description: 'The ID of the email to mark as unread' },
      },
      required: ['emailId'],
    },
  },
  {
    name: 'list_labels',
    description: 'List all Gmail labels (folders/categories).',
    inputSchema: { type: 'object' as const, properties: {} },
  },
  {
    name: 'get_thread',
    description: 'Get all emails in a conversation thread.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        threadId: { type: 'string', description: 'The ID of the thread to retrieve' },
      },
      required: ['threadId'],
    },
  },
  {
    name: 'send_email',
    description: 'Compose and send a new email.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        to: { type: 'string', description: 'Recipient email address (comma-separated for multiple)' },
        subject: { type: 'string', description: 'Email subject line' },
        body: { type: 'string', description: 'Email body (plain text)' },
        cc: { type: 'string', description: 'CC recipients (comma-separated)' },
        bcc: { type: 'string', description: 'BCC recipients (comma-separated)' },
      },
      required: ['to', 'subject', 'body'],
    },
  },
  {
    name: 'reply_to_email',
    description: 'Reply to an existing email. Sends the reply in the same thread.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        emailId: { type: 'string', description: 'The ID of the email to reply to' },
        body: { type: 'string', description: 'Reply body (plain text)' },
        replyAll: { type: 'boolean', description: 'Reply to all recipients (default: false)' },
      },
      required: ['emailId', 'body'],
    },
  },
  {
    name: 'draft_email',
    description: 'Create a draft email without sending it.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        to: { type: 'string', description: 'Recipient email address (comma-separated for multiple)' },
        subject: { type: 'string', description: 'Email subject line' },
        body: { type: 'string', description: 'Email body (plain text)' },
        cc: { type: 'string', description: 'CC recipients (comma-separated)' },
        bcc: { type: 'string', description: 'BCC recipients (comma-separated)' },
      },
      required: ['to', 'subject', 'body'],
    },
  },
  {
    name: 'archive_email',
    description: 'Archive an email (remove from inbox).',
    inputSchema: {
      type: 'object' as const,
      properties: {
        emailId: { type: 'string', description: 'The ID of the email to archive' },
      },
      required: ['emailId'],
    },
  },
  {
    name: 'trash_email',
    description: 'Move an email to trash.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        emailId: { type: 'string', description: 'The ID of the email to trash' },
      },
      required: ['emailId'],
    },
  },
  {
    name: 'add_label',
    description: 'Add a label to an email.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        emailId: { type: 'string', description: 'The ID of the email' },
        labelId: { type: 'string', description: 'The label ID to add (use list_labels to find IDs)' },
      },
      required: ['emailId', 'labelId'],
    },
  },
  {
    name: 'remove_label',
    description: 'Remove a label from an email.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        emailId: { type: 'string', description: 'The ID of the email' },
        labelId: { type: 'string', description: 'The label ID to remove (use list_labels to find IDs)' },
      },
      required: ['emailId', 'labelId'],
    },
  },
  {
    name: 'get_attachment',
    description: 'Download an email attachment. Returns the filename, MIME type, and base64-encoded content.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        emailId: { type: 'string', description: 'The ID of the email containing the attachment' },
        attachmentId: { type: 'string', description: 'The attachment ID (from read_email response). If not provided, lists all attachments.' },
      },
      required: ['emailId'],
    },
  },
];

// ============================================================================
// Gmail Tool Implementations
// ============================================================================

function getEmailBody(payload: gmail_v1.Schema$MessagePart): string {
  if (payload.body?.data) {
    return Buffer.from(payload.body.data, 'base64').toString('utf-8');
  }
  if (payload.parts) {
    const textPart = payload.parts.find((p) => p.mimeType === 'text/plain');
    if (textPart?.body?.data) {
      return Buffer.from(textPart.body.data, 'base64').toString('utf-8');
    }
    const htmlPart = payload.parts.find((p) => p.mimeType === 'text/html');
    if (htmlPart?.body?.data) {
      const html = Buffer.from(htmlPart.body.data, 'base64').toString('utf-8');
      return html.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '').replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    }
    for (const part of payload.parts) {
      const body = getEmailBody(part);
      if (body) return body;
    }
  }
  return '';
}

function getHeader(headers: gmail_v1.Schema$MessagePartHeader[] | undefined, name: string): string {
  return headers?.find((h) => h.name?.toLowerCase() === name.toLowerCase())?.value || '';
}

async function listEmails(args: { maxResults?: number; query?: string; labelIds?: string[] }): Promise<string> {
  const gmail = getGmailClient();
  const { maxResults = 20, query, labelIds = ['INBOX'] } = args;

  const response = await gmail.users.messages.list({
    userId: 'me',
    maxResults: Math.min(maxResults, 100),
    q: query,
    labelIds,
  });

  if (!response.data.messages?.length) return 'No emails found.';

  const emails = await Promise.all(
    response.data.messages.map(async (msg) => {
      const detail = await gmail.users.messages.get({
        userId: 'me',
        id: msg.id!,
        format: 'metadata',
        metadataHeaders: ['From', 'Subject', 'Date'],
      });
      const headers = detail.data.payload?.headers;
      return {
        id: msg.id,
        threadId: msg.threadId,
        from: getHeader(headers, 'From'),
        subject: getHeader(headers, 'Subject'),
        date: getHeader(headers, 'Date'),
        snippet: detail.data.snippet,
        isUnread: detail.data.labelIds?.includes('UNREAD'),
      };
    })
  );

  return JSON.stringify(emails, null, 2);
}

async function readEmail(args: { emailId: string }): Promise<string> {
  const gmail = getGmailClient();
  const response = await gmail.users.messages.get({ userId: 'me', id: args.emailId, format: 'full' });
  const headers = response.data.payload?.headers;
  const body = getEmailBody(response.data.payload!);

  return JSON.stringify({
    id: response.data.id,
    threadId: response.data.threadId,
    from: getHeader(headers, 'From'),
    to: getHeader(headers, 'To'),
    cc: getHeader(headers, 'Cc'),
    subject: getHeader(headers, 'Subject'),
    date: getHeader(headers, 'Date'),
    labels: response.data.labelIds,
    body,
  }, null, 2);
}

async function searchEmails(args: { query: string; maxResults?: number }): Promise<string> {
  return listEmails({ query: args.query, maxResults: args.maxResults });
}

async function markAsRead(args: { emailId: string }): Promise<string> {
  const gmail = getGmailClient();
  await gmail.users.messages.modify({ userId: 'me', id: args.emailId, requestBody: { removeLabelIds: ['UNREAD'] } });
  return `Email ${args.emailId} marked as read.`;
}

async function markAsUnread(args: { emailId: string }): Promise<string> {
  const gmail = getGmailClient();
  await gmail.users.messages.modify({ userId: 'me', id: args.emailId, requestBody: { addLabelIds: ['UNREAD'] } });
  return `Email ${args.emailId} marked as unread.`;
}

async function listLabels(): Promise<string> {
  const gmail = getGmailClient();
  const response = await gmail.users.labels.list({ userId: 'me' });
  return JSON.stringify(response.data.labels, null, 2);
}

async function getThread(args: { threadId: string }): Promise<string> {
  const gmail = getGmailClient();
  const response = await gmail.users.threads.get({ userId: 'me', id: args.threadId, format: 'full' });
  const messages = response.data.messages?.map((msg) => ({
    id: msg.id,
    from: getHeader(msg.payload?.headers, 'From'),
    to: getHeader(msg.payload?.headers, 'To'),
    subject: getHeader(msg.payload?.headers, 'Subject'),
    date: getHeader(msg.payload?.headers, 'Date'),
    body: getEmailBody(msg.payload!),
  }));
  return JSON.stringify({ threadId: response.data.id, messageCount: messages?.length, messages }, null, 2);
}

function buildRawEmail(headers: Record<string, string>, body: string): string {
  const lines = Object.entries(headers)
    .filter(([, v]) => v)
    .map(([k, v]) => `${k}: ${v}`);
  lines.push('Content-Type: text/plain; charset="UTF-8"');
  lines.push('MIME-Version: 1.0');
  lines.push('');
  lines.push(body);
  return Buffer.from(lines.join('\r\n')).toString('base64url');
}

async function sendEmail(args: { to: string; subject: string; body: string; cc?: string; bcc?: string }): Promise<string> {
  const gmail = getGmailClient();
  const raw = buildRawEmail({
    To: args.to,
    Subject: args.subject,
    Cc: args.cc || '',
    Bcc: args.bcc || '',
  }, args.body);

  const response = await gmail.users.messages.send({
    userId: 'me',
    requestBody: { raw },
  });

  return JSON.stringify({ status: 'sent', id: response.data.id, threadId: response.data.threadId }, null, 2);
}

async function replyToEmail(args: { emailId: string; body: string; replyAll?: boolean }): Promise<string> {
  const gmail = getGmailClient();

  // Fetch the original message to get headers
  const original = await gmail.users.messages.get({ userId: 'me', id: args.emailId, format: 'metadata', metadataHeaders: ['From', 'To', 'Cc', 'Subject', 'Message-ID'] });
  const headers = original.data.payload?.headers;
  const from = getHeader(headers, 'From');
  const to = getHeader(headers, 'To');
  const cc = getHeader(headers, 'Cc');
  const subject = getHeader(headers, 'Subject');
  const messageId = getHeader(headers, 'Message-ID');

  const replyTo = args.replyAll ? [from, ...to.split(',')].filter(Boolean).join(', ') : from;
  const replyCc = args.replyAll ? cc : '';

  const raw = buildRawEmail({
    To: replyTo,
    Cc: replyCc,
    Subject: subject.startsWith('Re:') ? subject : `Re: ${subject}`,
    'In-Reply-To': messageId,
    References: messageId,
  }, args.body);

  const response = await gmail.users.messages.send({
    userId: 'me',
    requestBody: { raw, threadId: original.data.threadId! },
  });

  return JSON.stringify({ status: 'sent', id: response.data.id, threadId: response.data.threadId }, null, 2);
}

async function draftEmail(args: { to: string; subject: string; body: string; cc?: string; bcc?: string }): Promise<string> {
  const gmail = getGmailClient();
  const raw = buildRawEmail({
    To: args.to,
    Subject: args.subject,
    Cc: args.cc || '',
    Bcc: args.bcc || '',
  }, args.body);

  const response = await gmail.users.drafts.create({
    userId: 'me',
    requestBody: { message: { raw } },
  });

  return JSON.stringify({ status: 'drafted', id: response.data.id, messageId: response.data.message?.id }, null, 2);
}

async function archiveEmail(args: { emailId: string }): Promise<string> {
  const gmail = getGmailClient();
  await gmail.users.messages.modify({ userId: 'me', id: args.emailId, requestBody: { removeLabelIds: ['INBOX'] } });
  return `Email ${args.emailId} archived.`;
}

async function trashEmail(args: { emailId: string }): Promise<string> {
  const gmail = getGmailClient();
  await gmail.users.messages.trash({ userId: 'me', id: args.emailId });
  return `Email ${args.emailId} moved to trash.`;
}

async function addLabel(args: { emailId: string; labelId: string }): Promise<string> {
  const gmail = getGmailClient();
  await gmail.users.messages.modify({ userId: 'me', id: args.emailId, requestBody: { addLabelIds: [args.labelId] } });
  return `Label ${args.labelId} added to email ${args.emailId}.`;
}

async function removeLabel(args: { emailId: string; labelId: string }): Promise<string> {
  const gmail = getGmailClient();
  await gmail.users.messages.modify({ userId: 'me', id: args.emailId, requestBody: { removeLabelIds: [args.labelId] } });
  return `Label ${args.labelId} removed from email ${args.emailId}.`;
}

function findAttachments(payload: gmail_v1.Schema$MessagePart, results: { filename: string; mimeType: string; attachmentId: string; size: number }[] = []): typeof results {
  if (payload.filename && payload.body?.attachmentId) {
    results.push({
      filename: payload.filename,
      mimeType: payload.mimeType || 'application/octet-stream',
      attachmentId: payload.body.attachmentId,
      size: payload.body.size || 0,
    });
  }
  if (payload.parts) {
    for (const part of payload.parts) findAttachments(part, results);
  }
  return results;
}

async function getAttachment(args: { emailId: string; attachmentId?: string }): Promise<string> {
  const gmail = getGmailClient();
  const message = await gmail.users.messages.get({ userId: 'me', id: args.emailId, format: 'full' });
  const attachments = findAttachments(message.data.payload!);

  if (!attachments.length) return 'No attachments found in this email.';

  if (!args.attachmentId) {
    return JSON.stringify({ emailId: args.emailId, attachments: attachments.map(({ filename, mimeType, attachmentId, size }) => ({ filename, mimeType, attachmentId, size })) }, null, 2);
  }

  const meta = attachments.find(a => a.attachmentId === args.attachmentId);
  const response = await gmail.users.messages.attachments.get({
    userId: 'me',
    messageId: args.emailId,
    id: args.attachmentId,
  });

  return JSON.stringify({
    filename: meta?.filename,
    mimeType: meta?.mimeType,
    size: response.data.size,
    data: response.data.data, // base64url-encoded
  }, null, 2);
}

// ============================================================================
// MCP Server
// ============================================================================

function createMcpServer(): Server {
  const server = new Server(
    { name: 'gmail-mcp', version: '1.0.0' },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    try {
      let result: string;
      switch (name) {
        case 'list_emails': result = await listEmails(args as any); break;
        case 'read_email': result = await readEmail(args as any); break;
        case 'search_emails': result = await searchEmails(args as any); break;
        case 'mark_as_read': result = await markAsRead(args as any); break;
        case 'mark_as_unread': result = await markAsUnread(args as any); break;
        case 'list_labels': result = await listLabels(); break;
        case 'get_thread': result = await getThread(args as any); break;
        case 'send_email': result = await sendEmail(args as any); break;
        case 'reply_to_email': result = await replyToEmail(args as any); break;
        case 'draft_email': result = await draftEmail(args as any); break;
        case 'archive_email': result = await archiveEmail(args as any); break;
        case 'trash_email': result = await trashEmail(args as any); break;
        case 'add_label': result = await addLabel(args as any); break;
        case 'remove_label': result = await removeLabel(args as any); break;
        case 'get_attachment': result = await getAttachment(args as any); break;
        default: throw new Error(`Unknown tool: ${name}`);
      }
      return { content: [{ type: 'text', text: result }] };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return { content: [{ type: 'text', text: `Error: ${message}` }], isError: true };
    }
  });

  return server;
}

// ============================================================================
// HTTP Server with OAuth 2.1 Authorization Server
// ============================================================================

async function main() {
  const app = express();

  const transports = new Map<string, SSEServerTransport>();

  // --------------------------------------------------------------------------
  // Token Validation Middleware (defined early, used by /messages and /sse)
  // --------------------------------------------------------------------------
  function validateToken(req: Request, res: Response, next: () => void) {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith('Bearer ')) {
      res.status(401)
        .set('WWW-Authenticate', `Bearer resource_metadata="${SERVER_URL}/.well-known/oauth-protected-resource"`)
        .json({ error: 'unauthorized' });
      return;
    }

    const token = authHeader.slice(7);
    const tokenData = accessTokens.get(token);

    if (!tokenData || Date.now() > tokenData.expires_at) {
      if (tokenData) {
        accessTokens.delete(token);
        saveTokens();
      }
      res.status(401)
        .set('WWW-Authenticate', `Bearer error="invalid_token"`)
        .json({ error: 'invalid_token' });
      return;
    }

    next();
  }

  // Messages endpoint MUST be defined BEFORE json middleware
  // The SSE transport needs to read the raw body
  app.post('/messages', validateToken, async (req, res) => {
    const sessionId = req.query.sessionId as string;
    const transport = transports.get(sessionId);

    if (!transport) {
      res.status(404).json({ error: 'Session not found' });
      return;
    }

    try {
      await transport.handlePostMessage(req, res);
    } catch (err) {
      console.error('Messages error:', err);
      res.status(500).json({ error: 'Internal error' });
    }
  });

  // Apply JSON middleware for other routes
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // --------------------------------------------------------------------------
  // OAuth 2.0 Protected Resource Metadata (RFC 9728)
  // --------------------------------------------------------------------------
  app.get('/.well-known/oauth-protected-resource', (_req, res) => {
    res.json({
      resource: SERVER_URL,
      authorization_servers: [SERVER_URL],
      scopes_supported: ['gmail.readonly', 'gmail.modify'],
    });
  });

  // --------------------------------------------------------------------------
  // OAuth 2.0 Authorization Server Metadata (RFC 8414)
  // --------------------------------------------------------------------------
  app.get('/.well-known/oauth-authorization-server', (_req, res) => {
    res.json({
      issuer: SERVER_URL,
      authorization_endpoint: `${SERVER_URL}/oauth/authorize`,
      token_endpoint: `${SERVER_URL}/oauth/token`,
      registration_endpoint: `${SERVER_URL}/oauth/register`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      code_challenge_methods_supported: ['S256', 'plain'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
      scopes_supported: ['gmail.readonly', 'gmail.modify'],
    });
  });

  // --------------------------------------------------------------------------
  // Dynamic Client Registration (RFC 7591)
  // --------------------------------------------------------------------------
  app.post('/oauth/register', (req, res) => {
    const { redirect_uris, client_name } = req.body;

    if (!redirect_uris || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
      res.status(400).json({ error: 'invalid_client_metadata', error_description: 'redirect_uris required' });
      return;
    }

    const client_id = generateId(16);
    const client_secret = generateSecret();

    const client: RegisteredClient = {
      client_id,
      client_secret,
      redirect_uris,
      client_name,
      created_at: Date.now(),
    };

    registeredClients.set(client_id, client);
    saveClients();

    console.log(`Registered new client: ${client_id} (${client_name || 'unnamed'})`);

    res.status(201).json({
      client_id,
      client_secret,
      redirect_uris,
      client_name,
      token_endpoint_auth_method: 'client_secret_post',
    });
  });

  // --------------------------------------------------------------------------
  // Authorization Endpoint
  // --------------------------------------------------------------------------
  app.get('/oauth/authorize', (req, res) => {
    const {
      client_id,
      redirect_uri,
      response_type,
      state,
      code_challenge,
      code_challenge_method,
    } = req.query as Record<string, string>;

    // Validate client
    const client = registeredClients.get(client_id);
    if (!client) {
      res.status(400).json({ error: 'invalid_client', error_description: 'Unknown client_id' });
      return;
    }

    // Validate redirect_uri
    if (!client.redirect_uris.includes(redirect_uri)) {
      res.status(400).json({ error: 'invalid_request', error_description: 'Invalid redirect_uri' });
      return;
    }

    // Validate response_type
    if (response_type !== 'code') {
      res.status(400).json({ error: 'unsupported_response_type' });
      return;
    }

    // Store pending auth state
    const authId = generateId(16);
    pendingAuths.set(authId, {
      client_id,
      redirect_uri,
      state,
      code_challenge,
      code_challenge_method: code_challenge_method || 'plain',
      expires_at: Date.now() + 10 * 60 * 1000, // 10 minutes
    });

    // Check if already authenticated with Google
    if (isGoogleAuthenticated()) {
      // Skip Google OAuth, directly issue code
      const code = generateId(32);
      const authData = pendingAuths.get(authId)!;
      pendingAuths.delete(authId);

      authorizationCodes.set(code, {
        code,
        client_id: authData.client_id,
        redirect_uri: authData.redirect_uri,
        code_challenge: authData.code_challenge,
        code_challenge_method: authData.code_challenge_method,
        expires_at: Date.now() + 10 * 60 * 1000, // 10 minutes
      });

      const redirectUrl = new URL(authData.redirect_uri);
      redirectUrl.searchParams.set('code', code);
      if (authData.state) redirectUrl.searchParams.set('state', authData.state);

      res.redirect(redirectUrl.toString());
      return;
    }

    // Redirect to Google OAuth
    const googleOAuth = getGoogleOAuth2Client();
    const googleAuthUrl = googleOAuth.generateAuthUrl({
      access_type: 'offline',
      scope: GOOGLE_SCOPES,
      prompt: 'consent',
      state: authId, // Pass our auth ID to Google
    });

    res.redirect(googleAuthUrl);
  });

  // --------------------------------------------------------------------------
  // Google OAuth Callback
  // --------------------------------------------------------------------------
  app.get('/google/callback', async (req, res) => {
    const { code: googleCode, state: authId, error } = req.query as Record<string, string>;

    if (error) {
      res.status(400).send(`Google authentication failed: ${error}`);
      return;
    }

    const authData = pendingAuths.get(authId);
    if (!authData) {
      res.status(400).send('Invalid or expired authentication session');
      return;
    }

    pendingAuths.delete(authId);

    try {
      // Exchange Google code for tokens
      const googleOAuth = getGoogleOAuth2Client();
      const { tokens } = await googleOAuth.getToken(googleCode);
      writeFileSync(TOKEN_PATH, JSON.stringify(tokens, null, 2));

      // Generate our authorization code
      const code = generateId(32);
      authorizationCodes.set(code, {
        code,
        client_id: authData.client_id,
        redirect_uri: authData.redirect_uri,
        code_challenge: authData.code_challenge,
        code_challenge_method: authData.code_challenge_method,
        expires_at: Date.now() + 10 * 60 * 1000,
      });

      // Redirect back to client with our code
      const redirectUrl = new URL(authData.redirect_uri);
      redirectUrl.searchParams.set('code', code);
      if (authData.state) redirectUrl.searchParams.set('state', authData.state);

      console.log(`Google auth successful, redirecting to client`);
      res.redirect(redirectUrl.toString());
    } catch (err) {
      console.error('Google token exchange failed:', err);
      res.status(500).send(`Token exchange failed: ${err}`);
    }
  });

  // --------------------------------------------------------------------------
  // Token Endpoint
  // --------------------------------------------------------------------------
  app.post('/oauth/token', (req, res) => {
    const {
      grant_type,
      code,
      redirect_uri,
      client_id,
      client_secret,
      code_verifier,
    } = req.body;

    if (grant_type !== 'authorization_code') {
      res.status(400).json({ error: 'unsupported_grant_type' });
      return;
    }

    // Validate authorization code
    const authCode = authorizationCodes.get(code);
    if (!authCode) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid authorization code' });
      return;
    }

    // Check expiration
    if (Date.now() > authCode.expires_at) {
      authorizationCodes.delete(code);
      res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code expired' });
      return;
    }

    // Validate client
    if (authCode.client_id !== client_id) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'Client mismatch' });
      return;
    }

    // Validate redirect_uri
    if (authCode.redirect_uri !== redirect_uri) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'Redirect URI mismatch' });
      return;
    }

    // Validate PKCE
    if (authCode.code_challenge) {
      if (!code_verifier) {
        res.status(400).json({ error: 'invalid_grant', error_description: 'Code verifier required' });
        return;
      }

      let expectedChallenge: string;
      if (authCode.code_challenge_method === 'S256') {
        expectedChallenge = hashCodeChallenge(code_verifier);
      } else {
        expectedChallenge = code_verifier;
      }

      if (expectedChallenge !== authCode.code_challenge) {
        res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid code verifier' });
        return;
      }
    }

    // Validate client secret (if client has one)
    const client = registeredClients.get(client_id);
    if (client?.client_secret && client.client_secret !== client_secret) {
      res.status(401).json({ error: 'invalid_client', error_description: 'Invalid client secret' });
      return;
    }

    // Consume the authorization code
    authorizationCodes.delete(code);

    // Generate access token
    const accessToken = generateId(32);
    const expiresIn = 86400 * 30; // 30 days

    accessTokens.set(accessToken, {
      token: accessToken,
      client_id,
      expires_at: Date.now() + expiresIn * 1000,
    });

    // Persist tokens to disk
    saveTokens();

    console.log(`Issued access token for client: ${client_id}`);

    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: expiresIn,
      scope: 'gmail.readonly gmail.modify',
    });
  });

  // --------------------------------------------------------------------------
  // SSE Endpoint (Protected)
  // --------------------------------------------------------------------------
  app.get('/sse', validateToken, async (req, res) => {
    if (!isGoogleAuthenticated()) {
      res.status(503).json({ error: 'Google authentication required' });
      return;
    }

    try {
      const transport = new SSEServerTransport('/messages', res);
      const sessionId = transport.sessionId;
      transports.set(sessionId, transport);

      const server = createMcpServer();

      res.on('close', () => {
        transports.delete(sessionId);
      });

      await server.connect(transport);
    } catch (err) {
      console.error('SSE error:', err);
      res.status(500).json({ error: 'SSE connection failed' });
    }
  });

  // --------------------------------------------------------------------------
  // Health & Status Endpoints
  // --------------------------------------------------------------------------
  app.get('/health', (_req, res) => {
    res.json({
      status: 'ok',
      google_authenticated: isGoogleAuthenticated(),
      registered_clients: registeredClients.size,
      active_tokens: accessTokens.size,
    });
  });

  // --------------------------------------------------------------------------
  // Periodic cleanup of expired auth state
  // --------------------------------------------------------------------------
  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [key, code] of authorizationCodes) {
      if (now > code.expires_at) authorizationCodes.delete(key);
    }
    for (const [key, auth] of pendingAuths) {
      if (now > auth.expires_at) pendingAuths.delete(key);
    }
  }, 60_000);

  // --------------------------------------------------------------------------
  // Start Server
  // --------------------------------------------------------------------------
  const server = app.listen(PORT, () => {
    console.log(`Gmail MCP server running at ${SERVER_URL}`);
    console.log(`Config directory: ${CONFIG_DIR}`);
    console.log(`Google auth status: ${isGoogleAuthenticated() ? 'authenticated' : 'not authenticated'}`);
    console.log(`Registered clients: ${registeredClients.size}`);
    console.log(`\nOAuth endpoints:`);
    console.log(`  Authorization: ${SERVER_URL}/oauth/authorize`);
    console.log(`  Token:         ${SERVER_URL}/oauth/token`);
    console.log(`  Registration:  ${SERVER_URL}/oauth/register`);
  });

  // --------------------------------------------------------------------------
  // Graceful Shutdown
  // --------------------------------------------------------------------------
  function shutdown() {
    console.log('\nShutting down...');
    clearInterval(cleanupInterval);
    for (const [id, transport] of transports) {
      try { transport.close?.(); } catch {}
      transports.delete(id);
    }
    server.close(() => {
      console.log('Server stopped.');
      process.exit(0);
    });
    // Force exit after 5 seconds if connections don't close
    setTimeout(() => process.exit(0), 5000);
  }

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch(console.error);
