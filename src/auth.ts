#!/usr/bin/env node
/**
 * Standalone OAuth authentication script.
 * Run this once to authenticate and store tokens.
 *
 * Usage: npm run auth
 */

import { google } from 'googleapis';
import { createServer } from 'http';
import { URL } from 'url';
import open from 'open';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONFIG_DIR = join(__dirname, '..');
const CREDENTIALS_PATH = join(CONFIG_DIR, 'credentials.json');
const TOKEN_PATH = join(CONFIG_DIR, 'token.json');

const SCOPES = [
  'https://www.googleapis.com/auth/gmail.readonly',
  'https://www.googleapis.com/auth/gmail.modify',
];

interface Credentials {
  installed?: {
    client_id: string;
    client_secret: string;
    redirect_uris: string[];
  };
  web?: {
    client_id: string;
    client_secret: string;
    redirect_uris: string[];
  };
}

async function authenticate(): Promise<void> {
  // Check for credentials file
  if (!existsSync(CREDENTIALS_PATH)) {
    console.error('Error: credentials.json not found.');
    console.error('');
    console.error('To set up credentials:');
    console.error('1. Go to https://console.cloud.google.com/apis/credentials');
    console.error('2. Create an OAuth 2.0 Client ID (Desktop app type)');
    console.error('3. Download the JSON and save it as credentials.json in this directory');
    process.exit(1);
  }

  const content = readFileSync(CREDENTIALS_PATH, 'utf-8');
  const credentials: Credentials = JSON.parse(content);
  const { client_id, client_secret } = credentials.installed || credentials.web || {};

  if (!client_id || !client_secret) {
    console.error('Error: Invalid credentials.json format');
    process.exit(1);
  }

  const oauth2Client = new google.auth.OAuth2(
    client_id,
    client_secret,
    'http://localhost:3000/callback'
  );

  // Start local server to receive callback
  const authCode = await new Promise<string>((resolve, reject) => {
    const server = createServer((req, res) => {
      const url = new URL(req.url || '', 'http://localhost:3000');

      if (url.pathname === '/callback') {
        const code = url.searchParams.get('code');
        const error = url.searchParams.get('error');

        if (error) {
          res.writeHead(400, { 'Content-Type': 'text/html' });
          res.end(`<h1>Authentication failed</h1><p>${error}</p>`);
          server.close();
          reject(new Error(error));
          return;
        }

        if (code) {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`
            <h1>Authentication successful!</h1>
            <p>You can close this window and return to the terminal.</p>
            <script>window.close()</script>
          `);
          server.close();
          resolve(code);
        }
      }
    });

    server.listen(3000, () => {
      const authUrl = oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: SCOPES,
        prompt: 'consent', // Force to get refresh token
      });

      console.log('Opening browser for authentication...');
      console.log('');
      console.log('If the browser does not open, visit this URL:');
      console.log(authUrl);
      console.log('');

      open(authUrl);
    });

    // Timeout after 5 minutes
    setTimeout(() => {
      server.close();
      reject(new Error('Authentication timed out'));
    }, 5 * 60 * 1000);
  });

  // Exchange code for tokens
  console.log('Exchanging code for tokens...');
  const { tokens } = await oauth2Client.getToken(authCode);

  // Save tokens
  writeFileSync(TOKEN_PATH, JSON.stringify(tokens, null, 2));
  console.log('');
  console.log('Authentication successful! Tokens saved to token.json');
  console.log('');
  console.log('You can now use the Gmail MCP server.');
}

authenticate().catch(console.error);
