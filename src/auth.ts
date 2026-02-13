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
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const CONFIG_DIR = join(homedir(), '.config', 'gmail-mcp');
mkdirSync(CONFIG_DIR, { recursive: true });
const CREDENTIALS_PATH = join(CONFIG_DIR, 'credentials.json');
const TOKEN_PATH = join(CONFIG_DIR, 'token.json');

const DEFAULT_GOOGLE_CREDENTIALS = {
  client_id: '52009412064-k1u1a1n7k0hdaolgtkjnm9q03iq945ds.apps.googleusercontent.com',
  client_secret: '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',
};

const SCOPES = [
  'https://www.googleapis.com/auth/gmail.readonly',
  'https://www.googleapis.com/auth/gmail.modify',
];

async function authenticate(): Promise<void> {
  let client_id: string;
  let client_secret: string;

  if (existsSync(CREDENTIALS_PATH)) {
    try {
      const credentials = JSON.parse(readFileSync(CREDENTIALS_PATH, 'utf-8'));
      const creds = credentials.installed || credentials.web;
      client_id = creds?.client_id;
      client_secret = creds?.client_secret;
    } catch {
      client_id = DEFAULT_GOOGLE_CREDENTIALS.client_id;
      client_secret = DEFAULT_GOOGLE_CREDENTIALS.client_secret;
    }
  } else {
    console.log('Using built-in Google OAuth credentials.');
    console.log('(To use your own, place a credentials.json in ' + CONFIG_DIR + ')');
    console.log('');
    client_id = DEFAULT_GOOGLE_CREDENTIALS.client_id;
    client_secret = DEFAULT_GOOGLE_CREDENTIALS.client_secret;
  }

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
  console.log(`Authentication successful! Tokens saved to ${TOKEN_PATH}`);
  console.log('');
  console.log('You can now use the Gmail MCP server.');
}

authenticate().catch(console.error);
