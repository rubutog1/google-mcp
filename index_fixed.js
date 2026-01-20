#!/usr/bin/env node

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { randomUUID } = require('crypto');
const { google } = require('googleapis');

const app = express();
app.use(express.json({ limit: '20mb' }));
app.use(cors({ origin: '*', exposedHeaders: ['Mcp-Session-Id'] }));

const PORT = process.env.PORT || 3001;
const BEARER = process.env.AUTH_BEARER_TOKEN || null;
const ALLOW_ANONYMOUS = process.env.ALLOW_ANONYMOUS === '1';
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`;

const credsDir = path.join(__dirname, '..', 'gdrive-mcp-server', 'credentials');
let oauthPath = process.env.GOOGLE_APPLICATION_CREDENTIALS || path.join(credsDir, 'gcp-oauth.keys.json');
const tokensDir = path.join(__dirname, 'tokens');
if (!fs.existsSync(tokensDir)) fs.mkdirSync(tokensDir, { recursive: true });

let oauthClientJson = null;
if (fs.existsSync(oauthPath)) {
  try { oauthClientJson = JSON.parse(fs.readFileSync(oauthPath, 'utf8')); } catch (e) { console.warn('Failed to parse OAuth client JSON', e && e.message); }
}

let OAUTH_CLIENT_ID = null;
let OAUTH_CLIENT_SECRET = null;
let OAUTH_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || null;
if (oauthClientJson) {
  const clientInfo = oauthClientJson.web || oauthClientJson.installed || oauthClientJson;
  OAUTH_CLIENT_ID = clientInfo.client_id;
  OAUTH_CLIENT_SECRET = clientInfo.client_secret;
  const redirectUris = clientInfo.redirect_uris || [];
  OAUTH_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || redirectUris.find((u) => /\/auth\/callback$/.test(u)) || redirectUris[0] || OAUTH_REDIRECT_URI;
}

function makeOauthClient() {
  return new google.auth.OAuth2(OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_REDIRECT_URI);
}

app.get('/health', (req, res) => {
  res.json({ ok: true, oauthConfigured: !!OAUTH_CLIENT_ID, tokensDirExists: fs.existsSync(tokensDir) });
});

app.get('/auth/url', (req, res) => {
  if (!OAUTH_CLIENT_ID) return res.status(500).json({ ok: false, error: 'OAuth client not configured' });
  const session = String(req.query?.session || randomUUID());
  const oauth2 = makeOauthClient();
  const scopes = [
    'https://www.googleapis.com/auth/drive',
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/calendar'
  ];
  const url = oauth2.generateAuthUrl({ access_type: 'offline', scope: scopes, prompt: 'consent', state: JSON.stringify({ session }) });
  res.json({ ok: true, auth_url: url });
});

app.get('/auth/start', (req, res) => {
  const session = String(req.query?.session || randomUUID());
  if (!OAUTH_CLIENT_ID) return res.status(500).send('OAuth client not configured');
  const oauth2 = makeOauthClient();
  const scopes = ['https://www.googleapis.com/auth/drive', 'openid', 'https://www.googleapis.com/auth/userinfo.email'];
  const url = oauth2.generateAuthUrl({ access_type: 'offline', scope: scopes, prompt: 'consent', state: JSON.stringify({ session }) });
  res.redirect(url);
});

app.get('/auth/callback', async (req, res) => {
  try {
    const code = req.query.code;
    const state = req.query.state ? JSON.parse(String(req.query.state)) : {};
    const session = state.session || req.query.session || randomUUID();
    if (!code) return res.status(400).send('Missing code');
    const oauth2 = makeOauthClient();
    const r = await oauth2.getToken(String(code));
    const tokens = r?.tokens || r;
    // persist tokens to a file named by session as a minimal fallback
    try {
      fs.writeFileSync(path.join(tokensDir, `${session}.json`), JSON.stringify(tokens), { encoding: 'utf8', mode: 0o600 });
    } catch (e) { console.warn('Failed to write session tokens file', e && e.message); }
    res.send('<html><body><h3>Authentication complete. You can close this window.</h3><script>window.close()</script></body></html>');
  } catch (e) {
    console.error('OAuth callback failed', e && e.stack);
    res.status(500).send('OAuth callback failed: ' + String(e && e.message));
  }
});

app.get('/oauth2callback', (req, res) => {
  const qs = Object.keys(req.query || {}).map(k => `${encodeURIComponent(k)}=${encodeURIComponent(req.query[k])}`).join('&');
  res.redirect(`/auth/callback${qs ? '?' + qs : ''}`);
});

app.post('/mcp', (req, res) => {
  const h = req.headers['authorization'] || req.headers['Authorization'];
  if (!BEARER && !ALLOW_ANONYMOUS) return res.status(401).json({ ok: false, error: 'Server bearer not configured' });
  if (BEARER && (!h || !h.startsWith('Bearer ') || h.slice(7).trim() !== BEARER)) return res.status(403).json({ ok: false, error: 'Forbidden' });
  // Minimal MCP relay: return tool list for clients
  res.json({ ok: true, tools: ['connect_gdrive', 'list_drive_files', 'gdrive_read_file', 'list_emails', 'read_email', 'send_email', 'list_calendar_events', 'create_calendar_event'] });
});

app.listen(PORT, () => console.log('Minimal MCP HTTP server listening on port', PORT));

