#!/usr/bin/env node
function timeAgo(d) {
  try {
    const now = new Date();
    const then = new Date(d);
    const diffMs = then.getTime() - now.getTime();
    const absMs = Math.abs(diffMs);
    const mins = Math.round(absMs / (60 * 1000));
    if (mins < 1) return diffMs >= 0 ? 'in <1 minute' : '<1 minute ago';
    if (mins < 60) return diffMs >= 0 ? `in ${mins} minute${mins === 1 ? '' : 's'}` : `${mins} minute${mins === 1 ? '' : 's'} ago`;
    const hours = Math.round(mins / 60);
    if (hours < 24) return diffMs >= 0 ? `in ${hours} hour${hours === 1 ? '' : 's'}` : `${hours} hour${hours === 1 ? '' : 's'} ago`;
    const days = Math.round(hours / 24);
    if (days < 30) return diffMs >= 0 ? `in ${days} day${days === 1 ? '' : 's'}` : `${days} day${days === 1 ? '' : 's'} ago`;
    const months = Math.round(days / 30);
    if (months < 12) return diffMs >= 0 ? `in ${months} month${months === 1 ? '' : 's'}` : `${months} month${months === 1 ? '' : 's'} ago`;
    const years = Math.round(months / 12);
    return diffMs >= 0 ? `in ${years} year${years === 1 ? '' : 's'}` : `${years} year${years === 1 ? '' : 's'} ago`;
  } catch (e) {
    return '';
  }
}
/**
 * GDrive MCP HTTP server – refactored with Gmail/Calendar fixes
 * Modes:
 *   REQUIRE_SESSION_ONLY=1  → each MCP session must authorize its own Google account
 *   USE_SHARED_TOKEN=1      → permissive mode can reuse a stable token across sessions
 *   ALLOW_ANONYMOUS=1       → allow /mcp without server bearer token (dev only)
 *
 * Required env:
 *   AUTH_BEARER_TOKEN        → bearer for /mcp unless ALLOW_ANONYMOUS=1
 *   PUBLIC_BASE_URL          → external https base, e.g. https://<ngrok>.ngrok-free.dev
 *   PORT                     → default 3000
 *
 * Google OAuth:
 *   GOOGLE_APPLICATION_CREDENTIALS  → path to client JSON
 *   or GOOGLE_OAUTH_JSON            → client JSON contents
 *   MCP_GDRIVE_CREDENTIALS          → path to saved owner creds (optional, permissive mode)
 *   MCP_GDRIVE_CREDENTIALS_JSON     → saved owner creds contents (optional, permissive mode)
 */

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { randomUUID } = require('crypto');
const { google } = require('googleapis');
const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const {
  isInitializeRequest,
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListToolsRequestSchema
} = require('@modelcontextprotocol/sdk/types.js');

try {
  process.umask(0o077);
} catch {}

const app = express();
app.use(express.json({ limit: '10mb' }));

// CORS
app.use(
  cors({
    origin: '*',
    exposedHeaders: ['Mcp-Session-Id'],
    allowedHeaders: [
      'Content-Type',
      'authorization',
      'mcp-session-id',
      'Mcp-Session-Id',
      'mcp-protocol-version',
      'Mcp-Protocol-Version',
      'ngrok-skip-browser-warning'
    ]
  })
);

// Config
const PORT = process.env.PORT || 3001;
const BEARER = process.env.AUTH_BEARER_TOKEN || null;
const ALLOW_ANONYMOUS = process.env.ALLOW_ANONYMOUS === '1';
const USE_SHARED_TOKEN = process.env.USE_SHARED_TOKEN === '1';
const REQUIRE_SESSION_ONLY = process.env.REQUIRE_SESSION_ONLY === '1';
const PUBLIC_BASE_URL =
  process.env.PUBLIC_BASE_URL || process.env.PUBLIC_URL || `http://localhost:${PORT}`;

console.log('[AUTH MODE]', REQUIRE_SESSION_ONLY ? 'require-session-only' : 'permissive');

// Bearer auth for /mcp and helper routes
function checkAuth(req, res, next) {
  if (!BEARER) {
    if (ALLOW_ANONYMOUS) return next();
    return res.status(401).json({ error: 'Missing server bearer token configuration' });
  }
  const h = req.headers['authorization'] || req.headers['Authorization'];
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing Authorization' });
  const token = h.slice(7).trim();
  if (token !== BEARER) return res.status(403).json({ error: 'Forbidden' });
  next();
}

function mask(str) {
  try {
    return String(str)
      .replace(/ya29\.[\w\-.]+/g, 'ya29.[redacted]')
      .replace(/(Authorization:\s*Bearer\s+)[^\s]+/gi, '$1[redacted]');
  } catch {
    return '[redacted]';
  }
}

// Paths
const credsDir = path.join(__dirname, '..', 'gdrive-mcp-server', 'credentials');
let oauthPath =
  process.env.GOOGLE_APPLICATION_CREDENTIALS || path.join(credsDir, 'gcp-oauth.keys.json');
let savedCredsPath =
  process.env.MCP_GDRIVE_CREDENTIALS ||
  path.join(credsDir, '.gdrive-server-credentials.json');

const tokensDir = path.join(__dirname, 'tokens');
if (!fs.existsSync(tokensDir)) fs.mkdirSync(tokensDir, { recursive: true });

// Allow JSON via env
try {
  if (process.env.GOOGLE_OAUTH_JSON) {
    const p = path.join('/tmp', 'gcp-oauth.keys.json');
    fs.writeFileSync(p, process.env.GOOGLE_OAUTH_JSON, 'utf8');
    oauthPath = p;
    console.log('Loaded GOOGLE_OAUTH_JSON into', p);
  }
  if (process.env.MCP_GDRIVE_CREDENTIALS_JSON) {
    const p2 = path.join('/tmp', '.gdrive-server-credentials.json');
    fs.writeFileSync(p2, process.env.MCP_GDRIVE_CREDENTIALS_JSON, 'utf8');
    savedCredsPath = p2;
    console.log('Loaded MCP_GDRIVE_CREDENTIALS_JSON into', p2);
  }
} catch (e) {
  console.warn('Failed to load JSON credential env vars:', e && e.message);
}

if (!fs.existsSync(oauthPath)) console.error('OAuth client JSON not found at', oauthPath);
if (!fs.existsSync(savedCredsPath) && !REQUIRE_SESSION_ONLY)
  console.error('Saved OAuth credentials not found at', savedCredsPath);

const savedCredentials = fs.existsSync(savedCredsPath)
  ? JSON.parse(fs.readFileSync(savedCredsPath, 'utf8'))
  : null;
const ownerCreds = REQUIRE_SESSION_ONLY ? null : savedCredentials;

// Read client JSON
let oauthClientJson = null;
if (fs.existsSync(oauthPath)) {
  try {
    oauthClientJson = JSON.parse(fs.readFileSync(oauthPath, 'utf8'));
  } catch (e) {
    console.warn('Failed to parse OAuth client JSON at', oauthPath, e && e.message);
  }
} else {
  console.warn('OAuth client JSON not found at', oauthPath);
}

// Extract client info
let OAUTH_CLIENT_ID = null;
let OAUTH_CLIENT_SECRET = null;
let OAUTH_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || null;

if (oauthClientJson) {
  const clientInfo = oauthClientJson.web || oauthClientJson.installed || oauthClientJson;
  OAUTH_CLIENT_ID = clientInfo.client_id;
  OAUTH_CLIENT_SECRET = clientInfo.client_secret;
  const redirectUris = clientInfo.redirect_uris || clientInfo.redirectUri || [];
  
  // FIXED: Proper redirect URI precedence
  OAUTH_REDIRECT_URI =
    process.env.GOOGLE_REDIRECT_URI ||
    (redirectUris && redirectUris.find((u) => /\/auth\/callback$/.test(u))) ||
    (redirectUris && redirectUris[0]) ||
    null;
    
  if (!OAUTH_REDIRECT_URI) {
    throw new Error('Missing OAuth redirect URI. Set GOOGLE_REDIRECT_URI or ensure client JSON contains a redirect_uri');
  }
}

// Token store
const { loadTokens, saveTokensForSession, listStableAccounts, deleteSession } = require('./tokenStore');

function sessionTokenPath(sessionId) {
  return path.join(tokensDir, `${sessionId}.json`);
}

function persistTokens(sessionId, tokens, acctKey = null) {
  try {
    saveTokensForSession(sessionId, tokens, acctKey || undefined);
    console.log('Saved tokens for session', sessionId, acctKey || '(no acct)');
    return true;
  } catch (e) {
    console.warn('saveTokensForSession failed, fallback to file for session', sessionId, e && (e.stack || e));
    try {
      const payload = { tokens, account: acctKey || null };
      fs.writeFileSync(sessionTokenPath(sessionId), JSON.stringify(payload), { encoding: 'utf8', mode: 0o600 });
      console.log('Wrote token fallback file for session', sessionId);
      return true;
    } catch (e2) {
      console.error('Failed to persist tokens for', sessionId, e2 && (e2.stack || e2));
      return false;
    }
  }
}

function saveSessionTokens(sessionId, tokens, acctKey = null) {
  const ok = persistTokens(sessionId, tokens, acctKey);
  if (!ok) throw new Error(`Unable to persist tokens for session ${sessionId}`);
}

// Auto bind a stable account to a fresh session in permissive mode
function ensureSessionHasTokens(sessionId) {
  try {
    const found = loadTokens(sessionId, { permissiveFallback: true });
    if (found && found.tokens) return true;
  } catch (e) {
    console.warn('ensureSessionHasTokens: loadTokens failed', e && (e.stack || e));
  }
  if (!sessionId) return false;
  const stableAccounts = listStableAccounts();
  if (stableAccounts.length === 0) return false;
  const acct = stableAccounts[0];
  console.log(`[AUTH] Auto-binding stable account ${acct} to new session ${sessionId}`);
  try {
    const stableTokens = loadTokens(null, { permissiveFallback: true, account: acct });
    if (stableTokens?.tokens) {
      const ok = persistTokens(sessionId, stableTokens.tokens, acct);
      if (ok) return true;
      console.warn('Auto-binding tokens were not persisted for session', sessionId);
    }
  } catch (e) {
    console.warn('ensureSessionHasTokens: failed to auto-bind', e && (e.stack || e));
  }
  return false;
}

// Hydrate an OAuth2 client from persisted tokens
async function ensureSessionHydrate(sessionId) {
  if (!sessionId) return null;
  try {
    try {
      const found = loadTokens(sessionId, { permissiveFallback: false });
      if (found && found.tokens) {
        const oauth2 = new google.auth.OAuth2(OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_REDIRECT_URI);
        oauth2.setCredentials(found.tokens);
        return oauth2;
      }
    } catch (e) {
      // ignore and fall through to file check
    }

    const tokenPath = path.join(tokensDir, `${sessionId}.json`);
    if (fs.existsSync(tokenPath)) {
      const raw = JSON.parse(fs.readFileSync(tokenPath, 'utf8'));
      const tokens = raw && raw.tokens ? raw.tokens : raw;
      const oauth2 = new google.auth.OAuth2(OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_REDIRECT_URI);
      oauth2.setCredentials(tokens);
      return oauth2;
    }
  } catch (e) {
    console.warn('ensureSessionHydrate failed', e && (e.stack || e));
  }
  return null;
}

function buildAuthRequired(sessionId) {
  const base = String(PUBLIC_BASE_URL || '').replace(/\/$/, '');
  const authUrl = `${base}/auth/start?session=${encodeURIComponent(sessionId || '')}`;
  return {
    ok: false,
    code: 'AUTH_REQUIRED',
    auth_url: authUrl,
    message: 'User authorization required to access Google Drive.',
  };
}

// Helpers
function logGoogleError(where, err) {
  const code = err?.code || err?.response?.status || null;
  const data = err?.errors || err?.response?.data || err?.response?.data?.error || err?.message || String(err);
  console.error(`[GoogleError] ${where}`, { code, data: typeof data === 'string' ? data : JSON.stringify(data) });
  return { code, data };
}

function buildDriveError(code, data) {
  return { ok: false, type: 'DRIVE_ERROR', code, data };
}

function isInvalidGrant(e) {
  const desc = e?.data?.error_description || e?.message || '';
  const err = e?.data?.error || e?.error || '';
  const reason = (Array.isArray(e?.errors) && e.errors[0]?.reason) || '';
  return (
    err === 'invalid_grant' ||
    /invalid[_\s-]?grant/i.test(reason) ||
    /token.*(expired|revoked)/i.test(desc) ||
    /malformed|bad request|unauthorized[_\s-]?client/i.test(desc)
  );
}

// CONSOLIDATED ERROR HANDLER - reduces duplicate code
function handleToolError(err, toolName, drv) {
  console.error(`[${toolName}] Error:`, err && (err.stack || err));
  const { code, data } = logGoogleError(toolName, err);
  const status = Number(code);
  
  if (String(code) === '400' && isInvalidGrant({ code, data })) {
    try {
      cleanupSession(drv.sessionId);
    } catch {}
    return { content: authRequiredContent(drv.sessionId, 'Token expired or revoked'), isError: false };
  }
  if (status === 401)
    return { content: authRequiredContent(drv.sessionId, 'Unauthorized 401 from Google'), isError: false };
  if (status === 403) {
    const looksLikeScope = /insufficient|scope|permission/i.test(JSON.stringify(data));
    if (looksLikeScope)
      return { content: authRequiredContent(drv.sessionId, 'Insufficient scopes or permissions'), isError: false };
    return { content: [{ type: 'json', json: buildDriveError(code, data) }], isError: true };
  }
  
  return { content: [{ type: 'json', json: buildDriveError(code, data) }], isError: true };
}

// Build Drive for session
function makeDriveForSession(sessionId, requireSessionOnly = REQUIRE_SESSION_ONLY, account = null) {
  const oauth2 = new google.auth.OAuth2(OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_REDIRECT_URI);

  // Shared token in permissive mode
  if (USE_SHARED_TOKEN && !requireSessionOnly) {
    const stableAccounts = listStableAccounts();
    if (stableAccounts.length > 0) {
      const shared = loadTokens(null, { permissiveFallback: true, account: stableAccounts[0] });
      if (shared?.tokens) {
        oauth2.setCredentials(shared.tokens);
        console.log(`[AUTH] Using shared token for account: ${shared.account}`);
        return { drive: google.drive({ version: 'v3', auth: oauth2 }), oauth2, acctKey: shared.account, sessionId };
      }
    }
  }

  console.log(requireSessionOnly ? '[AUTH MODE] per-session required' : '[AUTH MODE] permissive');

  const found = loadTokens(sessionId, { permissiveFallback: !requireSessionOnly });

  if (!found) {
    const choices = listStableAccounts();
    if (!account && choices.length > 1) {
      const e = new Error(`Multiple accounts available. Pass email: ${choices.join(', ')}`);
      throw e;
    }
  }

  if (found && found.source === 'session') {
    try {
      oauth2.setCredentials(found.tokens);
      console.log('Using per-session tokens for', sessionId, 'bound to', found.account || '(unknown)');
    } catch (e) {
      console.warn('Failed to set session credentials:', e && e.message);
    }
    return { drive: google.drive({ version: 'v3', auth: oauth2 }), oauth2, acctKey: found.account || null, sessionId };
  }

  if (requireSessionOnly) {
    const e = new Error('No per-session credentials found; this MCP session requires per-user authorization');
    e.missingSessionId = sessionId;
    console.log('No per-session credentials for', sessionId, '; requiring user auth');
    throw e;
  }

  if (!requireSessionOnly && found && found.source === 'stable') {
    try {
      oauth2.setCredentials(found.tokens);
      console.log('Using stable tokens fallback (account:', found.account, ')');
      try {
        saveTokensForSession(sessionId, found.tokens, found.account);
        console.log(`Bound stable account ${found.account} to session ${sessionId}`);
      } catch (e) {
        console.warn('Failed to bind stable token to session', e && e.message);
      }
      return { drive: google.drive({ version: 'v3', auth: oauth2 }), oauth2, acctKey: found.account, sessionId };
    } catch (e) {
      console.warn('Failed to set stable credentials', e && e.message);
    }
  }

  if (ownerCreds && !requireSessionOnly) {
    try {
      oauth2.setCredentials(ownerCreds);
      console.log('Using saved owner credentials');
    } catch {}
    return { drive: google.drive({ version: 'v3', auth: oauth2 }), oauth2, acctKey: null, sessionId };
  }

  const e = new Error('No credentials available; authorization required');
  e.missingSessionId = sessionId;
  console.log('No credentials found at all for', sessionId);
  throw e;
}

// Single retry with refresh and persistence
async function callWithAutoRefresh(actionFn, oauth2, sessionId, acctKey) {
  try {
    return await actionFn();
  } catch (err) {
    const status = err?.code || err?.response?.status;
    if (Number(status) === 401) {
      console.log('401 detected, attempting token refresh for session', sessionId);
      try {
        let newCreds = null;
        if (typeof oauth2.refreshAccessToken === 'function') {
          const r = await oauth2.refreshAccessToken();
          newCreds = r && r.credentials ? r.credentials : oauth2.credentials;
        } else if (oauth2?.credentials?.refresh_token) {
          await oauth2.getAccessToken();
          newCreds = oauth2.credentials;
        }
        if (newCreds) {
          oauth2.setCredentials(newCreds);
          const ok = persistTokens(sessionId, newCreds, acctKey);
          if (!ok) {
            const e = new Error('Failed to persist refreshed tokens');
            e.missingSessionId = sessionId;
            throw e;
          }
        }
      } catch (refreshErr) {
        console.warn('Token refresh failed for session', sessionId, refreshErr && (refreshErr.stack || refreshErr));
        if (isInvalidGrant(refreshErr)) {
          try {
            cleanupSession(sessionId);
          } catch (cleanupErr) {
            console.warn('cleanupSession failed', cleanupErr && (cleanupErr.stack || cleanupErr));
          }
          const e = new Error('invalid_grant');
          e.missingSessionId = sessionId;
          throw e;
        }
        throw refreshErr;
      }
      return await actionFn();
    }
    throw err;
  }
}

function cleanupSession(sessionId) {
  try {
    if (!sessionId) return;
    try {
      deleteSession(sessionId);
    } catch (e) {
      console.warn('deleteSession failed for', sessionId, e && (e.stack || e));
    }
    try {
      if (transports[sessionId] && typeof transports[sessionId].close === 'function') {
        transports[sessionId].close();
        delete transports[sessionId];
        console.log('Closed transport for session', sessionId);
      }
    } catch (e) {
      console.warn('Failed to close transport for', sessionId, e && (e.stack || e));
    }
  } catch (e) {
    console.warn('cleanupSession error', e && (e.stack || e));
  }
}

// HELPER: Extract email body from Gmail payload
function extractEmailBody(payload) {
  if (!payload) return null;
  if (payload.body && payload.body.data) {
    const d = payload.body.data;
    try {
      return Buffer.from(d.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    } catch (e) {
      return null;
    }
  }
  if (Array.isArray(payload.parts)) {
    for (const p of payload.parts) {
      const r = extractEmailBody(p);
      if (r) return r;
    }
  }
  return null;
}

// HELPER: Fetch Gmail messages with metadata
async function fetchGmailMessages(gmail, oauth2, sessionId, acctKey, messageIds) {
  const results = [];
  for (const m of messageIds) {
    try {
      const md = await callWithAutoRefresh(
        () => gmail.users.messages.get({ userId: 'me', id: m.id, format: 'metadata', metadataHeaders: ['From', 'To', 'Subject', 'Date'] }),
        oauth2, sessionId, acctKey
      );
      const headers = (md.data.payload && md.data.payload.headers) || [];
      const hmap = {};
      for (const h of headers) hmap[h.name] = h.value;
      results.push({
        id: md.data.id,
        threadId: md.data.threadId,
        snippet: md.data.snippet || '',
        from: hmap.From || '',
        to: hmap.To || '',
        subject: hmap.Subject || '',
        date: hmap.Date || '',
        labels: md.data.labelIds || []
      });
    } catch (e) {
      console.warn('Failed to fetch message metadata for', m.id, e && e.message);
    }
  }
  return results;
}

// MCP server
function createMcpServer(getDrive, getSessionId) {
  const server = new Server({ name: 'gdrive-http', version: '0.1.3' }, { capabilities: { resources: {}, tools: {} } });

  server.setRequestHandler(ListResourcesRequestSchema, async (request) => {
    const sessionId = typeof getSessionId === 'function' ? getSessionId() : null;
    const authClient = await ensureSessionHydrate(sessionId);
    
    if (!authClient) {
      const sid = sessionId || randomUUID();
      const payload = buildAuthRequired(sid);
      return {
        resources: [
          {
            uri: 'about:gdrive-auth',
            name: 'Google Drive Authorization',
            mimeType: 'application/json',
            description: 'Open auth_url to authorize this session.',
            text: JSON.stringify(payload)
          }
        ]
      };
    }

    try {
      const drive = google.drive({ version: 'v3', auth: authClient });
      const { data } = await drive.files.list({
        pageSize: 10,
        fields: 'nextPageToken, files(id,name,mimeType,modifiedTime,size,webViewLink)'
      });
      return {
        resources: [
          {
            uri: 'about:gdrive-list',
            name: 'Drive files',
            mimeType: 'application/json',
            text: JSON.stringify({ ok: true, files: data.files || [] })
          }
        ]
      };
    } catch (err) {
      const { code, data: detail } = logGoogleError('ListResources', err);
      return {
        resources: [
          {
            uri: 'about:gdrive-error',
            name: 'Drive error',
            mimeType: 'application/json',
            text: JSON.stringify({
              ok: false,
              code: 'DRIVE_ERROR',
              message: err?.message || 'Google Drive API error',
              detail: { code, detail }
            })
          }
        ]
      };
    }
  });

  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    try {
      const drv = await getDrive(request);
      const drive = drv.drive;
      const oauth2 = drv.oauth2;
      const acctKey = drv.acctKey;
      
      const fileId = request.params.uri.replace('gdrive:///', '');
      const meta = await callWithAutoRefresh(
        () => drive.files.get({ fileId, fields: 'mimeType' }),
        oauth2,
        drv.sessionId,
        acctKey
      );
      const mimeType = meta.data.mimeType || 'application/octet-stream';
      
      if ((meta.data.mimeType || '').startsWith('application/vnd.google-apps')) {
        let exportMimeType = 'text/plain';
        switch (meta.data.mimeType) {
          case 'application/vnd.google-apps.document':
            exportMimeType = 'text/markdown';
            break;
          case 'application/vnd.google-apps.spreadsheet':
            exportMimeType = 'text/csv';
            break;
          case 'application/vnd.google-apps.presentation':
            exportMimeType = 'text/plain';
            break;
          case 'application/vnd.google-apps.drawing':
            exportMimeType = 'image/png';
            break;
        }
        const res = await callWithAutoRefresh(
          () => drive.files.export({ fileId, mimeType: exportMimeType }, { responseType: 'text' }),
          oauth2,
          drv.sessionId,
          acctKey
        );
        return { contents: [{ uri: request.params.uri, mimeType: exportMimeType, text: res.data }] };
      }
      
      const res = await callWithAutoRefresh(
        () => drive.files.get({ fileId, alt: 'media' }, { responseType: 'arraybuffer' }),
        oauth2,
        drv.sessionId,
        acctKey
      );
      
      if (mimeType.startsWith('text/') || mimeType === 'application/json') {
        return {
          contents: [{ uri: request.params.uri, mimeType, text: Buffer.from(res.data).toString('utf8') }]
        };
      }
      return {
        contents: [{ uri: request.params.uri, mimeType, blob: Buffer.from(res.data).toString('base64') }]
      };
    } catch (err) {
      if (err && err.missingSessionId) {
        const e = new Error('This session has not connected a Google Drive yet.');
        e.missingSessionId = err.missingSessionId;
        throw e;
      }
      throw err;
    }
  });

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const sid = typeof getSessionId === 'function' ? getSessionId() : null;
    const connectUrl = `${PUBLIC_BASE_URL.replace(/\/$/, '')}/auth/start?session=${encodeURIComponent(sid || '')}`;

    const tools = [
      {
        name: 'connect_gdrive',
        description: `Connect your Google account (Drive, Gmail, Calendar): ${connectUrl}`,
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'connect_google',
        description: `Connect your Google account (Drive, Gmail, Calendar) - alias for connect_gdrive`,
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'gdrive_connect_hint',
        description: 'Get the authorization URL for this session',
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'list_drive_files',
        description: 'List files from Google Drive with optional pagination (optional "email" to select account)',
        inputSchema: {
          type: 'object',
          properties: {
            max_results: { type: 'number', description: 'Maximum number of files to return (default: 20, max: 100)' },
            email: { type: 'string' }
          }
        }
      },
      {
        name: 'gdrive_whoami',
        description: 'Show which Google account this session is bound to',
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'gdrive_search',
        description: 'Search Google Drive files (optional "email" to select account)',
        inputSchema: {
          type: 'object',
          properties: { query: { type: 'string' }, email: { type: 'string' } },
          required: ['query']
        }
      },
      {
        name: 'gdrive_read_file',
        description: 'Read file by ID (optional "email" to select account)',
        inputSchema: {
          type: 'object',
          properties: { file_id: { type: 'string' }, email: { type: 'string' } },
          required: ['file_id']
        }
      },
      {
        name: 'gdrive_list_meta',
        description: 'Return raw file metadata from Drive',
        inputSchema: {
          type: 'object',
          properties: {
            max_results: { type: 'number', description: 'Max files to return (default: 50, max: 100)' },
            email: { type: 'string' }
          }
        }
      },
      {
        name: 'create_google_doc',
        description: 'Create a NEW Google Docs document with name and content',
        inputSchema: {
          type: 'object',
          properties: {
            file_name: { type: 'string', description: 'Name for the new document' },
            content: { type: 'string', description: 'Initial content' },
            email: { type: 'string' }
          },
          required: ['file_name', 'content']
        }
      },
      {
        name: 'gdrive_update_doc_by_id',
        description: 'Update an EXISTING Google Docs document by file ID (replaces all content)',
        inputSchema: {
          type: 'object',
          properties: { file_id: { type: 'string' }, new_content: { type: 'string' }, email: { type: 'string' } },
          required: ['file_id', 'new_content']
        }
      },
      {
        name: 'gdrive_update_doc_by_name',
        description: 'Update an EXISTING Google Doc by name (replaces all content). Cannot create new docs - use create_google_doc for that.',
        inputSchema: {
          type: 'object',
          properties: { file_name: { type: 'string' }, new_content: { type: 'string' }, email: { type: 'string' } },
          required: ['file_name', 'new_content']
        }
      },
      // Gmail tools
      {
        name: 'list_emails',
        description: 'List emails from Gmail inbox (max_results, optional query)',
        inputSchema: { type: 'object', properties: { max_results: { type: 'number' }, query: { type: 'string' }, email: { type: 'string' } } }
      },
      {
        name: 'read_email',
        description: 'Read a specific email by Gmail message id',
        inputSchema: { type: 'object', properties: { email_id: { type: 'string' },
        email: { type: 'string' } }, required: ['email_id'] }
      },
      {
        name: 'send_email',
        description: 'Send an email via Gmail (to, subject, body, cc, bcc)',
        inputSchema: { type: 'object', properties: { to: { type: 'string' }, subject: { type: 'string' }, body: { type: 'string' }, cc: { type: 'string' }, bcc: { type: 'string' }, email: { type: 'string' } }, required: ['to','subject','body'] }
      },
      {
        name: 'search_emails',
        description: 'Search emails using Gmail query (e.g. "is:unread from:someone@example.com")',
        inputSchema: { type: 'object', properties: { query: { type: 'string' }, max_results: { type: 'number' }, email: { type: 'string' } }, required: ['query'] }
      },
      {
        name: 'mark_email_as_read',
        description: 'Mark an email as read',
        inputSchema: { type: 'object', properties: { email_id: { type: 'string' }, email: { type: 'string' } }, required: ['email_id'] }
      },
      {
        name: 'mark_email_as_unread',
        description: 'Mark an email as unread',
        inputSchema: { type: 'object', properties: { email_id: { type: 'string' }, email: { type: 'string' } }, required: ['email_id'] }
      },
      // Calendar tools
      {
        name: 'list_calendar_events',
        description: 'List events from Google Calendar (max_results, time_min, time_max)',
        inputSchema: { type: 'object', properties: { max_results: { type: 'number' }, time_min: { type: 'string' }, time_max: { type: 'string' }, calendar_id: { type: 'string' }, email: { type: 'string' } } }
      },
      {
        name: 'create_calendar_event',
        description: 'Create a calendar event (summary, start_time, end_time, description, location, attendees)',
        inputSchema: { type: 'object', properties: { summary: { type: 'string' }, start_time: { type: 'string' }, end_time: { type: 'string' }, description: { type: 'string' }, location: { type: 'string' }, attendees: { type: 'string' }, calendar_id: { type: 'string' }, email: { type: 'string' } }, required: ['summary','start_time','end_time'] }
      },
      {
        name: 'update_calendar_event',
        description: 'Update a calendar event by id',
        inputSchema: { type: 'object', properties: { event_id: { type: 'string' }, summary: { type: 'string' }, start_time: { type: 'string' }, end_time: { type: 'string' }, description: { type: 'string' }, location: { type: 'string' }, calendar_id: { type: 'string' }, email: { type: 'string' } }, required: ['event_id'] }
      },
      {
        name: 'delete_calendar_event',
        description: 'Delete a calendar event by id',
        inputSchema: { type: 'object', properties: { event_id: { type: 'string' }, calendar_id: { type: 'string' }, email: { type: 'string' } }, required: ['event_id'] }
      },
      {
        name: 'search_calendar_events',
        description: 'Search calendar events by keyword (searches summary/description/location)',
        inputSchema: { type: 'object', properties: { query: { type: 'string' }, max_results: { type: 'number' }, calendar_id: { type: 'string' }, email: { type: 'string' } }, required: ['query'] }
      },
      // Google Tasks tools (improved descriptions)
      {
        name: 'list_task_lists',
        description: 'List all Google Task lists (shows which lists you have like "My Tasks", "Work", etc.)',
        inputSchema: { type: 'object', properties: { email: { type: 'string' } } }
      },
      {
        name: 'create_task_list',
        description: 'Create a new Google Task list',
        inputSchema: { type: 'object', properties: { title: { type: 'string' }, email: { type: 'string' } }, required: ['title'] }
      },
      {
        name: 'list_tasks',
        description: 'List all tasks in a list with friendly format (shows what you need to do)',
        inputSchema: {
          type: 'object',
          properties: {
            task_list_id: { type: 'string', description: 'Optional - leave empty to use default list' },
            show_completed: { type: 'boolean', description: 'Include completed tasks (default: false)' },
            max_results: { type: 'number', description: 'Max tasks to return (default: 100)' },
            email: { type: 'string' }
          }
        }
      },
      {
        name: 'create_task',
        description: 'Create a new task (automatically handles date formatting)',
        inputSchema: {
          type: 'object',
          properties: {
            title: { type: 'string', description: 'What the task is (e.g., "Review Q4 budget")' },
            notes: { type: 'string', description: 'Additional details about the task' },
            due: { type: 'string', description: 'Due date like "2025-12-15" or "December 15, 2025"' },
            task_list_id: { type: 'string', description: 'Optional - leave empty to use default list' },
            email: { type: 'string' }
          },
          required: ['title']
        }
      },
      {
        name: 'update_task',
        description: 'Update an existing task (requires the exact Google Task ID shown by list_tasks; use update_task_by_title to search by name)',
        inputSchema: {
          type: 'object',
          properties: {
            task_id: { type: 'string', description: 'Task ID to update' },
            title: { type: 'string', description: 'New task title' },
            notes: { type: 'string', description: 'New task description/notes' },
            due: { type: 'string', description: 'New due date in RFC 3339 format or natural language' },
            status: { type: 'string', description: 'Task status: "needsAction" or "completed"' },
            task_list_id: { type: 'string', description: 'Task list ID (optional)' },
            email: { type: 'string' }
          },
          required: ['task_id']
        }
      },
      {
        name: 'delete_task',
        description: 'Delete a task from Google Tasks',
        inputSchema: { type: 'object', properties: { task_id: { type: 'string' }, task_list_id: { type: 'string' }, email: { type: 'string' } }, required: ['task_id'] }
      },
      {
        name: 'complete_task',
        description: 'Mark a task as completed (accepts either task ID or task title)',
        inputSchema: { 
          type: 'object', 
          properties: { 
            task_id: { 
              type: 'string', 
              description: 'Task ID (from list_tasks) or task title to search for' 
            }, 
            task_list_id: { type: 'string' }, 
            email: { type: 'string' } 
          }, 
          required: ['task_id'] 
        }
      },
      {
        name: 'uncomplete_task',
        description: 'Mark a completed task as incomplete (accepts either task ID or task title)',
        inputSchema: { 
          type: 'object', 
          properties: { 
            task_id: { 
              type: 'string', 
              description: 'Task ID (from list_tasks) or task title to search for' 
            }, 
            task_list_id: { type: 'string' }, 
            email: { type: 'string' } 
          }, 
          required: ['task_id'] 
        }
      },
      {
        name: 'search_tasks',
        description: 'Search for tasks by keyword (finds tasks containing specific words)',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Search term' },
            task_list_id: { type: 'string', description: 'Optional - searches all lists if omitted' },
            include_completed: { type: 'boolean', description: 'Include completed tasks' },
            email: { type: 'string' }
          },
          required: ['query']
        }
      },
      {
        name: 'complete_tasks_by_description',
        description: 'Complete tasks by searching for keywords (e.g., "complete all payment tasks")',
        inputSchema: {
          type: 'object',
          properties: {
            description: { type: 'string', description: 'Description or keywords to find tasks (e.g., "payment", "budget")' },
            task_list_id: { type: 'string', description: 'Task list ID (optional, searches all lists if omitted)' },
            email: { type: 'string' }
          },
          required: ['description']
        }
      },
      // Helper: update by title when the exact ID is not known
      {
        name: 'update_task_by_title',
        description: 'Find and update a task by title (convenience helper). Use search_title to locate the task and new_title/new_notes/new_due/new_status to modify it.',
        inputSchema: {
          type: 'object',
          properties: {
            search_title: { type: 'string', description: 'Title or partial title to search for (required)' },
            new_title: { type: 'string', description: 'New title to set' },
            new_notes: { type: 'string', description: 'New notes to set' },
            new_due: { type: 'string', description: 'New due date (YYYY-MM-DD or RFC3339)' },
            new_status: { type: 'string', description: 'New status: "needsAction" or "completed"' },
            task_list_id: { type: 'string', description: 'Optional task list ID' },
            email: { type: 'string' }
          },
          required: ['search_title']
        }
      },
      // NEW: Email/Calendar -> Tasks helpers
      {
        name: 'create_task_from_email',
        description: "Create a Google Task from a Gmail email (like Gmail's 'Add to Tasks' button)",
        inputSchema: {
          type: 'object',
          properties: {
            email_id: { type: 'string', description: 'Gmail message ID to convert to task' },
            task_list_id: { type: 'string', description: 'Optional - leave empty to use default list' },
            email: { type: 'string' }
          },
          required: ['email_id']
        }
      },
      {
        name: 'create_task_from_calendar',
        description: "Create a Google Task from a Calendar event (like Calendar's 'Add to Tasks' button)",
        inputSchema: {
          type: 'object',
          properties: {
            event_id: { type: 'string', description: 'Calendar event ID to convert to task' },
            calendar_id: { type: 'string', description: 'Calendar ID (default: primary)' },
            task_list_id: { type: 'string', description: 'Optional - leave empty to use default list' },
            email: { type: 'string' }
          },
          required: ['event_id']
        }
      },
      {
        name: 'find_and_create_task_from_email',
        description: "Search for emails by query and create tasks from matching emails",
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Gmail search query (e.g., "assignment due", "from:professor@university.edu")' },
            max_results: { type: 'number', description: 'Max emails to search (default: 5)' },
            task_list_id: { type: 'string', description: 'Optional task list ID' },
            email: { type: 'string' }
          },
          required: ['query']
        }
      },
      {
        name: 'find_and_create_task_from_calendar',
        description: 'Search calendar events by keyword and create tasks from matches',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Search keywords (e.g., "budget review", "presentation")' },
            max_results: { type: 'number', description: 'Max events to search (default: 10)' },
            calendar_id: { type: 'string', description: 'Calendar ID (default: primary)' },
            task_list_id: { type: 'string', description: 'Optional task list ID' },
            email: { type: 'string' }
          },
          required: ['query']
        }
      },
      // Auth status
      {
        name: 'get_auth_status',
        description: 'Get authentication status for this session — call this first to verify authentication. Returns ✅ or ❌ plus bound email and scopes.',
        inputSchema: { type: 'object', properties: {} }
      }
    ];
    return { tools };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    try {
      console.log(`[TOOL CALL] Tool: ${request.params.name}, Args:`, JSON.stringify(request.params.arguments || {}));
      
      // Parse email selector (account switcher). Treat empty/blank string as "no selector" so
      // callers that send email: "" (or omit email) will use the authenticated session account.
      const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      let accountSelector = null;
      if (request.params.arguments && typeof request.params.arguments.email === 'string') {
        const raw = request.params.arguments.email.trim();
        if (!raw) {
          // empty string -> no selector supplied (use session-bound account)
          accountSelector = null;
        } else if (emailRx.test(raw)) {
          accountSelector = raw.toLowerCase();
        } else {
          return {
            content: [{ type: 'text', text: 'Invalid email selector provided. Use a full email address like "user@example.com" or omit the field to use the authenticated account.' }],
            isError: true
          };
        }
      }

      // If this session doesn't have per-session tokens, try to auto-bind a stable account
      // so the user doesn't need to re-confirm authorization every time.
      const currentSessionId = typeof getSessionId === 'function' ? getSessionId() : null;
      try {
        const existing = currentSessionId ? loadTokens(currentSessionId, { permissiveFallback: false }) : null;
        if (!existing || !existing.tokens) {
          const stableAccounts = listStableAccounts();
          if (stableAccounts && stableAccounts.length) {
            // pick the first stable account as a sensible default
            const acct = stableAccounts[0];
            const shared = loadTokens(null, { permissiveFallback: true, account: acct });
            if (shared && shared.tokens && currentSessionId) {
              try {
                saveTokensForSession(currentSessionId, shared.tokens, acct);
                console.log(`[AUTH] Auto-bound stable account ${acct} to session ${currentSessionId}`);
              } catch (e) {
                console.warn('Auto-bind stable account failed', e && (e.stack || e));
              }
            }
          }
        }
      } catch (e) {
        console.warn('ensureSessionHasTokens: loadTokens failed', e && (e.stack || e));
      }

      // (no-op handlers here)

      if (
        request.params.name === 'gdrive_connect_hint' ||
        request.params.name === 'connect_gdrive' ||
        request.params.name === 'connect_google'
      ) {
        const sid = typeof getSessionId === 'function' ? getSessionId() : null;
        try {
          const oauth2 = new google.auth.OAuth2(OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_REDIRECT_URI);
          const allowedScopes = [
            'https://www.googleapis.com/auth/drive',
            'https://www.googleapis.com/auth/documents',
            'https://www.googleapis.com/auth/userinfo.email',
            'openid',
            'https://www.googleapis.com/auth/tasks',
            'https://www.googleapis.com/auth/gmail.readonly',
            'https://www.googleapis.com/auth/gmail.send',
            'https://www.googleapis.com/auth/gmail.modify',
            'https://www.googleapis.com/auth/calendar',
            'https://www.googleapis.com/auth/calendar.events'
          ];
          const url = oauth2.generateAuthUrl({
            access_type: 'offline',
            scope: allowedScopes,
            state: sid || '',
            include_granted_scopes: true,
            prompt: 'consent'
          });
          return { content: [{ type: 'text', text: `Authorize Google account for this session:\n${url}` }], isError: false };
        } catch (e) {
          const url = `${PUBLIC_BASE_URL.replace(/\/$/, '')}/auth/start?session=${encodeURIComponent(sid || '')}`;
          return { content: [{ type: 'text', text: `Authorize Google Drive for this session:\n${url}` }], isError: false };
        }
      }

      if (request.params.name === 'get_auth_status') {
        const sid = typeof getSessionId === 'function' ? getSessionId() : null;
        let bound = false;
        let email = null;
        let scopes = [];
        try {
          if (sid) {
            const found = loadTokens(sid, { permissiveFallback: false });
            if (found && found.tokens) {
              const oauth2 = new google.auth.OAuth2(OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_REDIRECT_URI);
              oauth2.setCredentials(found.tokens);
              try {
                if (typeof oauth2.refreshAccessToken === 'function') await oauth2.refreshAccessToken();
                else if (oauth2?.credentials?.refresh_token) await oauth2.getAccessToken();
              } catch (refreshErr) {}
              try {
                const oauth2Client = google.oauth2({ auth: oauth2, version: 'v2' });
                const me = await oauth2Client.userinfo.get();
                email = (me.data && me.data.email) || found.account || null;
                bound = true;
                scopes = found.tokens && found.tokens.scope ? found.tokens.scope.split(' ') : [];
              } catch (e) {
                bound = false;
              }
            }
          }
        } catch (e) {}
        // Provide JSON first (easier for agents to parse) and also a concise
        // human-readable text line. Include the sessionId so callers can bind.
        const payload = { authenticated: bound, email, scopes, stableAccounts: listStableAccounts(), sessionId: sid };
        const statusText = bound
          ? `✅ AUTHENTICATED as ${email || '(unknown email)'} (session: ${sid})`
          : `❌ NOT AUTHENTICATED (session: ${sid}) — call connect_google to authorize.`;
        return {
          content: [
            { type: 'json', json: payload },
            { type: 'text', text: statusText }
          ],
          isError: false
        };
      }

      // GET DRIVE + ALL API CLIENTS ONCE for all remaining tools
      const drv = await getDrive(
        Object.assign({}, request, {
          params: Object.assign({}, request.params, {
            arguments: Object.assign({}, request.params.arguments, { email: accountSelector })
          })
        })
      );
      const drive = drv.drive;
      const oauth2 = drv.oauth2;
      const acctKey = drv.acctKey;
      const sessionId = drv.sessionId;
      
      // Create all API clients once
      const gmail = google.gmail({ version: 'v1', auth: oauth2 });
      const calendar = google.calendar({ version: 'v3', auth: oauth2 });
      const docs = google.docs({ version: 'v1', auth: oauth2 });
  const tasks = google.tasks({ version: 'v1', auth: oauth2 });

      // === DRIVE TOOLS ===
      if (request.params.name === 'list_drive_files') {
        const maxResults = Math.min(Math.max(1, parseInt(request.params.arguments?.max_results) || 20), 100);
        console.log(`[list_drive_files] Using account: ${acctKey}, session: ${sessionId}`);

        try {
          const res = await callWithAutoRefresh(
            () => drive.files.list({
              pageSize: maxResults,
              fields: 'files(id,name,mimeType,modifiedTime,size)',
              orderBy: 'modifiedTime desc'
            }),
            oauth2, sessionId, acctKey
          );

          const files = Array.isArray(res?.data?.files) ? res.data.files : [];
          console.log(`[list_drive_files] Successfully retrieved ${files.length} files`);

          return {
            content: [{ type: 'text', text: JSON.stringify({ success: true, count: files.length, files }, null, 2) }],
            isError: false
          };
        } catch (err) {
          return handleToolError(err, 'list_drive_files', drv);
        }
      }

      if (request.params.name === 'gdrive_search') {
        const qRaw = (request.params.arguments?.query || '').trim();
        try {
          let res;
          if (!qRaw) {
            res = await callWithAutoRefresh(
              () => drive.files.list({
                pageSize: 10,
                fields: 'files(id, name, mimeType, modifiedTime, size, owners(displayName))',
                orderBy: 'modifiedTime desc'
              }),
              oauth2, sessionId, acctKey
            );
          } else {
            const q = qRaw.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
            const formatted = `name contains '${q}' and trashed = false`;
            res = await callWithAutoRefresh(
              () => drive.files.list({
                q: formatted,
                pageSize: 10,
                fields: 'files(id, name, mimeType, modifiedTime, size, owners(displayName))',
                orderBy: 'modifiedTime desc'
              }),
              oauth2, sessionId, acctKey
            );
          }

          const files = Array.isArray(res?.data?.files) ? res.data.files : [];
          if (files.length === 0) {
            return { content: [{ type: 'text', text: `Found 0 files. Try a query like "pdf" or "report".` }], isError: false };
          }
          const list = files
            .map((f) => {
              const owner = f.owners?.[0]?.displayName || '-';
              const mod = f.modifiedTime ? new Date(f.modifiedTime).toISOString() : '-';
              return `${f.name} (${f.mimeType}) | ${mod} | Owner: ${owner} | ID: ${f.id}`;
            })
            .join('\n');
          return { content: [{ type: 'text', text: `Found ${files.length} files:\n${list}` }], isError: false };
        } catch (err) {
          return handleToolError(err, 'gdrive_search', drv);
        }
      }

      if (request.params.name === 'gdrive_read_file') {
        const fileId = request.params.arguments?.file_id;
        if (!fileId) throw new Error('file_id required');

        try {
          const meta = await callWithAutoRefresh(
            () => drive.files.get({ fileId, fields: 'mimeType' }),
            oauth2, sessionId, acctKey
          );
          const mime = meta.data.mimeType || 'application/octet-stream';

          if (mime.startsWith('application/vnd.google-apps')) {
            let exportMimeType = 'text/plain';
            switch (mime) {
              case 'application/vnd.google-apps.document': exportMimeType = 'text/markdown'; break;
              case 'application/vnd.google-apps.spreadsheet': exportMimeType = 'text/csv'; break;
              case 'application/vnd.google-apps.presentation': exportMimeType = 'text/plain'; break;
              case 'application/vnd.google-apps.drawing': exportMimeType = 'image/png'; break;
            }
            const r = await callWithAutoRefresh(
              () => drive.files.export({ fileId, mimeType: exportMimeType }, { responseType: 'text' }),
              oauth2, sessionId, acctKey
            );
            return { content: [{ type: 'text', text: r.data }], isError: false };
          }

          const r = await callWithAutoRefresh(
            () => drive.files.get({ fileId, alt: 'media' }, { responseType: 'arraybuffer' }),
            oauth2, sessionId, acctKey
          );
          if (mime.startsWith('text/') || mime === 'application/json') {
            return { content: [{ type: 'text', text: Buffer.from(r.data).toString('utf8') }], isError: false };
          }
          return { content: [{ type: 'text', text: Buffer.from(r.data).toString('base64') }], isError: false };
        } catch (err) {
          return handleToolError(err, 'gdrive_read_file', drv);
        }
      }

      if (request.params.name === 'gdrive_list_meta') {
        try {
          const maxResultsRaw = request.params.arguments && request.params.arguments.max_results;
          let maxResults = 50;
          if (typeof maxResultsRaw === 'number') {
            maxResults = Math.max(1, Math.min(100, Math.floor(maxResultsRaw)));
          } else if (typeof maxResultsRaw === 'string' && maxResultsRaw.trim().length) {
            const parsed = parseInt(maxResultsRaw, 10);
            if (!Number.isNaN(parsed)) maxResults = Math.max(1, Math.min(100, parsed));
          }
          const res = await callWithAutoRefresh(
            () => drive.files.list({
              pageSize: maxResults,
              fields: 'files(id, name, mimeType, owners(displayName, emailAddress), modifiedTime, size)'
            }),
            oauth2, sessionId, acctKey
          );
          const files = Array.isArray(res?.data?.files) ? res.data.files : [];
          return { content: [{ type: 'json', json: { files } }], isError: false };
        } catch (err) {
          return handleToolError(err, 'gdrive_list_meta', drv);
        }
      }

      if (request.params.name === 'gdrive_update_doc_by_id') {
        const fileId = request.params.arguments?.file_id;
        const newContent = request.params.arguments?.new_content;
        if (!fileId || typeof newContent !== 'string') throw new Error('file_id and new_content required');

        try {
          const meta = await callWithAutoRefresh(
            () => drive.files.get({ fileId, fields: 'id,name,mimeType,capabilities' }),
            oauth2, sessionId, acctKey
          );
          const mime = meta.data.mimeType || '';
          const capabilities = meta.data.capabilities || {};
          const canEdit = Boolean(capabilities.canEdit);

          if (!canEdit) {
            return { content: authRequiredContent(sessionId, 'You do not have edit permissions for this document'), isError: false };
          }

          if (mime !== 'application/vnd.google-apps.document') {
            return { content: [{ type: 'text', text: `File ${meta.data.name} is not a Google Doc (${mime}).` }], isError: true };
          }

          const docResp = await callWithAutoRefresh(() => docs.documents.get({ documentId: fileId }), oauth2, sessionId, acctKey);
          const docData = docResp.data || docResp;
          const contentArr = docData?.body?.content || [];
          const last = contentArr.length ? contentArr[contentArr.length - 1] : null;
          const endIndex = last && typeof last.endIndex === 'number' ? last.endIndex : 1;

          const requestsPayload = [];
          if (endIndex > 1) {
            requestsPayload.push({ deleteContentRange: { range: { startIndex: 1, endIndex: endIndex - 1 } } });
          }
          requestsPayload.push({ insertText: { location: { index: 1 }, text: newContent } });

          const apiResult = await callWithAutoRefresh(
            () => docs.documents.batchUpdate({ documentId: fileId, requestBody: { requests: requestsPayload } }),
            oauth2, sessionId, acctKey
          );

          return {
            content: [{ type: 'json', json: {
              success: true,
              file_id: fileId,
              name: meta.data.name,
              message: 'Document updated successfully',
              content_length: newContent.length,
              api_response: apiResult && apiResult.data ? apiResult.data : apiResult
            }}],
            isError: false
          };
        } catch (err) {
          return handleToolError(err, 'gdrive_update_doc_by_id', drv);
        }
      }

      if (request.params.name === 'create_google_doc') {
        const fileName = (request.params.arguments?.file_name || '').trim();
        const contentText = request.params.arguments?.content || '';
        if (!fileName || typeof contentText !== 'string') throw new Error('file_name and content required');

        try {
          // Create a new Google Doc via Drive API
          const meta = { name: fileName, mimeType: 'application/vnd.google-apps.document' };
          const created = await callWithAutoRefresh(() => drive.files.create({ requestBody: meta, fields: 'id,name,webViewLink' }), oauth2, sessionId, acctKey);
          const fileId = created?.data?.id;

          // Seed the document content using the Docs API
          const requestsPayload = [];
          if (contentText && contentText.length) {
            requestsPayload.push({ insertText: { location: { index: 1 }, text: contentText } });
          }
          let apiResult = null;
          if (requestsPayload.length) {
            apiResult = await callWithAutoRefresh(() => docs.documents.batchUpdate({ documentId: fileId, requestBody: { requests: requestsPayload } }), oauth2, sessionId, acctKey);
          }

          return {
            content: [
              { type: 'text', text: `Created Google Doc "${fileName}" (ID: ${fileId}). View: ${created?.data?.webViewLink || 'no link'}` },
              { type: 'json', json: { success: true, file_id: fileId, name: created?.data?.name, webViewLink: created?.data?.webViewLink, api_response: apiResult && apiResult.data ? apiResult.data : apiResult } }
            ],
            isError: false
          };
        } catch (err) {
          return handleToolError(err, 'create_google_doc', drv);
        }
      }

      if (request.params.name === 'gdrive_update_doc_by_name') {
        const fileName = (request.params.arguments?.file_name || '').trim();
        const newContent = request.params.arguments?.new_content;
        if (!fileName || typeof newContent !== 'string') throw new Error('file_name and new_content required');

        try {
          const safe = fileName.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
          const q = `name contains '${safe}' and mimeType='application/vnd.google-apps.document' and trashed = false`;
          const res = await callWithAutoRefresh(
            () => drive.files.list({ q, pageSize: 10, fields: 'files(id,name,mimeType)' }),
            oauth2, sessionId, acctKey
          );
          const files = Array.isArray(res?.data?.files) ? res.data.files : [];
          if (!files.length) {
            return {
              content: [
                {
                  type: 'text',
                  text:
                    `❌ Cannot update: No Google Doc named "${fileName}" exists in your Drive.\n\n` +
                    `This tool can only UPDATE existing documents. To create a new document, use the create_google_doc tool instead.`
                }
              ],
              isError: true
            };
          }
          const file = files[0];

          const meta = await callWithAutoRefresh(
            () => drive.files.get({ fileId: file.id, fields: 'id,name,mimeType,capabilities' }),
            oauth2, sessionId, acctKey
          );
          const capabilities = meta.data.capabilities || {};
          if (!capabilities.canEdit) {
            return { content: authRequiredContent(sessionId, 'You do not have edit permissions for this document'), isError: false };
          }

          const docResp = await callWithAutoRefresh(() => docs.documents.get({ documentId: file.id }), oauth2, sessionId, acctKey);
          const docData = docResp.data || docResp;
          const contentArr = docData?.body?.content || [];
          const last = contentArr.length ? contentArr[contentArr.length - 1] : null;
          const endIndex = last && typeof last.endIndex === 'number' ? last.endIndex : 1;

          const requestsPayload = [];
          if (endIndex > 1) {
            requestsPayload.push({ deleteContentRange: { range: { startIndex: 1, endIndex: endIndex - 1 } } });
          }
          requestsPayload.push({ insertText: { location: { index: 1 }, text: newContent } });

          const apiResult = await callWithAutoRefresh(
            () => docs.documents.batchUpdate({ documentId: file.id, requestBody: { requests: requestsPayload } }),
            oauth2, sessionId, acctKey
          );

          return {
            content: [{ type: 'json', json: {
              success: true,
              searched_for: fileName,
              file_id: file.id,
              name: file.name,
              message: 'Document updated',
              api_response: apiResult && apiResult.data ? apiResult.data : apiResult
            }}],
            isError: false
          };
        } catch (err) {
          return handleToolError(err, 'gdrive_update_doc_by_name', drv);
        }
      }

      // === GMAIL TOOLS ===
      if (request.params.name === 'list_emails') {
        console.log('[list_emails] Starting, session:', sessionId, 'account:', acctKey);
        try {
          const maxResults = Math.min(Math.max(1, parseInt(request.params.arguments?.max_results) || 20), 100);
          const q = request.params.arguments?.query || undefined;
          const res = await callWithAutoRefresh(
            () => gmail.users.messages.list({ userId: 'me', maxResults, q }),
            oauth2, sessionId, acctKey
          );
          const msgs = Array.isArray(res?.data?.messages) ? res.data.messages : [];
          const email_list = await fetchGmailMessages(gmail, oauth2, sessionId, acctKey, msgs);
          console.log('[list_emails] Successfully retrieved', email_list.length, 'emails');

          // Format readable response for FlyerGPT (text-first)
          if (email_list.length === 0) {
            return { content: [{ type: 'text', text: 'No emails found.' }], isError: false };
          }

          let summary = `Found ${email_list.length} email${email_list.length > 1 ? 's' : ''}:\n\n`;
          email_list.forEach((email, idx) => {
            summary += `Email ${idx + 1}:\n`;
            summary += `From: ${email.from}\n`;
            summary += `Subject: ${email.subject || '(No subject)'}\n`;
            summary += `Date: ${email.date}\n`;
            summary += `Preview: ${email.snippet || ''}\n`;
            summary += `📧 Gmail ID: ${email.id}\n`;
            summary += `(Use this Gmail ID to read the full email)\n\n`;
          });

          return { content: [{ type: 'text', text: summary }], isError: false };
        } catch (err) {
          return handleToolError(err, 'list_emails', drv);
        }
      }

      if (request.params.name === 'read_email') {
        const emailId = request.params.arguments?.email_id;
        if (!emailId) throw new Error('email_id required');
        console.log('[read_email] Reading email', emailId);
        
        try {
          const msg = await callWithAutoRefresh(
            () => gmail.users.messages.get({ userId: 'me', id: emailId, format: 'full' }),
            oauth2, sessionId, acctKey
          );
          const headersArr = (msg.data.payload && msg.data.payload.headers) || [];
          const headers = {};
          for (const h of headersArr) headers[h.name] = h.value;

          const body = extractEmailBody(msg.data.payload) || '';
          console.log('[read_email] Successfully read email', emailId);
          return {
            content: [{ type: 'json', json: {
              success: true,
              id: msg.data.id,
              threadId: msg.data.threadId,
              labels: msg.data.labelIds || [],
              headers,
              snippet: msg.data.snippet || '',
              body
            }}],
            isError: false
          };
        } catch (err) {
          return handleToolError(err, 'read_email', drv);
        }
      }

      if (request.params.name === 'send_email') {
        const to = request.params.arguments?.to;
        const subject = request.params.arguments?.subject || '';
        const body = request.params.arguments?.body || '';
        const cc = request.params.arguments?.cc || '';
        const bcc = request.params.arguments?.bcc || '';
        if (!to || !subject || !body) throw new Error('to, subject and body required');
        
        console.log('[send_email] Sending email to', to);
        try {
          let rawLines = [];
          rawLines.push(`To: ${to}`);
          if (cc) rawLines.push(`Cc: ${cc}`);
          if (bcc) rawLines.push(`Bcc: ${bcc}`);
          rawLines.push(`Subject: ${subject}`);
          rawLines.push('Content-Type: text/plain; charset="UTF-8"');
          rawLines.push('MIME-Version: 1.0');
          rawLines.push('');
          rawLines.push(body);
          const raw = Buffer.from(rawLines.join('\n')).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
          const sent = await callWithAutoRefresh(
            () => gmail.users.messages.send({ userId: 'me', requestBody: { raw } }),
            oauth2, sessionId, acctKey
          );
          console.log('[send_email] Successfully sent email', sent.data.id);
          return { content: [{ type: 'json', json: { success: true, message_id: sent.data.id, thread_id: sent.data.threadId } }], isError: false };
        } catch (err) {
          return handleToolError(err, 'send_email', drv);
        }
      }

      if (request.params.name === 'search_emails') {
        const q = (request.params.arguments && request.params.arguments.query) || '';
        const maxResults = Math.min(Math.max(1, parseInt(request.params.arguments?.max_results) || 20), 100);
        if (!q) return { content: [{ type: 'text', text: 'Query required' }], isError: true };
        
        console.log('[search_emails] Searching emails with query:', q);
        try {
          const res = await callWithAutoRefresh(
            () => gmail.users.messages.list({ userId: 'me', q, maxResults }),
            oauth2, sessionId, acctKey
          );
          const msgs = Array.isArray(res?.data?.messages) ? res.data.messages : [];
          const results = await fetchGmailMessages(gmail, oauth2, sessionId, acctKey, msgs);
          console.log('[search_emails] Found', results.length, 'emails');
          return { content: [{ type: 'json', json: { success: true, count: results.length, results } }], isError: false };
        } catch (err) {
          return handleToolError(err, 'search_emails', drv);
        }
      }

      if (request.params.name === 'mark_email_as_read' || request.params.name === 'mark_email_as_unread') {
        const emailId = request.params.arguments?.email_id;
        if (!emailId) throw new Error('email_id required');
        
        console.log(`[${request.params.name}]`, emailId);
        try {
          if (request.params.name === 'mark_email_as_read') {
            await callWithAutoRefresh(
              () => gmail.users.messages.modify({ userId: 'me', id: emailId, requestBody: { removeLabelIds: ['UNREAD'] } }),
              oauth2, sessionId, acctKey
            );
            return { content: [{ type: 'text', text: 'Email marked as read' }], isError: false };
          } else {
            await callWithAutoRefresh(
              () => gmail.users.messages.modify({ userId: 'me', id: emailId, requestBody: { addLabelIds: ['UNREAD'] } }),
              oauth2, sessionId, acctKey
            );
            return { content: [{ type: 'text', text: 'Email marked as unread' }], isError: false };
          }
        } catch (err) {
          return handleToolError(err, request.params.name, drv);
        }
      }

      // === CALENDAR TOOLS ===
      if (request.params.name === 'list_calendar_events') {
        console.log('[list_calendar_events] Starting');
        try {
          const maxResults = Math.min(Math.max(1, parseInt(request.params.arguments?.max_results) || 10), 250);
          const calendarId = request.params.arguments?.calendar_id || 'primary';

          // Default to today's full day window (local) when no explicit time_min/time_max provided
          let timeMin = request.params.arguments?.time_min;
          let timeMax = request.params.arguments?.time_max;
          if (!timeMin || !timeMax) {
            const today = new Date();
            // start of local day
            const start = new Date(today);
            start.setHours(0, 0, 0, 0);
            const end = new Date(start.getTime() + 24 * 60 * 60 * 1000);
            if (!timeMin) timeMin = start.toISOString();
            if (!timeMax) timeMax = end.toISOString();
          }

          const params = { calendarId, maxResults, singleEvents: true, orderBy: 'startTime', timeMin };
          if (timeMax) params.timeMax = timeMax;

          const res = await callWithAutoRefresh(() => calendar.events.list(params), oauth2, sessionId, acctKey);
          const events = Array.isArray(res?.data?.items) ? res.data.items : [];
          console.log('[list_calendar_events] Retrieved', events.length, 'events');
          console.log('[list_calendar_events] Events data:', JSON.stringify(events, null, 2));

          // FIX: Always return text format that FlyerGPT can parse
          if (events.length === 0) {
            return { content: [{ type: 'text', text: 'No events found in the specified time range.' }], isError: false };
          }

          // Format events in a clear, readable way with ALL details
          let summary = `Found ${events.length} event${events.length > 1 ? 's' : ''}:\n\n`;
          events.forEach((event, idx) => {
            const start = event.start?.dateTime || event.start?.date || 'Unknown time';
            const end = event.end?.dateTime || event.end?.date || '';

            summary += `Event ${idx + 1}:\n`;
            summary += `Title: ${event.summary || '(No title)'}\n`;
            summary += `When: ${start}${end ? ' to ' + end : ''}\n`;
            if (event.location) summary += `Location: ${event.location}\n`;
            if (event.description) summary += `Description: ${String(event.description).substring(0, 200)}${String(event.description).length > 200 ? '...' : ''}\n`;
            if (event.attendees && event.attendees.length > 0) {
              summary += `Attendees: ${event.attendees.map(a => a.email).join(', ')}\n`;
            }
            summary += `Event ID: ${event.id}\n`;
            if (event.htmlLink) summary += `Link: ${event.htmlLink}\n`;
            summary += '\n';
          });

          // Return ONLY text format - no JSON that might confuse FlyerGPT
          return { content: [{ type: 'text', text: summary }], isError: false };
        } catch (err) {
          return handleToolError(err, 'list_calendar_events', drv);
        }
      }

      if (request.params.name === 'create_calendar_event') {
        console.log('[create_calendar_event] Creating event');
        try {
          const summary = request.params.arguments?.summary || '';
          const start_time = request.params.arguments?.start_time || '';
          const end_time = request.params.arguments?.end_time || '';
          const description = request.params.arguments?.description || '';
          const location = request.params.arguments?.location || '';
          const attendeesRaw = request.params.arguments?.attendees || '';
          const calendarId = request.params.arguments?.calendar_id || 'primary';
          if (!summary || !start_time || !end_time) throw new Error('summary, start_time and end_time are required');
          const attendees = attendeesRaw.split(',').map(s => s.trim()).filter(Boolean).map(email => ({ email }));
          const isAllDay = !/T/.test(start_time) && !/T/.test(end_time);
          const event = {
            summary,
            location,
            description,
            attendees: attendees.length ? attendees : undefined,
            start: isAllDay ? { date: start_time } : { dateTime: start_time },
            end: isAllDay ? { date: end_time } : { dateTime: end_time }
          };
          const res = await callWithAutoRefresh(() => calendar.events.insert({ calendarId, requestBody: event }), oauth2, sessionId, acctKey);
          console.log('[create_calendar_event] Created event', res.data.id);

          // Format response with clear link
          const eventLink = res.data.htmlLink || 'No link available';
          const responseText = `Successfully created calendar event: "${summary}"\n\n` +
            `📅 When: ${start_time} to ${end_time}\n` +
            `📍 Location: ${location || 'Not specified'}\n` +
            `🔗 View event: ${eventLink}\n` +
            `Event ID: ${res.data.id}`;

          return {
            content: [
              { type: 'text', text: responseText },
              { type: 'json', json: { success: true, event: res.data, htmlLink: eventLink } }
            ],
            isError: false
          };
        } catch (err) {
          return handleToolError(err, 'create_calendar_event', drv);
        }
      }

      if (request.params.name === 'update_calendar_event') {
        const eventId = request.params.arguments?.event_id;
        if (!eventId) throw new Error('event_id required');
        console.log('[update_calendar_event] Updating event', eventId);
        
        try {
          const calendarId = request.params.arguments?.calendar_id || 'primary';
          const patch = {};
          if (request.params.arguments?.summary) patch.summary = request.params.arguments.summary;
          if (request.params.arguments?.description) patch.description = request.params.arguments.description;
          if (request.params.arguments?.location) patch.location = request.params.arguments.location;
          if (request.params.arguments?.start_time) {
            const st = request.params.arguments.start_time;
            patch.start = /T/.test(st) ? { dateTime: st } : { date: st };
          }
          if (request.params.arguments?.end_time) {
            const et = request.params.arguments.end_time;
            patch.end = /T/.test(et) ? { dateTime: et } : { date: et };
          }
          const res = await callWithAutoRefresh(() => calendar.events.patch({ calendarId, eventId, requestBody: patch }), oauth2, sessionId, acctKey);
          console.log('[update_calendar_event] Updated event', eventId);
          return { content: [{ type: 'json', json: { success: true, event: res.data } }], isError: false };
        } catch (err) {
          return handleToolError(err, 'update_calendar_event', drv);
        }
      }

      if (request.params.name === 'delete_calendar_event') {
        const eventId = request.params.arguments?.event_id;
        if (!eventId) throw new Error('event_id required');
        console.log('[delete_calendar_event] Deleting event', eventId);
        
        try {
          const calendarId = request.params.arguments?.calendar_id || 'primary';
          await callWithAutoRefresh(() => calendar.events.delete({ calendarId, eventId }), oauth2, sessionId, acctKey);
          console.log('[delete_calendar_event] Deleted event', eventId);
          return { content: [{ type: 'text', text: 'Event deleted' }], isError: false };
        } catch (err) {
          return handleToolError(err, 'delete_calendar_event', drv);
        }
      }

      if (request.params.name === 'search_calendar_events') {
        const q = (request.params.arguments && request.params.arguments.query) || '';
        console.log('[search_calendar_events] Searching with query:', q);
        
        try {
          const maxResults = Math.min(Math.max(1, parseInt(request.params.arguments?.max_results) || 50), 250);
          const calendarId = request.params.arguments?.calendar_id || 'primary';
          const res = await callWithAutoRefresh(
            () => calendar.events.list({ calendarId, maxResults, singleEvents: true, orderBy: 'startTime' }),
            oauth2, sessionId, acctKey
          );
          const items = Array.isArray(res?.data?.items) ? res.data.items : [];
          const norm = q.toLowerCase();
          const matched = items.filter(ev => {
            const s = (ev.summary || '').toLowerCase();
            const d = (ev.description || '').toLowerCase();
            const l = (ev.location || '').toLowerCase();
            const at = (ev.attendees || []).map(a => (a.email || '').toLowerCase()).join(' ');
            return s.includes(norm) || d.includes(norm) || l.includes(norm) || at.includes(norm);
          });
          console.log('[search_calendar_events] Found', matched.length, 'matching events');
          return { content: [{ type: 'json', json: { success: true, count: matched.length, events: matched } }], isError: false };
        } catch (err) {
          return handleToolError(err, 'search_calendar_events', drv);
        }
      }

      // === TASKS TOOLS === (improved handlers)
      if (request.params.name === 'list_task_lists') {
        console.log('[list_task_lists] Starting, account:', acctKey);
        try {
          const res = await callWithAutoRefresh(() => tasks.tasklists.list({ maxResults: 100 }), oauth2, sessionId, acctKey);
          const lists = Array.isArray(res?.data?.items) ? res.data.items : [];
          console.log('[list_task_lists] Retrieved', lists.length, 'task lists');

          if (!lists.length) {
            return { content: [{ type: 'text', text: 'No task lists found.' }], isError: false };
          }

          // User-friendly format
          let summary = `📋 Your Google Task Lists (${acctKey}):\n\n`;
          lists.forEach((list, idx) => {
            summary += `${idx + 1}. ${list.title}\n`;
            if (list.updated) {
            return { content: [{ type: 'text', text: 'No tasks found.' }], isError: false };
              summary += `   Last updated: ${updated.toLocaleDateString()}\n`;
            }
            summary += '\n';
          });

          return { content: [{ type: 'text', text: summary }], isError: false };
        } catch (err) {
          return handleToolError(err, 'list_task_lists', drv);
        }
      }

      if (request.params.name === 'create_task_list') {
        const title = (request.params.arguments?.title || '').trim();
        if (!title) throw new Error('title required');

        console.log('[create_task_list] Creating task list:', title);
        try {
          const created = await callWithAutoRefresh(() => tasks.tasklists.insert({ requestBody: { title } }), oauth2, sessionId, acctKey);
          console.log('[create_task_list] Created task list', created.data.id);

          return { content: [{ type: 'text', text: `✅ Created task list: "${title}"` }], isError: false };
        } catch (err) {
          return handleToolError(err, 'create_task_list', drv);
        }
      }

      if (request.params.name === 'list_tasks') {
        console.log('[list_tasks] Starting for account:', acctKey);
        try {
          const taskListIdRaw = request.params.arguments?.task_list_id || '@default';
          const taskListId = taskListIdRaw === '@default' ? '@default' : taskListIdRaw;
          const showCompleted = !!request.params.arguments?.show_completed;
          const maxResults = Math.min(Math.max(1, parseInt(request.params.arguments?.max_results) || 100), 1000);

          const res = await callWithAutoRefresh(
            () => tasks.tasks.list({ tasklist: taskListId, showCompleted, maxResults }),
            oauth2, sessionId, acctKey
          );
          const items = Array.isArray(res?.data?.items) ? res.data.items : [];
          console.log('[list_tasks] Retrieved', items.length, 'tasks');

          if (!items.length) {
            return { content: [{ type: 'text', text: 'No tasks found in this list.' }], isError: false };
          }

          // User-friendly format with natural descriptions and prominent Task IDs
          let summary = `📝 Your Tasks (${items.length} total) for ${acctKey}:\n\n`;
          items.forEach((task, idx) => {
            const checkbox = task.status === 'completed' ? '✅' : '⬜';
            summary += `Task ${idx + 1}: ${checkbox} ${task.title}\n`;
            summary += `   🆔 Task ID: ${task.id}\n`;

            if (task.notes) {
              const notes = String(task.notes).length > 100 ? String(task.notes).substring(0, 100) + '...' : task.notes;
              summary += `   📄 ${notes}\n`;
            }

              if (task.due) {
                // Parse and display dates in UTC to avoid local timezone shifts
                const dueDate = new Date(task.due);
                // Compute UTC-only day difference
                const today = new Date();
                const utcToday = Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate());
                const utcDue = Date.UTC(dueDate.getUTCFullYear(), dueDate.getUTCMonth(), dueDate.getUTCDate());
                const diffDays = Math.round((utcDue - utcToday) / (1000 * 60 * 60 * 24));

                let dueText = '';
                try {
                  dueText = dueDate.toLocaleDateString(undefined, { timeZone: 'UTC' });
                } catch (e) {
                  dueText = String(task.due);
                }

                if (diffDays < 0) {
                  dueText += ` (${Math.abs(diffDays)} days overdue)`;
                } else if (diffDays === 0) {
                  dueText += ' (Due today!)';
                } else if (diffDays === 1) {
                  dueText += ' (Due tomorrow)';
                } else if (diffDays <= 7) {
                  dueText += ` (Due in ${diffDays} days)`;
                }
                summary += `   📅 Due: ${dueText}\n`;
              }

            if (task.completed) {
              const completedDate = new Date(task.completed);
              summary += `   ✓ Completed: ${completedDate.toLocaleDateString()}\n`;
            }

            summary += '\n';
          });

          return { content: [{ type: 'text', text: summary }], isError: false };
        } catch (err) {
          return handleToolError(err, 'list_tasks', drv);
        }
      }

      if (request.params.name === 'create_task') {
        const title = (request.params.arguments?.title || '').trim();
        if (!title) throw new Error('title required');

        console.log('[create_task] Creating task:', title);
        try {
          const taskListIdRaw = request.params.arguments?.task_list_id || '@default';
          const taskListId = taskListIdRaw === '@default' ? '@default' : taskListIdRaw;
          const body = { title };

          if (request.params.arguments?.notes) {
            body.notes = request.params.arguments.notes;
          }
          if (request.params.arguments?.due) {
            // Ensure proper RFC 3339 format
            let dueInput = request.params.arguments.due;
            let dueDate;
            // Try ISO date YYYY-MM-DD
            if (/^\d{4}-\d{2}-\d{2}$/.test(dueInput)) {
              dueDate = new Date(dueInput + 'T00:00:00Z');
            } else if (/T.*Z$/.test(dueInput)) {
              dueDate = new Date(dueInput);
            } else {
              // Fallback to Date parse (best-effort for natural language)
              dueDate = new Date(dueInput);
            }
            if (!isNaN(dueDate.getTime())) body.due = dueDate.toISOString();
          }

          const created = await callWithAutoRefresh(() => tasks.tasks.insert({ tasklist: taskListId, requestBody: body }), oauth2, sessionId, acctKey);
          // Verify creation by fetching the inserted task
          let confirmed = created?.data;
          try {
            if (created && created.data && created.data.id) {
              const check = await callWithAutoRefresh(() => tasks.tasks.get({ tasklist: taskListId, task: created.data.id }), oauth2, sessionId, acctKey);
              if (check && check.data) confirmed = check.data;
            }
          } catch (e) {
            // ignore verification failure; we'll still try to list to confirm below
          }

          // If confirmed is not present, try to search for a recent task with same title
          if (!confirmed || !confirmed.id) {
            try {
              const listing = await callWithAutoRefresh(() => tasks.tasks.list({ tasklist: taskListId, maxResults: 50, showCompleted: true }), oauth2, sessionId, acctKey);
              const found = Array.isArray(listing?.data?.items) ? listing.data.items.find(t => (t.title || '') === title) : null;
              if (found) confirmed = found;
            } catch (e) {}
          }

          if (!confirmed || !confirmed.id) {
            // Creation did not actually persist or cannot be confirmed
            return { content: [{ type: 'text', text: `❌ Failed to create task: "${title}"` }], isError: true };
          }

          let responseText = `✅ Task created: "${confirmed.title || title}"\n`;
          if (confirmed.notes) responseText += `📄 ${confirmed.notes}\n`;
          if (confirmed.due) responseText += `📅 Due: ${new Date(confirmed.due).toLocaleDateString()}\n`;

          return { content: [{ type: 'text', text: responseText }], isError: false };
        } catch (err) {
          return handleToolError(err, 'create_task', drv);
        }
      }

      // === NEW: CREATE TASK FROM EMAIL ===
      if (request.params.name === 'create_task_from_email') {
        const emailId = request.params.arguments?.email_id;
        if (!emailId) throw new Error('email_id required');

        console.log('[create_task_from_email] Converting email', emailId, 'to task');
        try {
          const taskListIdRaw = request.params.arguments?.task_list_id || '@default';
          const taskListId = taskListIdRaw === '@default' ? '@default' : taskListIdRaw;

          // Fetch the email details
          const msg = await callWithAutoRefresh(
            () => gmail.users.messages.get({ userId: 'me', id: emailId, format: 'full' }),
            oauth2, sessionId, acctKey
          );

          const headersArr = (msg.data.payload && msg.data.payload.headers) || [];
          const headers = {};
          for (const h of headersArr) headers[h.name] = h.value;

          const subject = headers.Subject || '(No subject)';
          const from = headers.From || '';
          const date = headers.Date || '';
          const body = extractEmailBody(msg.data.payload) || '';
          
          // Create task with email context
          const taskTitle = `📧 ${subject}`;
          const taskNotes = `From: ${from}\nDate: ${date}\n\nEmail preview:\n${body.substring(0, 500)}${body.length > 500 ? '...' : ''}\n\nGmail link: https://mail.google.com/mail/u/0/#inbox/${emailId}`;

          const taskBody = { title: taskTitle, notes: taskNotes };

          const created = await callWithAutoRefresh(
            () => tasks.tasks.insert({ tasklist: taskListId, requestBody: taskBody }),
            oauth2, sessionId, acctKey
          );

          // Verify creation
          let confirmed = created?.data;
          if (created?.data?.id) {
            try {
              const check = await callWithAutoRefresh(
                () => tasks.tasks.get({ tasklist: taskListId, task: created.data.id }),
                oauth2, sessionId, acctKey
              );
              if (check?.data) confirmed = check.data;
            } catch (e) {
              console.warn('[create_task_from_email] Verification failed:', e && e.message);
            }
          }

          if (!confirmed || !confirmed.id) {
            return { content: [{ type: 'text', text: `❌ Failed to create task from email: "${subject}"` }], isError: true };
          }

          const responseText = `✅ Created task from email:\n\n` +
            `📧 ${confirmed.title}\n` +
            `📋 Task details saved with email preview and link\n` +
            `🔗 View in Gmail: https://mail.google.com/mail/u/0/#inbox/${emailId}`;

          return { content: [{ type: 'text', text: responseText }], isError: false };
        } catch (err) {
          return handleToolError(err, 'create_task_from_email', drv);
        }
      }

      // === NEW: CREATE TASK FROM CALENDAR EVENT ===
      if (request.params.name === 'create_task_from_calendar') {
        const eventId = request.params.arguments?.event_id;
        if (!eventId) throw new Error('event_id required');

        console.log('[create_task_from_calendar] Converting event', eventId, 'to task');
        try {
          const calendarId = request.params.arguments?.calendar_id || 'primary';
          const taskListIdRaw = request.params.arguments?.task_list_id || '@default';
          const taskListId = taskListIdRaw === '@default' ? '@default' : taskListIdRaw;

          // Fetch the calendar event
          const event = await callWithAutoRefresh(
            () => calendar.events.get({ calendarId, eventId }),
            oauth2, sessionId, acctKey
          );

          const eventData = event.data;
          const summary = eventData.summary || '(No title)';
          const start = eventData.start?.dateTime || eventData.start?.date || '';
          const end = eventData.end?.dateTime || eventData.end?.date || '';
          const location = eventData.location || '';
          const description = eventData.description || '';

          // Create task with event context
          const taskTitle = `📅 ${summary}`;
          let taskNotes = `Event: ${summary}\nWhen: ${start}${end ? ' to ' + end : ''}\n`;
          if (location) taskNotes += `Location: ${location}\n`;
          if (description) taskNotes += `\nDescription:\n${description}\n`;
          taskNotes += `\nCalendar link: ${eventData.htmlLink || 'https://calendar.google.com'}`;

          const taskBody = { 
            title: taskTitle, 
            notes: taskNotes 
          };
          
          if (start) {
            try {
              const dueDate = new Date(start);
              if (!isNaN(dueDate.getTime())) {
                taskBody.due = dueDate.toISOString();
              }
            } catch (e) {
              console.warn('[create_task_from_calendar] Could not parse due date:', e && e.message);
            }
          }

          const created = await callWithAutoRefresh(
            () => tasks.tasks.insert({ tasklist: taskListId, requestBody: taskBody }),
            oauth2, sessionId, acctKey
          );

          // Verify creation
          let confirmed = created?.data;
          if (created?.data?.id) {
            try {
              const check = await callWithAutoRefresh(
                () => tasks.tasks.get({ tasklist: taskListId, task: created.data.id }),
                oauth2, sessionId, acctKey
              );
              if (check?.data) confirmed = check.data;
            } catch (e) {
              console.warn('[create_task_from_calendar] Verification failed:', e && e.message);
            }
          }

          if (!confirmed || !confirmed.id) {
            return { content: [{ type: 'text', text: `❌ Failed to create task from event: "${summary}"` }], isError: true };
          }

          const responseText = `✅ Created task from calendar event:\n\n` +
            `📅 ${confirmed.title}\n` +
            (confirmed.due ? `📆 Due: ${new Date(confirmed.due).toLocaleDateString()}\n` : '') +
            `📋 Task includes event details and calendar link\n` +
            `🔗 View event: ${eventData.htmlLink || 'Calendar'}`;

          return { content: [{ type: 'text', text: responseText }], isError: false };
        } catch (err) {
          return handleToolError(err, 'create_task_from_calendar', drv);
        }
      }

      // === NEW: FIND EMAIL AND CREATE TASKS ===
      if (request.params.name === 'find_and_create_task_from_email') {
        const query = (request.params.arguments?.query || '').trim();
        if (!query) throw new Error('query required');

        console.log('[find_and_create_task_from_email] Searching emails:', query);
        try {
          const maxResults = Math.min(Math.max(1, parseInt(request.params.arguments?.max_results) || 5), 20);
          const taskListIdRaw = request.params.arguments?.task_list_id || '@default';
          const taskListId = taskListIdRaw === '@default' ? '@default' : taskListIdRaw;

          // Search for emails
          const searchRes = await callWithAutoRefresh(
            () => gmail.users.messages.list({ userId: 'me', q: query, maxResults }),
            oauth2, sessionId, acctKey
          );

          const msgs = Array.isArray(searchRes?.data?.messages) ? searchRes.data.messages : [];
          
          if (msgs.length === 0) {
            return { content: [{ type: 'text', text: `No emails found matching: "${query}"` }], isError: false };
          }

          // Fetch email metadata
          const emailList = await fetchGmailMessages(gmail, oauth2, sessionId, acctKey, msgs);

          if (emailList.length === 0) {
            return { content: [{ type: 'text', text: `Found ${msgs.length} email(s) but couldn't fetch details` }], isError: false };
          }

          // Present options to user
          let summary = `📧 Found ${emailList.length} email(s) matching "${query}":\n\n`;
          emailList.forEach((email, idx) => {
            summary += `${idx + 1}. ${email.subject || '(No subject)'}\n`;
            summary += `   From: ${email.from}\n`;
            summary += `   Date: ${email.date}\n`;
            summary += `   ID: ${email.id}\n\n`;
          });

          summary += `\nTo create a task from any email, use:\ncreate_task_from_email with the email ID`;

          return { content: [{ type: 'text', text: summary }], isError: false };
        } catch (err) {
          return handleToolError(err, 'find_and_create_task_from_email', drv);
        }
      }

      // === NEW: FIND CALENDAR EVENT AND CREATE TASKS ===
      if (request.params.name === 'find_and_create_task_from_calendar') {
        const query = (request.params.arguments?.query || '').trim().toLowerCase();
        if (!query) throw new Error('query required');

        console.log('[find_and_create_task_from_calendar] Searching events:', query);
        try {
          const maxResults = Math.min(Math.max(1, parseInt(request.params.arguments?.max_results) || 10), 50);
          const calendarId = request.params.arguments?.calendar_id || 'primary';

          // List upcoming events
          const res = await callWithAutoRefresh(
            () => calendar.events.list({
              calendarId,
              maxResults: maxResults * 2,
              singleEvents: true,
              orderBy: 'startTime',
              timeMin: new Date().toISOString()
            }),
            oauth2, sessionId, acctKey
          );

          const items = Array.isArray(res?.data?.items) ? res.data.items : [];

          // Filter by query
          const matched = items.filter(ev => {
            const s = (ev.summary || '').toLowerCase();
            const d = (ev.description || '').toLowerCase();
            const l = (ev.location || '').toLowerCase();
            return s.includes(query) || d.includes(query) || l.includes(query);
          }).slice(0, maxResults);

          if (matched.length === 0) {
            return { content: [{ type: 'text', text: `No calendar events found matching: "${query}"` }], isError: false };
          }

          // Present options
          let summary = `📅 Found ${matched.length} event(s) matching "${query}":\n\n`;
          matched.forEach((event, idx) => {
            const start = event.start?.dateTime || event.start?.date || '';
            summary += `${idx + 1}. ${event.summary || '(No title)'}\n`;
            summary += `   When: ${start}\n`;
            if (event.location) summary += `   Location: ${event.location}\n`;
            summary += `   Event ID: ${event.id}\n\n`;
          });

          summary += `\nTo create a task from any event, use:\ncreate_task_from_calendar with the event ID`;

          return { content: [{ type: 'text', text: summary }], isError: false };
        } catch (err) {
          return handleToolError(err, 'find_and_create_task_from_calendar', drv);
        }
      }

      // === FIXED: UPDATE TASK - Better error handling and validation ===
      if (request.params.name === 'update_task') {
        const taskId = request.params.arguments?.task_id;
        if (!taskId) throw new Error('task_id required');

        console.log('[update_task] Updating task', taskId);
        try {
          const taskListIdRaw = request.params.arguments?.task_list_id || '@default';
          const taskListId = taskListIdRaw === '@default' ? '@default' : taskListIdRaw;

          // VALIDATION: Check if task exists first
          let existingTask = null;
          try {
            const checkTask = await callWithAutoRefresh(
              () => tasks.tasks.get({ tasklist: taskListId, task: taskId }),
              oauth2, sessionId, acctKey
            );
            existingTask = checkTask?.data;
          } catch (e) {
            // Task doesn't exist - try to find it by title/description
            console.log('[update_task] Task not found, searching by title...');
            const searchRes = await callWithAutoRefresh(
              () => tasks.tasks.list({ tasklist: taskListId, showCompleted: true, maxResults: 100 }),
              oauth2, sessionId, acctKey
            );
            
            const allTasks = Array.isArray(searchRes?.data?.items) ? searchRes.data.items : [];
            const found = allTasks.find(t => 
              t.id === taskId || 
              (t.title || '').toLowerCase().includes(String(taskId).toLowerCase())
            );

            if (found) {
              existingTask = found;
              console.log('[update_task] Found task by search:', found.id);
            } else {
              return {
                content: [{
                  type: 'text',
                  text: `❌ Task not found with ID "${taskId}".\n\n` +
                    `Available tasks:\n${allTasks.map((t, i) => `${i + 1}. ${t.title} (ID: ${t.id})`).join('\n')}`
                }],
                isError: true
              };
            }
          }

          if (!existingTask) {
            return {
              content: [{ type: 'text', text: `❌ Task "${taskId}" not found` }],
              isError: true
            };
          }

          // Build patch with only changed fields (ignore empty strings)
          const patch = {};
          if (typeof request.params.arguments?.title === 'string' && request.params.arguments.title.trim().length) {
            patch.title = request.params.arguments.title.trim();
          }
          if (typeof request.params.arguments?.notes === 'string' && request.params.arguments.notes.trim().length) {
            patch.notes = request.params.arguments.notes.trim();
          }
          if (typeof request.params.arguments?.status === 'string' && request.params.arguments.status.trim().length) {
            const st = String(request.params.arguments.status).trim();
            const stNorm = st === 'completed' || st.toLowerCase() === 'completed' ? 'completed' : st === 'needsAction' || st.toLowerCase() === 'needsaction' || st.toLowerCase() === 'needs action' ? 'needsAction' : null;
            if (stNorm) patch.status = stNorm;
          }

          if (typeof request.params.arguments?.due === 'string' && request.params.arguments.due.trim().length) {
            let dueInput = request.params.arguments.due.trim();
            let dueDate;
            
            // Handle various date formats
            if (/^\d{4}-\d{2}-\d{2}$/.test(dueInput)) {
              dueDate = new Date(dueInput + 'T00:00:00Z');
            } else if (/T.*Z$/.test(dueInput)) {
              dueDate = new Date(dueInput);
            } else {
              dueDate = new Date(dueInput);
            }
            
            if (!isNaN(dueDate.getTime())) {
              patch.due = dueDate.toISOString();
            } else {
              return {
                content: [{ type: 'text', text: `❌ Invalid due date format: "${dueInput}". Use YYYY-MM-DD format.` }],
                isError: true
              };
            }
          }

          if (Object.keys(patch).length === 0) {
            return {
              content: [{ type: 'text', text: `❌ No changes specified for task "${existingTask.title}"` }],
              isError: false
            };
          }

          // Ensure the PATCH/PUT body contains the task id (Tasks API requires it for full updates)
          if (!patch.id) patch.id = existingTask.id;

          // Perform update
          const updated = await callWithAutoRefresh(
            () => tasks.tasks.update({ tasklist: taskListId, task: existingTask.id, requestBody: patch }),
            oauth2, sessionId, acctKey
          );

          // Verify update
          const verified = await callWithAutoRefresh(
            () => tasks.tasks.get({ tasklist: taskListId, task: existingTask.id }),
            oauth2, sessionId, acctKey
          );

          const final = verified?.data || updated?.data;
          
          let responseText = `✅ Task updated: "${final.title}"\n\n`;
          responseText += `Changes made:\n`;
          if (patch.title) responseText += `• Title: ${patch.title}\n`;
          if (patch.notes) responseText += `• Notes updated\n`;
          if (patch.due) responseText += `• Due date: ${new Date(patch.due).toLocaleDateString()}\n`;
          if (patch.status) responseText += `• Status: ${patch.status}\n`;

          return { content: [{ type: 'text', text: responseText }], isError: false };
        } catch (err) {
          return handleToolError(err, 'update_task', drv);
        }
      }

      // === NEW: UPDATE TASK BY TITLE - User-friendly alternative ===
      if (request.params.name === 'update_task_by_title') {
        const searchTitle = (request.params.arguments?.search_title || '').trim();
        if (!searchTitle) throw new Error('search_title required');

        console.log('[update_task_by_title] Searching for task:', searchTitle);
        console.log('[update_task_by_title] All arguments:', JSON.stringify(request.params.arguments));
        
        try {
          const taskListIdRaw = request.params.arguments?.task_list_id || '@default';
          const taskListId = taskListIdRaw === '@default' ? '@default' : taskListIdRaw;

          // Search for the task by title
          const searchRes = await callWithAutoRefresh(
            () => tasks.tasks.list({ tasklist: taskListId, showCompleted: false, maxResults: 100 }),
            oauth2, sessionId, acctKey
          );
          
          const allTasks = Array.isArray(searchRes?.data?.items) ? searchRes.data.items : [];
          console.log('[update_task_by_title] Found', allTasks.length, 'tasks to search');
          
          // Find exact or partial match
          const searchLower = searchTitle.toLowerCase();
          const exactMatch = allTasks.find(t => (t.title || '').toLowerCase() === searchLower);
          const partialMatch = allTasks.find(t => (t.title || '').toLowerCase().includes(searchLower));
          const foundTask = exactMatch || partialMatch;

          if (!foundTask) {
            console.log('[update_task_by_title] No task found matching:', searchTitle);
            return {
              content: [{
                type: 'text',
                text: `❌ No task found matching "${searchTitle}".\n\n` +
                  `Available tasks:\n${allTasks.map((t, i) => `${i + 1}. ${t.title}`).join('\n')}`
              }],
              isError: true
            };
          }

          console.log('[update_task_by_title] Found task:', foundTask.title, 'ID:', foundTask.id);

          // CRITICAL FIX: Start with existing task data to preserve all fields
          const patch = {
            id: foundTask.id,
            title: foundTask.title,
            notes: foundTask.notes || '',
            status: foundTask.status || 'needsAction'
          };
          
          // Preserve existing due date if present
          if (foundTask.due) {
            patch.due = foundTask.due;
          }

          // Only override fields that are explicitly provided and non-empty
          if (typeof request.params.arguments?.new_title === 'string' && request.params.arguments.new_title.trim().length) {
            patch.title = request.params.arguments.new_title.trim();
          }
          if (typeof request.params.arguments?.new_notes === 'string' && request.params.arguments.new_notes.trim().length) {
            patch.notes = request.params.arguments.new_notes.trim();
          }
          if (typeof request.params.arguments?.new_status === 'string' && request.params.arguments.new_status.trim().length) {
            const ns = String(request.params.arguments.new_status).trim();
            const nsNorm = ns === 'completed' || ns.toLowerCase() === 'completed' ? 'completed' : ns === 'needsAction' || ns.toLowerCase() === 'needsaction' || ns.toLowerCase() === 'needs action' ? 'needsAction' : null;
            if (nsNorm) patch.status = nsNorm;
          }

          // FIXED: Better due date handling (store as UTC-internal and display as UTC)
          if (typeof request.params.arguments?.new_due === 'string' && request.params.arguments.new_due.trim().length) {
            let dueInput = request.params.arguments.new_due.trim();
            let dueDate = null;
            
            // Try multiple date formats
            if (/^\d{4}-\d{2}-\d{2}$/.test(dueInput)) {
              // YYYY-MM-DD format — treat as UTC midnight for Tasks API
              dueDate = new Date(dueInput + 'T00:00:00Z');
            } else if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(dueInput)) {
              // RFC 3339 format
              dueDate = new Date(dueInput);
            } else {
              // Natural language parsing (best effort)
              dueDate = new Date(dueInput);
            }
            
            // Only apply if parsing succeeded
            if (dueDate && !isNaN(dueDate.getTime())) {
              patch.due = dueDate.toISOString();
            } else {
              console.warn('[update_task_by_title] Could not parse due date:', dueInput);
              // Don't fail the entire update, just skip the due date change
            }
          }

          console.log('[update_task_by_title] Applying patch:', JSON.stringify(patch));

          // Perform update with FULL task data
          const updated = await callWithAutoRefresh(
            () => tasks.tasks.update({ tasklist: taskListId, task: foundTask.id, requestBody: patch }),
            oauth2, sessionId, acctKey
          );

          console.log('[update_task_by_title] Update API call completed');

          // Verify update
          const verified = await callWithAutoRefresh(
            () => tasks.tasks.get({ tasklist: taskListId, task: foundTask.id }),
            oauth2, sessionId, acctKey
          );

          const final = verified?.data || updated?.data;
          
          console.log('[update_task_by_title] Verification complete. Final title:', final?.title);
          
          // Build response showing what actually changed
          let responseText = `✅ Task updated successfully!\n\n`;
          
          const changedFields = [];
          if (request.params.arguments?.new_title && foundTask.title !== patch.title) {
            changedFields.push(`• Title: "${foundTask.title}" → "${patch.title}"`);
          }
          if (request.params.arguments?.new_notes && foundTask.notes !== patch.notes) {
            changedFields.push(`• Notes updated`);
          }
          if (request.params.arguments?.new_due) {
            // Display due as UTC to avoid timezone shift
            try {
              changedFields.push(`• Due date: ${new Date(patch.due).toLocaleDateString(undefined, { timeZone: 'UTC' })}`);
            } catch (e) {
              changedFields.push(`• Due date updated`);
            }
          }
          if (request.params.arguments?.new_status && foundTask.status !== patch.status) {
            changedFields.push(`• Status: ${patch.status}`);
          }

          if (changedFields.length > 0) {
            responseText += `Changes made:\n${changedFields.join('\n')}\n`;
          } else {
            responseText += `No changes made (all fields already match)\n`;
          }
          
          responseText += `\n📋 Current task state:\n`;
          responseText += `Title: ${final.title}\n`;
          if (final.notes) responseText += `Notes: ${final.notes}\n`;
          if (final.due) responseText += `Due: ${new Date(final.due).toLocaleDateString(undefined, { timeZone: 'UTC' })}\n`;
          responseText += `Status: ${final.status}\n`;
          responseText += `\n🆔 Task ID: ${final.id}`;

          return { content: [{ type: 'text', text: responseText }], isError: false };
        } catch (err) {
          console.error('[update_task_by_title] Error:', err);
          return handleToolError(err, 'update_task_by_title', drv);
        }
      }

      if (request.params.name === 'delete_task') {
        const taskId = request.params.arguments?.task_id;
        if (!taskId) throw new Error('task_id required');

        console.log('[delete_task] Deleting task', taskId);
        try {
          const taskListIdRaw = request.params.arguments?.task_list_id || '@default';
          const taskListId = taskListIdRaw === '@default' ? '@default' : taskListIdRaw;

          await callWithAutoRefresh(() => tasks.tasks.delete({ tasklist: taskListId, task: taskId }), oauth2, sessionId, acctKey);
          console.log('[delete_task] Deleted task', taskId);

          return { content: [{ type: 'text', text: '✅ Task deleted successfully' }], isError: false };
        } catch (err) {
          return handleToolError(err, 'delete_task', drv);
        }
      }

      if (request.params.name === 'complete_task' || request.params.name === 'uncomplete_task') {
        const taskId = request.params.arguments?.task_id;
        if (!taskId) throw new Error('task_id required');

        console.log(`[${request.params.name}]`, taskId);
        try {
          const taskListIdRaw = request.params.arguments?.task_list_id || '@default';
          const taskListId = taskListIdRaw === '@default' ? '@default' : taskListIdRaw;
          const status = request.params.name === 'complete_task' ? 'completed' : 'needsAction';
          const patch = { status };
          if (status === 'completed') {
            patch.completed = new Date().toISOString();
          }

          // include id in body for Tasks.update
          if (!patch.id) patch.id = taskId;

          const updated = await callWithAutoRefresh(
            () => tasks.tasks.update({ tasklist: taskListId, task: taskId, requestBody: patch }),
            oauth2, sessionId, acctKey
          );
          console.log(`[${request.params.name}] Updated task`, taskId);

          const emoji = status === 'completed' ? '✅' : '⬜';
          const text = status === 'completed' ? 'completed' : 'reopened';
          return { content: [{ type: 'text', text: `${emoji} Task ${text}: "${updated.data.title}"` }], isError: false };
        } catch (err) {
          return handleToolError(err, request.params.name, drv);
        }
      }

      if (request.params.name === 'complete_tasks_by_description') {
        const description = (request.params.arguments?.description || '').trim().toLowerCase();
        if (!description) throw new Error('description required');

        console.log('[complete_tasks_by_description] Searching for tasks matching:', description);
        try {
          const taskListId = request.params.arguments?.task_list_id || null;
          let allTasks = [];

          if (taskListId) {
            // Search in specific list
            const res = await callWithAutoRefresh(() => tasks.tasks.list({ tasklist: taskListId, showCompleted: false, maxResults: 1000 }), oauth2, sessionId, acctKey);
            const items = Array.isArray(res?.data?.items) ? res.data.items : [];
            allTasks = items.map(t => ({ ...t, _listId: taskListId }));
          } else {
            // Search across all lists
            const listsRes = await callWithAutoRefresh(() => tasks.tasklists.list({ maxResults: 100 }), oauth2, sessionId, acctKey);
            const lists = Array.isArray(listsRes?.data?.items) ? listsRes.data.items : [];

            for (const list of lists) {
              try {
                const res = await callWithAutoRefresh(() => tasks.tasks.list({ tasklist: list.id, showCompleted: false, maxResults: 1000 }), oauth2, sessionId, acctKey);
                const items = Array.isArray(res?.data?.items) ? res.data.items : [];
                allTasks.push(...items.map(t => ({ ...t, _listId: list.id, _listTitle: list.title })));
              } catch (e) {
                console.warn('[complete_tasks_by_description] Failed to search list', list.id, e && e.message);
              }
            }
          }

          // Filter by description keywords
          const matched = allTasks.filter(task => {
            const title = (task.title || '').toLowerCase();
            const notes = (task.notes || '').toLowerCase();
            return title.includes(description) || notes.includes(description);
          });

          if (!matched.length) {
            return { content: [{ type: 'text', text: `No incomplete tasks found matching: "${description}"` }], isError: false };
          }

          console.log('[complete_tasks_by_description] Found', matched.length, 'tasks to complete');

          // Complete all matched tasks
          const completed = [];
          const failed = [];

          for (const task of matched) {
            try {
              const patch = { status: 'completed', completed: new Date().toISOString() };
              if (!patch.id) patch.id = task.id;
              await callWithAutoRefresh(() => tasks.tasks.update({ tasklist: task._listId, task: task.id, requestBody: patch }), oauth2, sessionId, acctKey);
              completed.push(task.title);
              console.log('[complete_tasks_by_description] Completed task:', task.title);
            } catch (e) {
              console.warn('[complete_tasks_by_description] Failed to complete task', task.id, e && e.message);
              failed.push(task.title);
            }
          }

          // Build response
          let summary = `✅ Task Completion Summary:\n\n`;

          if (completed.length > 0) {
            summary += `Completed ${completed.length} task${completed.length > 1 ? 's' : ''}:\n`;
            completed.forEach((title, idx) => {
              summary += `${idx + 1}. ${title}\n`;
            });
          }

          if (failed.length > 0) {
            summary += `\n❌ Failed to complete ${failed.length} task${failed.length > 1 ? 's' : ''}:\n`;
            failed.forEach((title, idx) => {
              summary += `${idx + 1}. ${title}\n`;
            });
          }

          return { content: [{ type: 'text', text: summary }], isError: false };
        } catch (err) {
          return handleToolError(err, 'complete_tasks_by_description', drv);
        }
      }

      if (request.params.name === 'search_tasks') {
        const query = (request.params.arguments?.query || '').trim().toLowerCase();
        if (!query) throw new Error('query required');

        console.log('[search_tasks] Searching for:', query);
        try {
          const taskListId = request.params.arguments?.task_list_id || null;
          const includeCompleted = !!request.params.arguments?.include_completed;
          let allTasks = [];

          if (taskListId) {
            const res = await callWithAutoRefresh(() => tasks.tasks.list({ tasklist: taskListId, showCompleted: includeCompleted, maxResults: 1000 }), oauth2, sessionId, acctKey);
            const items = Array.isArray(res?.data?.items) ? res.data.items : [];
            allTasks = items.map(t => ({ ...t, _listId: taskListId }));
          } else {
            const listsRes = await callWithAutoRefresh(() => tasks.tasklists.list({ maxResults: 100 }), oauth2, sessionId, acctKey);
            const lists = Array.isArray(listsRes?.data?.items) ? listsRes.data.items : [];

            for (const list of lists) {
              try {
                const res = await callWithAutoRefresh(() => tasks.tasks.list({ tasklist: list.id, showCompleted: includeCompleted, maxResults: 1000 }), oauth2, sessionId, acctKey);
                const items = Array.isArray(res?.data?.items) ? res.data.items : [];
                allTasks.push(...items.map(t => ({ ...t, _listId: list.id, _listTitle: list.title })));
              } catch (e) {}
            }
          }

          const matched = allTasks.filter(task => {
            const title = (task.title || '').toLowerCase();
            const notes = (task.notes || '').toLowerCase();
            return title.includes(query) || notes.includes(query);
          });

          if (!matched.length) {
            return { content: [{ type: 'text', text: `No tasks found matching: "${query}"` }], isError: false };
          }

          let summary = `🔍 Found ${matched.length} task${matched.length !== 1 ? 's' : ''} matching "${query}":\n\n`;
          matched.forEach((task, idx) => {
            const checkbox = task.status === 'completed' ? '✅' : '⬜';
            summary += `${idx + 1}. ${checkbox} ${task.title}\n`;
            if (task._listTitle) summary += `   📋 ${task._listTitle}\n`;
            if (task.due) summary += `   📅 Due: ${new Date(task.due).toLocaleDateString()}\n`;
            summary += '\n';
          });

          // Also include a lightweight task context mapping for follow-up actions (positions -> ids)
          const _taskContext = matched.map((t) => ({ id: t.id, title: t.title, listId: t._listId }));
          return { content: [{ type: 'text', text: summary }], isError: false, _taskContext };
        } catch (err) {
          return handleToolError(err, 'search_tasks', drv);
        }
      }

      throw new Error('Tool not found');
    } catch (err) {
      if (err && err.missingSessionId) {
        return { content: authRequiredContent(err.missingSessionId, 'No per-session token'), isError: false };
      }
      if (err && err.message && err.message.startsWith('Multiple accounts available. Pass email:')) {
        return { content: [{ type: 'text', text: err.message }], isError: true };
      }
      throw err;
    }
  });

  return server;
}

// Transports store
const transports = {};
let _lastSessionId = null;
function getSessionId() {
  return _lastSessionId;
}

// Auth routes
app.get('/auth/start', (req, res) => {
  const session = req.query.session;
  if (!session)
    return res.status(400).send('Missing session query parameter. Use /auth/start?session=<mcp-session-id>');
  if (!OAUTH_CLIENT_ID || !OAUTH_CLIENT_SECRET)
    return res.status(500).send('OAuth client not configured on server');

  const oauth2 = new google.auth.OAuth2(OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_REDIRECT_URI);
  const allowedScopes = [
    'https://www.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/documents',
    'https://www.googleapis.com/auth/userinfo.email',
    'openid',
    'https://www.googleapis.com/auth/tasks',
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/calendar',
    'https://www.googleapis.com/auth/calendar.events'
  ];
  const requestedScopes =
    typeof req.query.scopes === 'string' && req.query.scopes.trim().length
      ? req.query.scopes.split(/\s+/)
      : allowedScopes;
  const scopes = requestedScopes.filter((s) => allowedScopes.includes(s));
  if (scopes.length === 0) scopes.push(...allowedScopes);

  let promptOpt = undefined;
  try {
    const existing = loadTokens(session, { permissiveFallback: false });
    if (!existing || !existing.tokens || !existing.tokens.refresh_token) {
      promptOpt = 'consent';
    } else if (existing.tokens && existing.tokens.scope) {
      const have = String(existing.tokens.scope).split(/\s+/).filter(Boolean);
      const need = allowedScopes;
      const missing = need.find((s) => !have.includes(s));
      if (missing) promptOpt = 'consent';
    }
  } catch {
    promptOpt = 'consent';
  }

  const url = oauth2.generateAuthUrl({
    access_type: 'offline',
    scope: scopes,
    state: session,
    include_granted_scopes: true,
    ...(promptOpt ? { prompt: promptOpt } : {})
  });
  console.log('Starting OAuth for session', session);
  res.redirect(url);
});

// Return auth URL as JSON (public endpoint)
app.get('/auth/url', (req, res) => {
  const headerSid = req.header('Mcp-Session-Id') || req.header('mcp-session-id');
  const cookieSid = (() => {
    try {
      const c = req.headers.cookie || '';
      const m = c.split(/;\s*/).map((p) => p.split('='));
      for (const [k, v] of m) {
        if (k && k.trim() === 'mcp-session-id') return decodeURIComponent((v || '').trim());
      }
    } catch (e) {}
    return null;
  })();

  let session = headerSid || req.query.session || cookieSid || null;
  let stateType = 'client-provided';
  if (!session) {
    session = randomUUID();
    stateType = 'server-minted';
  }

  if (!OAUTH_CLIENT_ID || !OAUTH_CLIENT_SECRET)
    return res.status(500).json({ ok: false, error: 'OAuth client not configured on server' });

  try {
    const oauth2 = new google.auth.OAuth2(OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_REDIRECT_URI);
    const allowedScopes = [
      'https://www.googleapis.com/auth/drive',
      'https://www.googleapis.com/auth/documents',
      'https://www.googleapis.com/auth/userinfo.email',
      'openid',
      'https://www.googleapis.com/auth/tasks',
      'https://www.googleapis.com/auth/gmail.readonly',
      'https://www.googleapis.com/auth/gmail.send',
      'https://www.googleapis.com/auth/gmail.modify',
      'https://www.googleapis.com/auth/calendar',
      'https://www.googleapis.com/auth/calendar.events'
    ];

    const requestedScopes =
      typeof req.query.scopes === 'string' && req.query.scopes.trim().length
        ? req.query.scopes.split(/\s+/)
        : allowedScopes;
    const scopes = requestedScopes.filter((s) => allowedScopes.includes(s));
    if (scopes.length === 0) scopes.push(...allowedScopes);

    let promptOpt = undefined;
    try {
      const existing = loadTokens(session, { permissiveFallback: false });
      if (!existing || !existing.tokens || !existing.tokens.refresh_token) {
        promptOpt = 'consent';
      } else if (existing.tokens && existing.tokens.scope) {
        const have = String(existing.tokens.scope).split(/\s+/).filter(Boolean);
        const need = allowedScopes;
        const missing = need.find((s) => !have.includes(s));
        if (missing) promptOpt = 'consent';
      }
    } catch {
      promptOpt = 'consent';
    }

    const url = oauth2.generateAuthUrl({
      access_type: 'offline',
      scope: scopes,
      state: session,
      include_granted_scopes: true,
      ...(promptOpt ? { prompt: promptOpt } : {})
    });

    res.setHeader('Mcp-Session-Id', session);
    try {
      res.cookie('mcp-session-id', session, { httpOnly: true, sameSite: 'lax', path: '/' });
    } catch (e) {}
    res.set('Cache-Control', 'no-store');
    return res.json({ ok: true, sessionId: session, state: stateType, auth_url: url });
  } catch (e) {
    console.error('auth/url error', e && (e.stack || e));
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// Alias for Python server compatibility
app.get('/oauth2callback', (req, res) => {
  try {
    const qs = new URLSearchParams(req.query).toString();
    return res.redirect(302, `/auth/callback?${qs}`);
  } catch (e) {
    return res.redirect(302, '/auth/callback');
  }
});

app.get('/auth/callback', async (req, res) => {
  const code = req.query.code;
  const state = req.query.state;
  if (!code || !state) return res.status(400).send('Missing code or state in callback');

  const rawState = String(state || '');
  console.log('Auth callback raw state:', JSON.stringify(rawState));
  let first = rawState.trim().split(/\s+/)[0] || '';
  try {
    const decoded = decodeURIComponent(first);
    if (decoded && decoded !== first) first = decoded.trim().split(/\s+/)[0] || '';
  } catch {}
  const sessionId =
    (first.match(/^([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/i) || [null])[0];

  console.log('Auth callback parsed sessionId:', sessionId);
  if (!sessionId) return res.status(400).send('Invalid state value');

  if (!OAUTH_CLIENT_ID || !OAUTH_CLIENT_SECRET)
    return res.status(500).send('OAuth client not configured on server');

  try {
    const oauth2 = new google.auth.OAuth2(OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_REDIRECT_URI);
    const { tokens } = await oauth2.getToken(code);

    let merged = tokens;
    try {
      const existing = loadTokens(sessionId, { permissiveFallback: false });
      if (existing?.tokens) merged = Object.assign({}, existing.tokens, tokens);
    } catch {}

    oauth2.setCredentials(merged);

    let acctKey = null;
    try {
      const oauth2Client = google.oauth2({ auth: oauth2, version: 'v2' });
      const me = await oauth2Client.userinfo.get();
      acctKey = (me.data && (me.data.email || me.data.id))
        ? String(me.data.email || me.data.id).toLowerCase()
        : null;
    } catch {}

    try {
      saveSessionTokens(sessionId, merged, acctKey || undefined);
      if (acctKey) saveTokensForSession(sessionId, merged, acctKey);
    } catch (e) {
      console.error('Failed to save session tokens for', sessionId, e && e.message);
      throw e;
    }

    try {
      const t = transports[sessionId];
      if (t && typeof t.notify === 'function') {
        try {
          t.notify('auth/success', { sessionId });
        } catch (e) {
          console.warn('Transport notify failed', e && e.message);
        }
      }
    } catch {}

    res.send(
      `<html><body><h3>Authorization complete</h3><p>You can now return to FlyerGPT. Session: ${sessionId}</p></body></html>`
    );
  } catch (err) {
    console.error('Auth callback token exchange failed:', err);
    res.status(500).send('Token exchange failed: ' + String(err));
  }
});

// Session status endpoint (public for polling)
app.get('/session/status', async (req, res) => {
  try {
    const headerSid = req.header('Mcp-Session-Id') || req.header('mcp-session-id');
    const cookieSid = (() => {
      try {
        const c = req.headers.cookie || '';
        const m = c.split(/;\s*/).map((p) => p.split('='));
        for (const [k, v] of m) {
          if (k && k.trim() === 'mcp-session-id') return decodeURIComponent((v || '').trim());
        }
      } catch (e) {}
      return null;
    })();

    const session = headerSid || req.query.session || cookieSid || null;
    if (!session) return res.status(400).json({ ok: false, code: 'BAD_REQUEST', message: 'missing session' });

    try {
      const found = loadTokens(session, { permissiveFallback: false });
      let bound = false;
      let email = null;
      let scopes = [];
      if (found && found.tokens) {
        try {
          const oauth2 = new google.auth.OAuth2(OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_REDIRECT_URI);
          oauth2.setCredentials(found.tokens);
          try {
            if (typeof oauth2.refreshAccessToken === 'function') {
              await oauth2.refreshAccessToken();
            } else if (oauth2?.credentials?.refresh_token) {
              await oauth2.getAccessToken();
            }
          } catch (refreshErr) {
            throw refreshErr;
          }

          const oauth2Client = google.oauth2({ auth: oauth2, version: 'v2' });
          const me = await oauth2Client.userinfo.get();
          email = (me.data && me.data.email) || found.account || null;
          bound = true;
          scopes = found.tokens && found.tokens.scope ? found.tokens.scope.split(' ') : [];
        } catch (e) {
          bound = false;
          email = null;
          scopes = [];
        }
      }

      res.setHeader('Mcp-Session-Id', session);
      try {
        res.cookie('mcp-session-id', session, { httpOnly: true, sameSite: 'lax', path: '/' });
      } catch (e) {}
      res.set('Cache-Control', 'no-store');

      return res.json({ ok: true, sessionId: session, bound, email, scopes });
    } catch (e) {
      return res.status(500).json({ ok: false, error: String(e) });
    }
  } catch (err) {
    console.error('session/status outer error:', err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

// Attach session id to request
app.use((req, res, next) => {
  req.mcpSessionId = req.headers['mcp-session-id'] || req.query.session || null;
  const sid = req.headers['mcp-session-id'] || req.headers['Mcp-Session-Id'] || null;
  if (sid) res.setHeader('Mcp-Session-Id', sid);
  next();
});

// Auth-required content blocks
function authRequiredContent(sessionId, reason) {
  const authUrl = `${String(PUBLIC_BASE_URL || '').replace(/\/$/, '')}/auth/start?session=${encodeURIComponent(
    sessionId || ''
  )}`;
  const msg = (reason ? `${reason}\n` : '') + `Authorize Google Drive for this session:\n${authUrl}`;
  return [{ type: 'text', text: msg }];
}

// MCP endpoint
app.post('/mcp', checkAuth, async (req, res) => {
  try {
    console.log('--- incoming /mcp POST ---');
    try {
      const headers = Object.assign({}, req.headers || {});
      if (headers.authorization) headers.authorization = mask(headers.authorization);
      Object.keys(headers).forEach((k) => {
        if (/token|auth|authorization/i.test(k)) headers[k] = mask(headers[k]);
      });
      console.log('headers:', JSON.stringify(headers));
    } catch {}
    try {
      console.log('bodyKeys:', Object.keys(req.body || {}), 'bodySize:', JSON.stringify(req.body || {}).length);
    } catch {}

    const sessionHeader = req.headers['mcp-session-id'] || req.headers['Mcp-Session-Id'];
    let transport;

    if (sessionHeader && transports[sessionHeader]) {
      transport = transports[sessionHeader];
    } else if (isInitializeRequest(req.body)) {
      const clientProposed = sessionHeader;
      const rfc4122 =
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      let sess = null;
      if (clientProposed) {
        if (rfc4122.test(clientProposed)) {
          if (transports[clientProposed]) {
            transport = transports[clientProposed];
            console.log('Reusing existing transport for proposed session id:', clientProposed);
          } else {
            sess = clientProposed;
            console.log('Accepted client-proposed session id for initialize:', clientProposed);
          }
        } else {
          console.log('Rejected client-proposed session id (invalid):', clientProposed);
          sess = randomUUID();
        }
      } else {
        sess = randomUUID();
      }

      if (!transport) {
        if (!REQUIRE_SESSION_ONLY) {
          try {
            ensureSessionHasTokens(sess);
          } catch {}
        }
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => sess,
          onsessioninitialized: (id) => {
            transports[id] = transport;
          }
        });

        try {
          if (typeof transport.onHttpRequest === 'function') {
            transport.onHttpRequest(({ headers }) => {
              try {
                _lastSessionId = headers['mcp-session-id'] || headers['Mcp-Session-Id'] || null;
              } catch (e) {
                _lastSessionId = null;
              }
            });
          }
        } catch (e) {}

        const server = createMcpServer(
          (request) => {
            const rawAccount =
              request?.params?.arguments && typeof request.params.arguments.email === 'string'
                ? request.params.arguments.email
                : null;
            const account =
              rawAccount && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(rawAccount)
                ? rawAccount.toLowerCase()
                : null;

            const per = loadTokens(sess, { permissiveFallback: false });
            const choices = listStableAccounts();
            if (!per && !account && choices.length > 1) {
              const e = new Error(`Multiple accounts available. Pass email: ${choices.join(', ')}`);
              throw e;
            }

            const requireForThis = REQUIRE_SESSION_ONLY === true;
            return makeDriveForSession(sess, requireForThis, account);
          },
          () => sess
        );
        await server.connect(transport);
      }
    } else if (sessionHeader && !transports[sessionHeader]) {
      res
        .status(400)
        .json({ jsonrpc: '2.0', error: { code: -32000, message: 'No transport for session' }, id: null });
      return;
    } else {
      return res
        .status(400)
        .json({ jsonrpc: '2.0', error: { code: -32000, message: 'Initialize with a session first' }, id: null });
    }

    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    console.error('Error /mcp POST:', err && err.stack ? err.stack : err);
    if (!res.headersSent)
      res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: String(err) }, id: null });
  }
});

app.get('/mcp', checkAuth, async (req, res) => {
  try {
    let sessionId = req.headers['mcp-session-id'] || req.query.sessionId;
    if (!sessionId) {
      const active = Object.keys(transports || {});
      if (active.length === 1) sessionId = active[0];
    }
    if (!sessionId || !transports[sessionId]) {
      res.status(400).json({ ok: false, error: 'Invalid or missing session ID' });
      return;
    }
    const transport = transports[sessionId];
    await transport.handleRequest(req, res);
  } catch (err) {
    console.error('Error /mcp GET:', err);
    if (!res.headersSent) res.status(500).send('Internal server error');
  }
});

app.post('/session', checkAuth, async (_req, res) => {
  try {
    const newId = randomUUID();
    res.json({ ok: true, sessionId: newId });
  } catch (err) {
    console.error('Error issuing session id:', err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

app.delete('/mcp', checkAuth, async (req, res) => {
  try {
    const sessionId = req.headers['mcp-session-id'];
    if (!sessionId || !transports[sessionId]) {
      res.status(400).send('Invalid or missing session ID');
      return;
    }
    const t = transports[sessionId];
    if (t && typeof t.close === 'function') t.close();
    delete transports[sessionId];
    try {
      deleteSession(sessionId);
    } catch {}
    res.status(200).send('OK');
  } catch (err) {
    console.error('Error /mcp DELETE:', err);
    res.status(500).send('Internal server error');
  }
});

app.get('/whoami', checkAuth, async (req, res) => {
  try {
    const session = req.query.session || req.headers['mcp-session-id'];
    if (!session) return res.status(400).json({ ok: false, error: 'Missing session id' });

    try {
      const per = loadTokens(session, { permissiveFallback: false });
      if (!per || !per.tokens) {
        const authUrl = `${PUBLIC_BASE_URL.replace(/\/$/, '')}/auth/start?session=${encodeURIComponent(session)}`;
        return res.json({ ok: true, bound: false, authHint: authUrl });
      }
      const oauth2 = new google.auth.OAuth2(OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_REDIRECT_URI);
      oauth2.setCredentials(per.tokens);
      const oauth2Client = google.oauth2({ auth: oauth2, version: 'v2' });
      const me = await oauth2Client.userinfo.get();
      return res.json({
        ok: true,
        bound: true,
        email: (me.data && me.data.email) || per.account || null,
        scopes: per.tokens && per.tokens.scope ? per.tokens.scope.split(' ') : []
      });
    } catch (e) {
      console.error('whoami route error:', e);
      return res.status(500).json({ ok: false, error: String(e) });
    }
  } catch (err) {
    console.error('whoami route outer error:', err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

app.get('/health', async (_req, res) => {
  try {
    const oauthExists = fs.existsSync(oauthPath);
    const credsExists = fs.existsSync(savedCredsPath);
    try {
      const tokenFiles = fs.existsSync(tokensDir)
        ? fs.readdirSync(tokensDir).filter((f) => f.endsWith('.json'))
        : [];
      return res.json({
        ok: true,
        oauthExists,
        credsExists,
        mode: REQUIRE_SESSION_ONLY ? 'require-session-only' : 'permissive',
        tokenFiles: tokenFiles.length
      });
    } catch (e) {
      return res.status(500).json({ ok: false, oauthExists, credsExists, error: String(e) });
    }
  } catch (err) {
    console.error('Health route error:', err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

app.get('/sessions', checkAuth, async (_req, res) => {
  try {
    const active = Object.keys(transports || {});
    const sessions = active.map((id) => ({
      sessionId: id,
      hasTokens: fs.existsSync(path.join(tokensDir, `${id}.json`))
    }));
    const tokenFiles = fs.existsSync(tokensDir)
      ? fs.readdirSync(tokensDir).filter((f) => f.endsWith('.json'))
      : [];
    const orphanTokens = tokenFiles.map((f) => f.replace(/\.json$/, '')).filter((id) => !active.includes(id));
    res.json({ ok: true, sessions, orphanTokens });
  } catch (err) {
    console.error('Error /sessions:', err);
    res.status(500).json({ ok: false, error: String(err) });
  }
});

// Server and shutdown
const httpServer = app.listen(PORT, () => console.log(`GDrive MCP HTTP server listening on port ${PORT}`));

function gracefulShutdown() {
  console.log('Graceful shutdown initiated');
  try {
    Object.keys(transports).forEach((id) => {
      try {
        if (transports[id] && typeof transports[id].close === 'function') transports[id].close();
      } catch (e) {
        console.warn('Error closing transport', id, e && e.message);
      }
      try {
        delete transports[id];
      } catch {}
    });
    if (httpServer && typeof httpServer.close === 'function') {
      httpServer.close(() => {
        console.log('HTTP server closed');
        process.exit(0);
      });
      setTimeout(() => {
        console.warn('Forcing shutdown after timeout');
        process.exit(1);
      }, 5000);
    } else {
      process.exit(0);
    }
  } catch (e) {
    console.error('Shutdown failure', e);
    process.exit(1);
  }
}

process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);
process.on('uncaughtException', (e) => {
  console.error('uncaughtException', e && (e.stack || e));
});
process.on('unhandledRejection', (e) => {
  console.error('unhandledRejection', e && (e.stack || e));
});