const path = require('path');
const fs = require('fs');
const { google } = require('googleapis');

// Load environment variables from .env if present
try {
  require('dotenv').config();
} catch {}

try {
  process.umask(0o077);
} catch {}

// ============================================================================
// CONFIGURATION
// ============================================================================

const PORT = process.env.PORT || 3001;
const BEARER = process.env.AUTH_BEARER_TOKEN || null;
const ALLOW_ANONYMOUS = process.env.ALLOW_ANONYMOUS === '1';
const PUBLIC_BASE_URL =
  process.env.PUBLIC_BASE_URL || process.env.PUBLIC_URL || `http://localhost:${PORT}`;
const ENFORCE_HTTPS = process.env.ENFORCE_HTTPS === '1' || process.env.ENFORCE_HTTPS === 'true';

// Token expiry: 8 hours of inactivity
const TOKEN_EXPIRY_MS = 8 * 60 * 60 * 1000; // 8 hours in milliseconds

// Security & audit config
const TOKEN_ENCRYPTION_KEY = process.env.TOKEN_ENCRYPTION_KEY || null;
const AUDIT_LOG_PATH = path.join(__dirname, '../../audit.log');

// CORS configuration
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS || '';
const parsedAllowedOrigins = ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(Boolean);

// Paths
const credsDir = path.join(__dirname, '../../..', 'gdrive-mcp-server', 'credentials');
let oauthPath =
  process.env.GOOGLE_APPLICATION_CREDENTIALS || path.join(credsDir, 'gcp-oauth.keys.json');

const tokensDir = path.join(__dirname, '../../tokens');
const usersDir = path.join(__dirname, '../../users');
if (!fs.existsSync(tokensDir)) fs.mkdirSync(tokensDir, { recursive: true });
if (!fs.existsSync(usersDir)) fs.mkdirSync(usersDir, { recursive: true });

// API keys directory (per-email API keys)
const API_KEYS_DIR = path.join(__dirname, '../../api_keys');
if (!fs.existsSync(API_KEYS_DIR)) {
  fs.mkdirSync(API_KEYS_DIR, { recursive: true });
}

// Load OAuth JSON from env if provided
try {
  if (process.env.GOOGLE_OAUTH_JSON) {
    const p = path.join('/tmp', 'gcp-oauth.keys.json');
    fs.writeFileSync(p, process.env.GOOGLE_OAUTH_JSON, 'utf8');
    oauthPath = p;
    console.log('Loaded GOOGLE_OAUTH_JSON into', p);
  }
} catch (e) {
  console.warn('Failed to load JSON credential env vars:', e && e.message);
}

if (!fs.existsSync(oauthPath)) {
  console.error('OAuth client JSON not found at', oauthPath);
}

// Read client JSON
let oauthClientJson = null;
if (fs.existsSync(oauthPath)) {
  try {
    oauthClientJson = JSON.parse(fs.readFileSync(oauthPath, 'utf8'));
  } catch (e) {
    console.warn('Failed to parse OAuth client JSON at', oauthPath, e && e.message);
  }
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
  
  OAUTH_REDIRECT_URI =
    process.env.GOOGLE_REDIRECT_URI ||
    (redirectUris && redirectUris.find((u) => /\/auth\/callback$/.test(u))) ||
    (redirectUris && redirectUris[0]) ||
    null;
    
  if (!OAUTH_REDIRECT_URI) {
    throw new Error('Missing OAuth redirect URI. Set GOOGLE_REDIRECT_URI or ensure client JSON contains a redirect_uri');
  }
}

const SCOPES = [
  'openid',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
  'https://www.googleapis.com/auth/drive',
  'https://www.googleapis.com/auth/documents',
  'https://www.googleapis.com/auth/gmail.readonly',
  'https://www.googleapis.com/auth/gmail.send',
  'https://www.googleapis.com/auth/gmail.modify',
  'https://www.googleapis.com/auth/calendar',
  'https://www.googleapis.com/auth/calendar.events',
  'https://www.googleapis.com/auth/tasks'
];

// Rate limiting
const RATE_WINDOW_MS = Number(process.env.MCP_RATE_WINDOW_MS || 60000);
const RATE_MAX_REQUESTS = Number(process.env.MCP_RATE_MAX_REQUESTS || 120);
const TRANSPORT_TTL_MS = Number(process.env.MCP_SESSION_TTL_MS || 60 * 60 * 1000);

module.exports = {
  PORT,
  BEARER,
  ALLOW_ANONYMOUS,
  PUBLIC_BASE_URL,
  ENFORCE_HTTPS,
  TOKEN_EXPIRY_MS,
  TOKEN_ENCRYPTION_KEY,
  AUDIT_LOG_PATH,
  ALLOWED_ORIGINS: parsedAllowedOrigins,
  tokensDir,
  usersDir,
  API_KEYS_DIR,
  OAUTH_CLIENT_ID,
  OAUTH_CLIENT_SECRET,
  OAUTH_REDIRECT_URI,
  SCOPES,
  RATE_WINDOW_MS,
  RATE_MAX_REQUESTS,
  TRANSPORT_TTL_MS
};
