#!/usr/bin/env node

/**
 * Email-Based Google Workspace MCP Server
 * 
 * Authentication model: Email-based user identification
 * - Users authenticate using their email address
 * - Tokens are stored per email, not per session
 * - Multiple sessions can use the same email's credentials
 * - OAuth flow requires email parameter
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
const PUBLIC_BASE_URL =
  process.env.PUBLIC_BASE_URL || process.env.PUBLIC_URL || `http://localhost:${PORT}`;

console.log('[AUTH MODE] Email-based authentication');

// Bearer auth middleware
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

const tokensDir = path.join(__dirname, 'tokens');
const usersDir = path.join(__dirname, 'users');
if (!fs.existsSync(tokensDir)) fs.mkdirSync(tokensDir, { recursive: true });
if (!fs.existsSync(usersDir)) fs.mkdirSync(usersDir, { recursive: true });

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

// ============================================================================
// EMAIL-BASED USER STORAGE
// ============================================================================

/**
 * Get safe filename for email
 */
function emailToFilename(email) {
  return email.toLowerCase().replace(/[^a-z0-9@._-]/g, '_');
}

/**
 * Get user data file path
 */
function getUserPath(email) {
  return path.join(usersDir, `${emailToFilename(email)}.json`);
}

/**
 * Create or get user by email
 */
function getOrCreateUser(email, displayName = null) {
  const emailLower = email.toLowerCase().trim();
  const userPath = getUserPath(emailLower);
  
  if (fs.existsSync(userPath)) {
    try {
      const data = JSON.parse(fs.readFileSync(userPath, 'utf8'));
      return data;
    } catch (e) {
      console.warn('Failed to read user file for', emailLower, e.message);
    }
  }
  
  // Create new user
  const userId = randomUUID();
  const userData = {
    user_id: userId,
    email: emailLower,
    display_name: displayName || emailLower,
    created_at: new Date().toISOString(),
    last_login: new Date().toISOString(),
    is_active: true
  };
  
  try {
    fs.writeFileSync(userPath, JSON.stringify(userData, null, 2), { encoding: 'utf8', mode: 0o600 });
    console.log('Created user:', emailLower);
    return userData;
  } catch (e) {
    console.error('Failed to create user file:', e.message);
    throw e;
  }
}

/**
 * Get user by email (returns null if not exists)
 */
function getUserByEmail(email) {
  const emailLower = email.toLowerCase().trim();
  const userPath = getUserPath(emailLower);
  
  if (!fs.existsSync(userPath)) {
    return null;
  }
  
  try {
    return JSON.parse(fs.readFileSync(userPath, 'utf8'));
  } catch (e) {
    console.warn('Failed to read user file for', emailLower, e.message);
    return null;
  }
}

/**
 * Update user's last login
 */
function updateLastLogin(email) {
  const user = getUserByEmail(email);
  if (!user) return;
  
  user.last_login = new Date().toISOString();
  const userPath = getUserPath(email);
  
  try {
    fs.writeFileSync(userPath, JSON.stringify(user, null, 2), { encoding: 'utf8', mode: 0o600 });
  } catch (e) {
    console.warn('Failed to update last login:', e.message);
  }
}

/**
 * Store tokens for a user (by email)
 */
function storeTokensForEmail(email, tokens) {
  const emailLower = email.toLowerCase().trim();
  const tokenPath = path.join(tokensDir, `${emailToFilename(emailLower)}.json`);
  
  const tokenData = {
    email: emailLower,
    tokens: tokens,
    updated_at: new Date().toISOString()
  };
  
  try {
    fs.writeFileSync(tokenPath, JSON.stringify(tokenData, null, 2), { encoding: 'utf8', mode: 0o600 });
    console.log('Stored tokens for email:', emailLower);
    return true;
  } catch (e) {
    console.error('Failed to store tokens for', emailLower, ':', e.message);
    return false;
  }
}

/**
 * Load tokens for a user (by email)
 */
function loadTokensForEmail(email) {
  const emailLower = email.toLowerCase().trim();
  const tokenPath = path.join(tokensDir, `${emailToFilename(emailLower)}.json`);
  
  if (!fs.existsSync(tokenPath)) {
    return null;
  }
  
  try {
    const data = JSON.parse(fs.readFileSync(tokenPath, 'utf8'));
    return data.tokens;
  } catch (e) {
    console.warn('Failed to load tokens for', emailLower, ':', e.message);
    return null;
  }
}

/**
 * Verify email and return user if authenticated
 */
async function verifyEmail(email) {
  if (!email || typeof email !== 'string') {
    return null;
  }
  
  const emailLower = email.toLowerCase().trim();
  const user = getUserByEmail(emailLower);
  
  if (!user || !user.is_active) {
    return null;
  }
  
  const tokens = loadTokensForEmail(emailLower);
  if (!tokens) {
    return null;
  }
  
  return user;
}

/**
 * List all authenticated emails
 */
function listAuthenticatedEmails() {
  if (!fs.existsSync(tokensDir)) return [];
  
  try {
    const files = fs.readdirSync(tokensDir).filter(f => f.endsWith('.json'));
    return files.map(f => {
      try {
        const data = JSON.parse(fs.readFileSync(path.join(tokensDir, f), 'utf8'));
        return data.email;
      } catch {
        return null;
      }
    }).filter(Boolean);
  } catch (e) {
    console.warn('Failed to list authenticated emails:', e.message);
    return [];
  }
}

// ============================================================================
// GOOGLE API HELPERS
// ============================================================================

/**
 * Build OAuth2 client with auto-refresh for an email
 */
async function getCredentialsForEmail(email) {
  const emailLower = email.toLowerCase().trim();
  const tokens = loadTokensForEmail(emailLower);
  
  if (!tokens) {
    throw new Error(`No tokens found for email: ${emailLower}`);
  }
  
  const oauth2 = new google.auth.OAuth2(
    OAUTH_CLIENT_ID,
    OAUTH_CLIENT_SECRET,
    OAUTH_REDIRECT_URI
  );
  
  oauth2.setCredentials(tokens);
  
  // Auto-refresh if expired
  if (oauth2.credentials.expiry_date && oauth2.credentials.expiry_date < Date.now()) {
    console.log('Token expired for', emailLower, 'attempting refresh...');
    try {
      const { credentials } = await oauth2.refreshAccessToken();
      oauth2.setCredentials(credentials);
      storeTokensForEmail(emailLower, credentials);
      console.log('Token refreshed for', emailLower);
    } catch (e) {
      console.error('Token refresh failed for', emailLower, ':', e.message);
      throw new Error('Token refresh failed - user may need to re-authenticate');
    }
  }
  
  return oauth2;
}

/**
 * Call API with auto-refresh
 */
async function callWithAutoRefresh(actionFn, oauth2, email) {
  try {
    return await actionFn();
  } catch (err) {
    const status = err?.code || err?.response?.status;
    if (Number(status) === 401) {
      console.log('401 detected, attempting token refresh for', email);
      try {
        const { credentials } = await oauth2.refreshAccessToken();
        oauth2.setCredentials(credentials);
        storeTokensForEmail(email, credentials);
        return await actionFn();
      } catch (refreshErr) {
        console.warn('Token refresh failed for', email, refreshErr.message);
        throw new Error('Authentication expired - please re-authenticate');
      }
    }
    throw err;
  }
}

// ============================================================================
// ERROR HANDLING
// ============================================================================

function buildAuthRequired(email) {
  const base = String(PUBLIC_BASE_URL || '').replace(/\/$/, '');
  const authUrl = `${base}/auth/start?email=${encodeURIComponent(email || '')}`;
  return {
    ok: false,
    code: 'AUTH_REQUIRED',
    auth_url: authUrl,
    message: `User authorization required for ${email}. Visit auth_url to authenticate.`,
  };
}

function handleToolError(err, toolName, email) {
  console.error(`[${toolName}] Error:`, err && (err.stack || err));
  
  if (err.message && err.message.includes('Authentication expired')) {
    return {
      content: [{
        type: 'text',
        text: `❌ Authentication expired for ${email}. Please re-authenticate:\n${PUBLIC_BASE_URL}/auth/start?email=${encodeURIComponent(email)}`
      }],
      isError: false
    };
  }
  
  if (err.message && err.message.includes('No tokens found')) {
    return {
      content: [{
        type: 'text',
        text: `❌ No credentials found for ${email}. Please authenticate:\n${PUBLIC_BASE_URL}/auth/start?email=${encodeURIComponent(email)}`
      }],
      isError: false
    };
  }
  
  return {
    content: [{
      type: 'text',
      text: `❌ Error in ${toolName}: ${err.message || String(err)}`
    }],
    // IMPORTANT: keep isError=false so MCP clients like FlyerGPT
    // show this message instead of a generic "external data" error.
    isError: false
  };
}

// ============================================================================
// GMAIL HELPERS
// ============================================================================

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

async function fetchGmailMessages(gmail, oauth2, email, messageIds) {
  const results = [];
  for (const m of messageIds) {
    try {
      const md = await callWithAutoRefresh(
        () => gmail.users.messages.get({
          userId: 'me',
          id: m.id,
          format: 'metadata',
          metadataHeaders: ['From', 'To', 'Subject', 'Date']
        }),
        oauth2,
        email
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

// ============================================================================
// MCP SERVER
// ============================================================================

function createMcpServer() {
  const server = new Server(
    { name: 'gdrive-http-email', version: '0.2.0' },
    { capabilities: { resources: {}, tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const connectUrl = `${PUBLIC_BASE_URL.replace(/\/$/, '')}/auth/start`;

    const tools = [
      {
        name: 'get_user_email',
        description: `CRITICAL: Call this FIRST to get the user's email address. Ask the user "What is your email address?" and use their response. This email is required for ALL other tools.`,
        inputSchema: {
          type: 'object',
          properties: {
            user_provided_email: { 
              type: 'string', 
              description: 'The email address the user told you when you asked "What is your email?"' 
            }
          },
          required: ['user_provided_email']
        }
      },
      {
        name: 'check_google_auth',
        description: `Check if a user's email is authenticated. Returns auth status and auth_url if needed. Call this SECOND (after get_user_email) before using other tools.`,
        inputSchema: {
          type: 'object',
          properties: {
            email: { type: 'string', description: 'User email address from get_user_email' }
          },
          required: ['email']
        }
      },
      {
        name: 'connect_google',
        description: `Get authorization URL for an email address: ${connectUrl}`,
        inputSchema: {
          type: 'object',
          properties: {
            email: { type: 'string', description: 'Email address to authenticate' }
          },
          required: ['email']
        }
      },
      {
        name: 'list_drive_files',
        description: 'List files from Google Drive (requires authenticated email)',
        inputSchema: {
          type: 'object',
          properties: {
            email: { type: 'string', description: 'Authenticated email address' },
            max_results: { type: 'number', description: 'Max files (default: 20, max: 100)' }
          },
          required: ['email']
        }
      },
      {
        name: 'gdrive_search',
        description: 'Search Google Drive files',
        inputSchema: {
          type: 'object',
          properties: {
            email: { type: 'string' },
            query: { type: 'string' }
          },
          required: ['email', 'query']
        }
      },
      {
        name: 'gdrive_read_file',
        description: 'Read file by ID',
        inputSchema: {
          type: 'object',
          properties: {
            email: { type: 'string' },
            file_id: { type: 'string' }
          },
          required: ['email', 'file_id']
        }
      },
      {
        name: 'create_google_doc',
        description: 'Create a NEW Google Docs document',
        inputSchema: {
          type: 'object',
          properties: {
            email: { type: 'string' },
            file_name: { type: 'string' },
            content: { type: 'string' }
          },
          required: ['email', 'file_name', 'content']
        }
      },
      {
        name: 'gdrive_update_doc_by_name',
        description: 'Update existing Google Doc by name',
        inputSchema: {
          type: 'object',
          properties: {
            email: { type: 'string' },
            file_name: { type: 'string' },
            new_content: { type: 'string' }
          },
          required: ['email', 'file_name', 'new_content']
        }
      },
      // Gmail tools
      {
        name: 'list_emails',
        description: 'List emails from Gmail',
        inputSchema: {
          type: 'object',
          properties: {
            email: { type: 'string' },
            max_results: { type: 'number' },
            query: { type: 'string' }
          },
          required: ['email']
        }
      },
      {
        name: 'read_email',
        description: 'Read specific email by ID',
        inputSchema: {
          type: 'object',
          properties: {
            email: { type: 'string' },
            email_id: { type: 'string' }
          },
          required: ['email', 'email_id']
        }
      },
      {
        name: 'send_email',
        description: 'Send email via Gmail',
        inputSchema: {
          type: 'object',
          properties: {
            email: { type: 'string' },
            to: { type: 'string' },
            subject: { type: 'string' },
            body: { type: 'string' },
            cc: { type: 'string' },
            bcc: { type: 'string' }
          },
          required: ['email', 'to', 'subject', 'body']
        }
      },
      // Calendar tools
      {
        name: 'list_calendar_events',
        description: 'List calendar events',
        inputSchema: {
          type: 'object',
          properties: {
            email: { type: 'string' },
            max_results: { type: 'number' },
            time_min: { type: 'string' },
            time_max: { type: 'string' }
          },
          required: ['email']
        }
      },
      {
        name: 'create_calendar_event',
        description: 'Create calendar event',
        inputSchema: {
          type: 'object',
          properties: {
            email: { type: 'string' },
            summary: { type: 'string' },
            start_time: { type: 'string' },
            end_time: { type: 'string' },
            description: { type: 'string' },
            location: { type: 'string' }
          },
          required: ['email', 'summary', 'start_time', 'end_time']
        }
      },
      // Tasks tools
      {
        name: 'list_task_lists',
        description: 'List Google Task lists',
        inputSchema: {
          type: 'object',
          properties: {
            email: { type: 'string' }
          },
          required: ['email']
        }
      },
      {
        name: 'list_tasks',
        description: 'List tasks in a list',
        inputSchema: {
          type: 'object',
          properties: {
            email: { type: 'string' },
            task_list_id: { type: 'string', description: 'Task list ID from list_task_lists, or "@default" for your default task list' },
            show_completed: { type: 'boolean' },
            max_results: { type: 'number' }
          },
          required: ['email']
        }
      },
      {
        name: 'create_task',
        description: 'Create a new task',
        inputSchema: {
          type: 'object',
          properties: {
            email: { type: 'string' },
            title: { type: 'string' },
            notes: { type: 'string' },
            due: { type: 'string' },
            task_list_id: { type: 'string' }
          },
          required: ['email', 'title']
        }
      },
      {
        name: 'complete_task',
        description: 'Mark task as completed',
        inputSchema: {
          type: 'object',
          properties: {
            email: { type: 'string' },
            task_id: { type: 'string' },
            task_list_id: { type: 'string' }
          },
          required: ['email', 'task_id']
        }
      }
    ];

    return { tools };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    try {
      console.log(`[TOOL CALL] ${request.params.name}`, JSON.stringify(request.params.arguments || {}));

      const email = request.params.arguments?.email;

      // NEW: get_user_email tool - validates and returns the email
      if (request.params.name === 'get_user_email') {
        const userEmail = request.params.arguments?.user_provided_email;
        
        if (!userEmail) {
          return {
            content: [{
              type: 'text',
              text: '❌ Please ask the user: "What is your email address?" and try again with their response.'
            }],
            // Validation failure should not surface as a hard tool error;
            // keep the call successful so the model can read this message.
            isError: false
          };
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(userEmail)) {
          return {
            content: [{
              type: 'text',
              text: `❌ "${userEmail}" is not a valid email address. Please ask the user for a valid email.`
            }],
            // Also treat invalid email as a soft error so the client
            // doesn't show a generic external-data failure.
            isError: false
          };
        }

        const emailLower = userEmail.toLowerCase().trim();
        
        return {
          content: [
            {
              type: 'text',
              text: `✅ Got user email: ${emailLower}. Now call check_google_auth with this email to verify authentication.`
            },
            {
              type: 'text',
              text: `DATA:\n${JSON.stringify({
                success: true,
                email: emailLower,
                message: `✅ Got user email: ${emailLower}. Now use this email in all other tool calls.`,
                next_step: `Call check_google_auth with email="${emailLower}" to verify authentication`
              }, null, 2)}`
            }
          ],
          isError: false
        };
      }

      // check_google_auth tool
      if (request.params.name === 'check_google_auth') {
        if (!email) {
          return {
            content: [{
              type: 'text',
              text: '❌ Email parameter is required'
            }],
            isError: false
          };
        }

        const user = getUserByEmail(email);
        
        if (!user) {
          const authUrl = `${PUBLIC_BASE_URL}/auth/start?email=${encodeURIComponent(email)}`;
          return {
            content: [{
              type: 'text',
              text: `DATA:\n${JSON.stringify({
                authenticated: false,
                email: email,
                message: 'User not found. Please complete Google OAuth.',
                auth_url: authUrl,
                next_step: 'Visit auth_url to grant Google permissions'
              }, null, 2)}`
            }],
            isError: false
          };
        }

        const tokens = loadTokensForEmail(email);
        if (!tokens) {
          const authUrl = `${PUBLIC_BASE_URL}/auth/start?email=${encodeURIComponent(email)}`;
          return {
            content: [{
              type: 'text',
              text: `DATA:\n${JSON.stringify({
                authenticated: false,
                email: email,
                user_id: user.user_id,
                message: 'User exists but not authenticated. Please complete OAuth.',
                auth_url: authUrl
              }, null, 2)}`
            }],
            isError: false
          };
        }

        return {
          content: [{
            type: 'text',
            text: `DATA:\n${JSON.stringify({
              authenticated: true,
              email: email,
              user_id: user.user_id,
              display_name: user.display_name,
              message: 'User is authenticated. You can now use Google tools.'
            }, null, 2)}`
          }],
          isError: false
        };
      }

      // connect_google tool
      if (request.params.name === 'connect_google') {
        if (!email) {
          return {
            content: [{
              type: 'text',
              text: '❌ Email parameter is required'
            }],
            isError: false
          };
        }

        const authUrl = `${PUBLIC_BASE_URL}/auth/start?email=${encodeURIComponent(email)}`;
        return {
          content: [{
            type: 'text',
            text: `Authorize Google account for ${email}:\n${authUrl}`
          }],
          isError: false
        };
      }

      // All other tools require authenticated email
      if (!email) {
        return {
          content: [{
            type: 'text',
            text: '❌ Email parameter is required for this tool'
          }],
          isError: false
        };
      }

      const user = await verifyEmail(email);
      if (!user) {
        const authUrl = `${PUBLIC_BASE_URL}/auth/start?email=${encodeURIComponent(email)}`;
        return {
          content: [{
            type: 'text',
            text: `❌ Email ${email} is not authenticated. Please visit:\n${authUrl}`
          }],
          isError: false
        };
      }

      // Get credentials
      const oauth2 = await getCredentialsForEmail(email);

      // Create API clients
      const drive = google.drive({ version: 'v3', auth: oauth2 });
      const gmail = google.gmail({ version: 'v1', auth: oauth2 });
      const calendar = google.calendar({ version: 'v3', auth: oauth2 });
      const docs = google.docs({ version: 'v1', auth: oauth2 });
      const tasks = google.tasks({ version: 'v1', auth: oauth2 });

      // === DRIVE TOOLS ===
      if (request.params.name === 'list_drive_files') {
        const maxResults = Math.min(Math.max(1, parseInt(request.params.arguments?.max_results) || 20), 100);
        
        try {
          const res = await callWithAutoRefresh(
            () => drive.files.list({
              pageSize: maxResults,
              fields: 'files(id,name,mimeType,modifiedTime,size)',
              orderBy: 'modifiedTime desc'
            }),
            oauth2,
            email
          );

          const files = Array.isArray(res?.data?.files) ? res.data.files : [];
          
          return {
            content: [{
              type: 'text',
              text: JSON.stringify({ success: true, count: files.length, files }, null, 2)
            }],
            isError: false
          };
        } catch (err) {
          return handleToolError(err, 'list_drive_files', email);
        }
      }

      if (request.params.name === 'gdrive_search') {
        const qRaw = (request.params.arguments?.query || '').trim();
        
        try {
          const q = qRaw.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
          const formatted = `name contains '${q}' and trashed = false`;
          
          const res = await callWithAutoRefresh(
            () => drive.files.list({
              q: formatted,
              pageSize: 10,
              fields: 'files(id,name,mimeType,modifiedTime,size)',
              orderBy: 'modifiedTime desc'
            }),
            oauth2,
            email
          );

          const files = Array.isArray(res?.data?.files) ? res.data.files : [];
          
          if (files.length === 0) {
            return {
              content: [{ type: 'text', text: `Found 0 files matching "${qRaw}"` }],
              isError: false
            };
          }

          const list = files.map(f =>
            `${f.name} (${f.mimeType}) | ID: ${f.id}`
          ).join('\n');
          
          return {
            content: [{ type: 'text', text: `Found ${files.length} files:\n${list}` }],
            isError: false
          };
        } catch (err) {
          return handleToolError(err, 'gdrive_search', email);
        }
      }

      if (request.params.name === 'gdrive_read_file') {
        const fileId = request.params.arguments?.file_id;
        if (!fileId) throw new Error('file_id required');

        try {
          const meta = await callWithAutoRefresh(
            () => drive.files.get({ fileId, fields: 'mimeType' }),
            oauth2,
            email
          );
          
          const mime = meta.data.mimeType || 'application/octet-stream';

          if (mime.startsWith('application/vnd.google-apps')) {
            let exportMimeType = 'text/plain';
            switch (mime) {
              case 'application/vnd.google-apps.document':
                exportMimeType = 'text/markdown';
                break;
              case 'application/vnd.google-apps.spreadsheet':
                exportMimeType = 'text/csv';
                break;
            }
            
            const r = await callWithAutoRefresh(
              () => drive.files.export({ fileId, mimeType: exportMimeType }, { responseType: 'text' }),
              oauth2,
              email
            );
            
            return {
              content: [{ type: 'text', text: r.data }],
              isError: false
            };
          }

          const r = await callWithAutoRefresh(
            () => drive.files.get({ fileId, alt: 'media' }, { responseType: 'arraybuffer' }),
            oauth2,
            email
          );
          
          if (mime.startsWith('text/') || mime === 'application/json') {
            return {
              content: [{ type: 'text', text: Buffer.from(r.data).toString('utf8') }],
              isError: false
            };
          }
          
          return {
            content: [{ type: 'text', text: Buffer.from(r.data).toString('base64') }],
            isError: false
          };
        } catch (err) {
          return handleToolError(err, 'gdrive_read_file', email);
        }
      }

      if (request.params.name === 'create_google_doc') {
        const fileName = (request.params.arguments?.file_name || '').trim();
        const contentText = request.params.arguments?.content || '';
        if (!fileName) throw new Error('file_name required');

        try {
          const meta = { name: fileName, mimeType: 'application/vnd.google-apps.document' };
          const created = await callWithAutoRefresh(
            () => drive.files.create({ requestBody: meta, fields: 'id,name,webViewLink' }),
            oauth2,
            email
          );
          
          const fileId = created?.data?.id;

          if (contentText) {
            const requestsPayload = [{ insertText: { location: { index: 1 }, text: contentText } }];
            await callWithAutoRefresh(
              () => docs.documents.batchUpdate({
                documentId: fileId,
                requestBody: { requests: requestsPayload }
              }),
              oauth2,
              email
            );
          }

          return {
            content: [{
              type: 'text',
              text: `✅ Created Google Doc "${fileName}" (ID: ${fileId})\nView: ${created?.data?.webViewLink || 'N/A'}`
            }],
            isError: false
          };
        } catch (err) {
          return handleToolError(err, 'create_google_doc', email);
        }
      }

      if (request.params.name === 'gdrive_update_doc_by_name') {
        const fileName = (request.params.arguments?.file_name || '').trim();
        const newContent = request.params.arguments?.new_content;
        if (!fileName || typeof newContent !== 'string') {
          throw new Error('file_name and new_content required');
        }

        try {
          const safe = fileName.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
          const q = `name contains '${safe}' and mimeType='application/vnd.google-apps.document' and trashed = false`;
          
          const res = await callWithAutoRefresh(
            () => drive.files.list({ q, pageSize: 10, fields: 'files(id,name)' }),
            oauth2,
            email
          );
          
          const files = Array.isArray(res?.data?.files) ? res.data.files : [];
          if (!files.length) {
            return {
              content: [{
                type: 'text',
                text: `❌ No Google Doc named "${fileName}" found. Use create_google_doc to create new documents.`
              }],
              // Treat as a soft error so MCP clients can surface the
              // explanation instead of a generic external-data failure.
              isError: false
            };
          }

          const file = files[0];
          const docResp = await callWithAutoRefresh(
            () => docs.documents.get({ documentId: file.id }),
            oauth2,
            email
          );
          
          const docData = docResp.data || docResp;
          const contentArr = docData?.body?.content || [];
          const last = contentArr.length ? contentArr[contentArr.length - 1] : null;
          const endIndex = last && typeof last.endIndex === 'number' ? last.endIndex : 1;

          const requestsPayload = [];
          if (endIndex > 1) {
            requestsPayload.push({
              deleteContentRange: { range: { startIndex: 1, endIndex: endIndex - 1 } }
            });
          }
          requestsPayload.push({
            insertText: { location: { index: 1 }, text: newContent }
          });

          await callWithAutoRefresh(
            () => docs.documents.batchUpdate({
              documentId: file.id,
              requestBody: { requests: requestsPayload }
            }),
            oauth2,
            email
          );

          return {
            content: [{
              type: 'text',
              text: `✅ Updated document "${file.name}"`
            }],
            isError: false
          };
        } catch (err) {
          return handleToolError(err, 'gdrive_update_doc_by_name', email);
        }
      }

      // === GMAIL TOOLS ===
      if (request.params.name === 'list_emails') {
        try {
          const maxResults = Math.min(Math.max(1, parseInt(request.params.arguments?.max_results) || 20), 100);
          const q = request.params.arguments?.query || undefined;
          
          const res = await callWithAutoRefresh(
            () => gmail.users.messages.list({ userId: 'me', maxResults, q }),
            oauth2,
            email
          );
          
          const msgs = Array.isArray(res?.data?.messages) ? res.data.messages : [];
          const emailList = await fetchGmailMessages(gmail, oauth2, email, msgs);

          if (emailList.length === 0) {
            return {
              content: [{ type: 'text', text: 'No emails found.' }],
              isError: false
            };
          }

          let summary = `Found ${emailList.length} email${emailList.length > 1 ? 's' : ''}:\n\n`;
          emailList.forEach((em, idx) => {
            summary += `Email ${idx + 1}:\n`;
            summary += `From: ${em.from}\n`;
            summary += `Subject: ${em.subject || '(No subject)'}\n`;
            summary += `Date: ${em.date}\n`;
            summary += `Preview: ${em.snippet || ''}\n`;
            summary += `📧 Gmail ID: ${em.id}\n\n`;
          });

          return {
            content: [{ type: 'text', text: summary }],
            isError: false
          };
        } catch (err) {
          return handleToolError(err, 'list_emails', email);
        }
      }

      if (request.params.name === 'read_email') {
        const emailId = request.params.arguments?.email_id;
        if (!emailId) throw new Error('email_id required');

        try {
          const msg = await callWithAutoRefresh(
            () => gmail.users.messages.get({ userId: 'me', id: emailId, format: 'full' }),
            oauth2,
            email
          );
          
          const headersArr = (msg.data.payload && msg.data.payload.headers) || [];
          const headers = {};
          for (const h of headersArr) headers[h.name] = h.value;

          const body = extractEmailBody(msg.data.payload) || '';

          return {
            content: [{
              type: 'text',
              text: `DATA:\n${JSON.stringify({
                success: true,
                id: msg.data.id,
                from: headers.From || '',
                to: headers.To || '',
                subject: headers.Subject || '',
                date: headers.Date || '',
                body: body
              }, null, 2)}`
            }],
            isError: false
          };
        } catch (err) {
          return handleToolError(err, 'read_email', email);
        }
      }

      if (request.params.name === 'send_email') {
        const to = request.params.arguments?.to;
        const subject = request.params.arguments?.subject || '';
        const body = request.params.arguments?.body || '';
        if (!to || !subject || !body) throw new Error('to, subject, and body required');

        try {
          let rawLines = [];
          rawLines.push(`To: ${to}`);
          if (request.params.arguments?.cc) rawLines.push(`Cc: ${request.params.arguments.cc}`);
          if (request.params.arguments?.bcc) rawLines.push(`Bcc: ${request.params.arguments.bcc}`);
          rawLines.push(`Subject: ${subject}`);
          rawLines.push('Content-Type: text/plain; charset="UTF-8"');
          rawLines.push('');
          rawLines.push(body);
          
          const raw = Buffer.from(rawLines.join('\n'))
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');

          const sent = await callWithAutoRefresh(
            () => gmail.users.messages.send({ userId: 'me', requestBody: { raw } }),
            oauth2,
            email
          );

          return {
            content: [{
              type: 'text',
              text: `✅ Email sent successfully (ID: ${sent.data.id})`
            }],
            isError: false
          };
        } catch (err) {
          return handleToolError(err, 'send_email', email);
        }
      }

      // === CALENDAR TOOLS ===
      if (request.params.name === 'list_calendar_events') {
        try {
          const maxResults = Math.min(Math.max(1, parseInt(request.params.arguments?.max_results) || 10), 250);
          const calendarId = 'primary';

          let timeMin = request.params.arguments?.time_min;
          let timeMax = request.params.arguments?.time_max;
          
          if (!timeMin || !timeMax) {
            const today = new Date();
            const start = new Date(today);
            start.setHours(0, 0, 0, 0);
            const end = new Date(start.getTime() + 24 * 60 * 60 * 1000);
            if (!timeMin) timeMin = start.toISOString();
            if (!timeMax) timeMax = end.toISOString();
          }

          const res = await callWithAutoRefresh(
            () => calendar.events.list({
              calendarId,
              maxResults,
              singleEvents: true,
              orderBy: 'startTime',
              timeMin,
              timeMax
            }),
            oauth2,
            email
          );

          const events = Array.isArray(res?.data?.items) ? res.data.items : [];

          if (events.length === 0) {
            return {
              content: [{ type: 'text', text: 'No events found.' }],
              isError: false
            };
          }

          let summary = `Found ${events.length} event${events.length > 1 ? 's' : ''}:\n\n`;
          events.forEach((event, idx) => {
            const start = event.start?.dateTime || event.start?.date || '';
            summary += `Event ${idx + 1}:\n`;
            summary += `Title: ${event.summary || '(No title)'}\n`;
            summary += `When: ${start}\n`;
            if (event.location) summary += `Location: ${event.location}\n`;
            summary += `Event ID: ${event.id}\n\n`;
          });

          return {
            content: [{ type: 'text', text: summary }],
            isError: false
          };
        } catch (err) {
          return handleToolError(err, 'list_calendar_events', email);
        }
      }

      if (request.params.name === 'create_calendar_event') {
        const summary = request.params.arguments?.summary || '';
        const start_time = request.params.arguments?.start_time || '';
        const end_time = request.params.arguments?.end_time || '';
        if (!summary || !start_time || !end_time) {
          throw new Error('summary, start_time, and end_time required');
        }

        try {
          const isAllDay = !/T/.test(start_time);
          const event = {
            summary,
            description: request.params.arguments?.description || '',
            location: request.params.arguments?.location || '',
            start: isAllDay ? { date: start_time } : { dateTime: start_time },
            end: isAllDay ? { date: end_time } : { dateTime: end_time }
          };

          const res = await callWithAutoRefresh(
            () => calendar.events.insert({ calendarId: 'primary', requestBody: event }),
            oauth2,
            email
          );

          return {
            content: [{
              type: 'text',
              text: `✅ Created event: "${summary}"\n📅 ${start_time} to ${end_time}\n🔗 ${res.data.htmlLink || 'N/A'}`
            }],
            isError: false
          };
        } catch (err) {
          return handleToolError(err, 'create_calendar_event', email);
        }
      }

      // === TASKS TOOLS ===
      if (request.params.name === 'list_task_lists') {
        try {
          const res = await callWithAutoRefresh(
            () => tasks.tasklists.list({ maxResults: 100 }),
            oauth2,
            email
          );
          
          const lists = Array.isArray(res?.data?.items) ? res.data.items : [];

          if (!lists.length) {
            return {
              content: [{ type: 'text', text: 'No task lists found.' }],
              isError: false
            };
          }

          let summary = `📋 Your Google Task Lists:\n\n`;
          lists.forEach((list, idx) => {
            summary += `${idx + 1}. ${list.title}\n`;
            summary += `   🆔 Task List ID: ${list.id}\n`;
          });
          summary += `\nTip: Use "@default" for your default task list.\n`;

          return {
            content: [{ type: 'text', text: summary }],
            isError: false
          };
        } catch (err) {
          return handleToolError(err, 'list_task_lists', email);
        }
      }

      if (request.params.name === 'list_tasks') {
        try {
          let taskListId = request.params.arguments?.task_list_id || '@default';
          const showCompleted = !!request.params.arguments?.show_completed;
          const maxResults = Math.min(Math.max(1, parseInt(request.params.arguments?.max_results) || 100), 1000);

          // Allow either a task list ID or a human-friendly title
          if (taskListId !== '@default' && !/^[A-Za-z0-9_-]{10,}$/.test(taskListId)) {
            const listsRes = await callWithAutoRefresh(
              () => tasks.tasklists.list({ maxResults: 100 }),
              oauth2,
              email
            );

            const lists = Array.isArray(listsRes?.data?.items) ? listsRes.data.items : [];
            const match = lists.find(l => (l.title || '').toLowerCase().trim() === String(taskListId).toLowerCase().trim());

            if (!match) {
              return {
                content: [{
                  type: 'text',
                  text: `Unknown task list "${taskListId}". Run list_task_lists to see valid task list IDs (or use "@default").`
                }],
                isError: false
              };
            }

            taskListId = match.id;
          }

          const res = await callWithAutoRefresh(
            () => tasks.tasks.list({ tasklist: taskListId, showCompleted, maxResults }),
            oauth2,
            email
          );

          const items = Array.isArray(res?.data?.items) ? res.data.items : [];

          if (!items.length) {
            return {
              content: [{ type: 'text', text: 'No tasks found.' }],
              isError: false
            };
          }

          let summary = `📝 Your Tasks (${items.length} total):\n\n`;
          items.forEach((task, idx) => {
            const checkbox = task.status === 'completed' ? '✅' : '⬜';
            summary += `Task ${idx + 1}: ${checkbox} ${task.title}\n`;
            summary += `   🆔 Task ID: ${task.id}\n`;
            if (task.notes) summary += `   📄 ${task.notes}\n`;
            if (task.due) summary += `   📅 Due: ${new Date(task.due).toLocaleDateString()}\n`;
            summary += '\n';
          });

          return {
            content: [{ type: 'text', text: summary }],
            isError: false
          };
        } catch (err) {
          return handleToolError(err, 'list_tasks', email);
        }
      }

      if (request.params.name === 'create_task') {
        const title = (request.params.arguments?.title || '').trim();
        if (!title) throw new Error('title required');

        try {
          const taskListId = request.params.arguments?.task_list_id || '@default';
          const body = { title };

          if (request.params.arguments?.notes) {
            body.notes = request.params.arguments.notes;
          }
          
          if (request.params.arguments?.due) {
            const dueInput = request.params.arguments.due;
            let dueDate;
            if (/^\d{4}-\d{2}-\d{2}$/.test(dueInput)) {
              dueDate = new Date(dueInput + 'T00:00:00Z');
            } else {
              dueDate = new Date(dueInput);
            }
            if (!isNaN(dueDate.getTime())) {
              body.due = dueDate.toISOString();
            }
          }

          const created = await callWithAutoRefresh(
            () => tasks.tasks.insert({ tasklist: taskListId, requestBody: body }),
            oauth2,
            email
          );

          return {
            content: [{
              type: 'text',
              text: `✅ Task created: "${created.data.title}"`
            }],
            isError: false
          };
        } catch (err) {
          return handleToolError(err, 'create_task', email);
        }
      }

      if (request.params.name === 'complete_task') {
        const taskId = request.params.arguments?.task_id;
        if (!taskId) throw new Error('task_id required');

        try {
          const taskListId = request.params.arguments?.task_list_id || '@default';
          const patch = {
            id: taskId,
            status: 'completed',
            completed: new Date().toISOString()
          };

          const updated = await callWithAutoRefresh(
            () => tasks.tasks.update({ tasklist: taskListId, task: taskId, requestBody: patch }),
            oauth2,
            email
          );

          return {
            content: [{
              type: 'text',
              text: `✅ Task completed: "${updated.data.title}"`
            }],
            isError: false
          };
        } catch (err) {
          return handleToolError(err, 'complete_task', email);
        }
      }

      throw new Error(`Tool not found: ${request.params.name}`);
    } catch (err) {
      console.error('[TOOL ERROR]', err);
      return {
        content: [{
          type: 'text',
          text: `❌ Error: ${err.message || String(err)}`
        }],
        // Keep isError=false so the MCP client surfaces this message
        // instead of a generic external-data failure.
        isError: false
      };
    }
  });

  return server;
}

// ============================================================================
// HTTP ROUTES
// ============================================================================

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    service: 'Email-Based Google Workspace MCP Server',
    version: '0.2.0',
    authentication: 'Email-based (no session dependency)',
    endpoints: {
      '/': 'API documentation',
      '/auth/start': 'HTML page to start OAuth (requires ?email=...)',
      '/auth?email=...': 'Start OAuth flow for email',
      '/auth/callback': 'OAuth callback handler',
      '/check-auth?email=...': 'Check if email is authenticated',
      '/whoami?email=...': 'Get user info for email',
      '/health': 'Health check',
      '/mcp': 'MCP protocol endpoint (POST)'
    },
    usage: {
      step_1: 'Call check_google_auth tool with user email',
      step_2a: 'If authenticated=true, use tools with email parameter',
      step_2b: 'If authenticated=false, user visits auth_url',
      step_3: 'After OAuth, all tools work with that email',
      note: 'Multiple sessions can use the same authenticated email'
    },
    authenticated_emails: listAuthenticatedEmails()
  });
});

// Start auth HTML page
app.get('/auth/start', (req, res) => {
  const email = req.query.email || '';
  
  const html = `
<!DOCTYPE html>
<html>
<head>
  <title>Google OAuth - Email Authentication</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
    input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; font-size: 16px; }
    button { background-color: #4285f4; color: white; padding: 12px 24px; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; width: 100%; }
    button:hover { background-color: #357ae8; }
    .info { background-color: #f0f0f0; padding: 15px; border-radius: 4px; margin-top: 20px; }
  </style>
</head>
<body>
  <h1>Google OAuth Authentication</h1>
  <p>Enter your email address to authenticate:</p>
  
  <input type="email" id="emailInput" placeholder="your.email@example.com" value="${email}" />
  <button onclick="startAuth()">Authenticate with Google</button>
  
  <div class="info">
    <h3>How it works:</h3>
    <ol>
      <li>Enter your email address</li>
      <li>Click "Authenticate with Google"</li>
      <li>Sign in with Google and grant permissions</li>
      <li>You'll be redirected back - authentication complete!</li>
      <li>Use your email in MCP tools to access Google services</li>
    </ol>
  </div>
  
  <script>
    async function startAuth() {
      const email = document.getElementById('emailInput').value.trim();
      if (!email || !email.includes('@')) {
        alert('Please enter a valid email address');
        return;
      }
      window.location.href = '/auth?email=' + encodeURIComponent(email);
    }
    
    document.getElementById('emailInput').addEventListener('keypress', function(e) {
      if (e.key === 'Enter') startAuth();
    });
  </script>
</body>
</html>
  `;
  
  res.send(html);
});

// Start OAuth flow
app.get('/auth', (req, res) => {
  const email = req.query.email;
  
  if (!email) {
    return res.status(400).send('Missing email parameter. Use: /auth?email=user@example.com');
  }
  
  const emailLower = email.toLowerCase().trim();
  
  if (!OAUTH_CLIENT_ID || !OAUTH_CLIENT_SECRET) {
    return res.status(500).send('OAuth client not configured');
  }
  
  const oauth2 = new google.auth.OAuth2(
    OAUTH_CLIENT_ID,
    OAUTH_CLIENT_SECRET,
    OAUTH_REDIRECT_URI
  );
  
  const authUrl = oauth2.generateAuthUrl({
    access_type: 'offline',
    scope: SCOPES,
    state: emailLower,
    prompt: 'consent'
  });
  
  console.log('Starting OAuth for email:', emailLower);
  res.redirect(authUrl);
});

// OAuth callback
app.get('/auth/callback', async (req, res) => {
  const code = req.query.code;
  const state = req.query.state; // This contains the email
  
  if (!code || !state) {
    return res.status(400).send('Missing code or state in callback');
  }
  
  const email = state.toLowerCase().trim();
  
  try {
    const oauth2 = new google.auth.OAuth2(
      OAUTH_CLIENT_ID,
      OAUTH_CLIENT_SECRET,
      OAUTH_REDIRECT_URI
    );
    
    const { tokens } = await oauth2.getToken(code);
    oauth2.setCredentials(tokens);
    
    // Get user info from Google
    const oauth2Client = google.oauth2({ auth: oauth2, version: 'v2' });
    const userInfo = await oauth2Client.userinfo.get();
    
    const googleEmail = userInfo.data.email;
    const displayName = userInfo.data.name || email;
    
    // Verify email matches
    if (googleEmail.toLowerCase() !== email) {
      return res.status(400).send(`Email mismatch: expected ${email}, got ${googleEmail}`);
    }
    
    // Create or update user
    getOrCreateUser(email, displayName);
    
    // Store tokens
    storeTokensForEmail(email, tokens);
    updateLastLogin(email);
    
    console.log('✅ OAuth complete for:', email);
    
    res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Authentication Complete</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
    h1 { color: #4285f4; }
    .success { background-color: #d4edda; border: 1px solid #c3e6cb; padding: 20px; border-radius: 4px; margin: 20px 0; }
  </style>
</head>
<body>
  <h1>✅ Authentication Complete!</h1>
  <div class="success">
    <p><strong>Email:</strong> ${email}</p>
    <p><strong>Display Name:</strong> ${displayName}</p>
  </div>
  <p>You can now use your email (${email}) with MCP tools to access Google services.</p>
  <p>You can close this window and return to FlyerGPT.</p>
</body>
</html>
    `);
  } catch (err) {
    console.error('OAuth callback error:', err);
    res.status(500).send(`Authentication failed: ${err.message}`);
  }
});

// Check auth status
app.get('/check-auth', async (req, res) => {
  const email = req.query.email;
  
  if (!email) {
    return res.status(400).json({ error: 'Email parameter required' });
  }
  
  const user = getUserByEmail(email);
  
  if (!user) {
    return res.json({
      authenticated: false,
      email: email,
      message: 'User not found'
    });
  }
  
  const tokens = loadTokensForEmail(email);
  
  if (!tokens) {
    return res.json({
      authenticated: false,
      email: email,
      user_id: user.user_id,
      message: 'User exists but not authenticated'
    });
  }
  
  res.json({
    authenticated: true,
    email: email,
    user_id: user.user_id,
    display_name: user.display_name,
    is_active: user.is_active
  });
});

// Whoami endpoint
app.get('/whoami', checkAuth, async (req, res) => {
  const email = req.query.email;
  
  if (!email) {
    return res.status(400).json({ error: 'Email parameter required' });
  }
  
  const user = getUserByEmail(email);
  
  if (!user) {
    return res.json({
      ok: false,
      bound: false,
      message: 'User not found'
    });
  }
  
  const tokens = loadTokensForEmail(email);
  
  if (!tokens) {
    return res.json({
      ok: false,
      bound: false,
      message: 'Not authenticated'
    });
  }
  
  res.json({
    ok: true,
    bound: true,
    email: email,
    display_name: user.display_name
  });
});

// Health check
app.get('/health', (req, res) => {
  const authenticated = listAuthenticatedEmails();
  
  res.json({
    ok: true,
    mode: 'email-based',
    authenticated_emails_count: authenticated.length,
    oauth_configured: !!(OAUTH_CLIENT_ID && OAUTH_CLIENT_SECRET)
  });
});

// MCP endpoint
const transports = {};

// IMPORTANT: MCP endpoints do NOT use checkAuth - FlyerGPT doesn't send bearer tokens
// Security is handled by email verification in each tool call

app.post('/mcp', async (req, res) => {
  try {
    console.log('[MCP POST] Received request');
    const sessionHeader = req.headers['mcp-session-id'] || req.headers['Mcp-Session-Id'];
    let transport;

    if (sessionHeader && transports[sessionHeader]) {
      console.log('[MCP POST] Reusing existing transport for session:', sessionHeader);
      transport = transports[sessionHeader];
    } else if (isInitializeRequest(req.body)) {
      const sess = sessionHeader || randomUUID();
      console.log('[MCP POST] Initializing new session:', sess);
      
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => sess,
        onsessioninitialized: (id) => {
          transports[id] = transport;
          console.log('[MCP] Session initialized:', id);
        }
      });

      const server = createMcpServer();
      await server.connect(transport);
      console.log('[MCP] Server connected to transport');
    } else {
      console.log('[MCP POST] Invalid request - not an initialize request and no session');
      return res.status(400).json({
        jsonrpc: '2.0',
        error: { code: -32000, message: 'Initialize with session first' },
        id: null
      });
    }

    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    console.error('[MCP POST] Error:', err);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: '2.0',
        error: { code: -32603, message: String(err) },
        id: null
      });
    }
  }
});

app.get('/mcp', async (req, res) => {
  try {
    const sessionId = req.headers['mcp-session-id'] || req.query.sessionId;
    console.log('[MCP GET] Session:', sessionId);
    
    if (!sessionId || !transports[sessionId]) {
      return res.status(400).json({ ok: false, error: 'Invalid or missing session ID' });
    }
    
    const transport = transports[sessionId];
    await transport.handleRequest(req, res);
  } catch (err) {
    console.error('[MCP GET] Error:', err);
    if (!res.headersSent) {
      res.status(500).send('Internal server error');
    }
  }
});

app.delete('/mcp', async (req, res) => {
  try {
    const sessionId = req.headers['mcp-session-id'];
    console.log('[MCP DELETE] Closing session:', sessionId);
    
    if (!sessionId || !transports[sessionId]) {
      return res.status(400).send('Invalid or missing session ID');
    }
    
    const t = transports[sessionId];
    if (t && typeof t.close === 'function') t.close();
    delete transports[sessionId];
    
    res.status(200).send('OK');
  } catch (err) {
    console.error('[MCP DELETE] Error:', err);
    res.status(500).send('Internal server error');
  }
});

// ============================================================================
// START SERVER
// ============================================================================

const httpServer = app.listen(PORT, () => {
  console.log(`\n${'='.repeat(60)}`);
  console.log('📧 Email-Based Google Workspace MCP Server');
  console.log(`${'='.repeat(60)}`);
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`🌐 Base URL: ${PUBLIC_BASE_URL}`);
  console.log(`🔑 Auth Mode: Email-based (no session dependency)`);
  console.log(`📁 Users directory: ${usersDir}`);
  console.log(`🔐 Tokens directory: ${tokensDir}`);
  
  const authenticated = listAuthenticatedEmails();
  if (authenticated.length > 0) {
    console.log(`\n✅ Authenticated emails (${authenticated.length}):`);
    authenticated.forEach(email => console.log(`   - ${email}`));
  } else {
    console.log(`\n⚠️  No authenticated emails yet`);
  }
  
  console.log(`\n📚 To authenticate a new email:`);
  console.log(`   1. Visit: ${PUBLIC_BASE_URL}/auth/start`);
  console.log(`   2. Enter email address`);
  console.log(`   3. Complete Google OAuth`);
  console.log(`   4. Use email in MCP tools\n`);
  console.log(`${'='.repeat(60)}\n`);
});

function gracefulShutdown() {
  console.log('\n🛑 Graceful shutdown initiated...');
  
  try {
    Object.keys(transports).forEach((id) => {
      try {
        if (transports[id] && typeof transports[id].close === 'function') {
          transports[id].close();
        }
        delete transports[id];
      } catch (e) {
        console.warn('Error closing transport', id, e.message);
      }
    });
    
    if (httpServer && typeof httpServer.close === 'function') {
      httpServer.close(() => {
        console.log('✅ HTTP server closed');
        process.exit(0);
      });
      
      setTimeout(() => {
        console.warn('⚠️  Forcing shutdown after timeout');
        process.exit(1);
      }, 5000);
    } else {
      process.exit(0);
    }
  } catch (e) {
    console.error('❌ Shutdown error:', e);
    process.exit(1);
  }
}

process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);
process.on('uncaughtException', (e) => {
  console.error('❌ Uncaught exception:', e);
});
process.on('unhandledRejection', (e) => {
  console.error('❌ Unhandled rejection:', e);
});