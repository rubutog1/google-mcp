const { google } = require('googleapis');
const { PUBLIC_BASE_URL, BEARER, OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_REDIRECT_URI, SCOPES } = require('../config/config');
const { getUserByEmail } = require('../storage/users');
const { loadTokensForEmail, storeTokensForEmail } = require('../storage/tokens');
const { generateAuthUrl, handleOAuthCallback } = require('../google/oauth');
const { logAudit } = require('../helpers/audit');
const { isValidEmail } = require('../helpers/validation');
const { getOrCreateUser, updateLastLogin } = require('../storage/users');

/**
 * Auth start page - HTML form for email input
 */
function authStartHandler(req, res) {
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
      <li>Configure the server API key in your MCP client's X-API-Key header</li>
      <li>Use your email in MCP tools to access your Google services</li>
    </ol>
    <p><strong>Note:</strong> All users share the same server API key. 
    The email parameter in MCP tools determines which account to access.</p>
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
}

/**
 * Start OAuth flow
 */
function authHandler(req, res) {
  const email = req.query.email;
  
  if (!email) {
    return res.status(400).send('Missing email parameter. Use: /auth?email=user@example.com');
  }
  
  const emailLower = email.toLowerCase().trim();
  
  if (!OAUTH_CLIENT_ID || !OAUTH_CLIENT_SECRET) {
    return res.status(500).send('OAuth client not configured');
  }
  
  const authUrl = generateAuthUrl(emailLower);
  console.log('Starting OAuth for email:', emailLower);
  res.redirect(authUrl);
}

/**
 * OAuth callback handler
 */
async function authCallbackHandler(req, res) {
  const code = req.query.code;
  const state = req.query.state; // This contains the email
  
  if (!code || !state) {
    return res.status(400).send('Missing code or state in callback');
  }
  
  const email = state.toLowerCase().trim();
  
  try {
    const { email: authenticatedEmail, displayName } = await handleOAuthCallback(code, state);
    
    res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>Authentication Complete</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
    h1 { color: #4285f4; }
    .success { background-color: #d4edda; border: 1px solid #c3e6cb; padding: 20px; border-radius: 4px; margin: 20px 0; }
    .api-key { background-color: #f8f9fa; padding: 15px; border-radius: 4px; font-family: monospace; word-break: break-all; }
  </style>
</head>
<body>
  <h1>✅ Authentication Complete!</h1>
  <div class="success">
    <p><strong>Email:</strong> ${email}</p>
    <p><strong>Display Name:</strong> ${displayName}</p>
  </div>
  <p>You can now use your email (<strong>${email}</strong>) with MCP tools to access Google services.</p>
  
  <h3>Server API Key (X-API-Key header):</h3>
  <div class="api-key">${BEARER || 'Not configured'}</div>
  
  <p style="margin-top: 20px; font-size: 14px; color: #666;">
    <strong>Note:</strong> This is the shared server API key that all users use. 
    In your MCP tools, specify your email address to access your account.
  </p>
  
  <p style="margin-top: 20px;">You can close this window and return to your application.</p>
</body>
</html>
    `);
  } catch (err) {
    console.error('OAuth callback error:', err);
    res.status(500).send(`Authentication failed: ${err.message}`);
  }
}

/**
 * Check auth status
 */
function checkAuthHandler(req, res) {
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
}

/**
 * Whoami endpoint
 */
function whoamiHandler(req, res) {
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
}

module.exports = {
  authStartHandler,
  authHandler,
  authCallbackHandler,
  checkAuthHandler,
  whoamiHandler
};
