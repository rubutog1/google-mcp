const { google } = require('googleapis');
const { OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_REDIRECT_URI, SCOPES, PUBLIC_BASE_URL } = require('../config/config');
const { getOrCreateUser, updateLastLogin } = require('../storage/users');
const { storeTokensForEmail } = require('../storage/tokens');
const { logAudit } = require('../helpers/audit');

/**
 * Generate OAuth authorization URL
 */
function generateAuthUrl(email) {
  const oauth2 = new google.auth.OAuth2(
    OAUTH_CLIENT_ID,
    OAUTH_CLIENT_SECRET,
    OAUTH_REDIRECT_URI
  );
  
  const authUrl = oauth2.generateAuthUrl({
    access_type: 'offline',
    scope: SCOPES,
    state: email.toLowerCase().trim(),
    prompt: 'consent'
  });
  
  return authUrl;
}

/**
 * Handle OAuth callback
 */
async function handleOAuthCallback(code, state) {
  const email = state.toLowerCase().trim();
  
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
    throw new Error(`Email mismatch: expected ${email}, got ${googleEmail}`);
  }
  
  // Create or update user
  getOrCreateUser(email, displayName);
  
  // Store tokens (encrypted if configured)
  await storeTokensForEmail(email, tokens);
  updateLastLogin(email);
  logAudit({ type: 'oauth_complete', email, display_name: displayName });
  
  console.log('✅ OAuth complete for:', email);
  
  return { email, displayName };
}

/**
 * Build auth required response
 */
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

module.exports = {
  generateAuthUrl,
  handleOAuthCallback,
  buildAuthRequired
};
