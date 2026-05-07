const { google } = require('googleapis');
const { OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_REDIRECT_URI } = require('../config/config');
const { loadTokensForEmail, storeTokensForEmail } = require('../storage/tokens');

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
  
  // Auto-refresh if expired or close to expiry
  const creds = oauth2.credentials || {};
  const now = Date.now();
  let needsRefresh = false;
  if (creds.expiry_date && creds.expiry_date < now) {
    needsRefresh = true;
  } else if (typeof creds.expires_in === 'number' && creds.expires_in <= 60) {
    needsRefresh = true;
  }

  if (needsRefresh) {
    console.log('Token expired or near expiry for', emailLower, 'attempting refresh...');
    try {
      const { credentials } = await oauth2.refreshAccessToken();
      oauth2.setCredentials(credentials);
      await storeTokensForEmail(emailLower, credentials);
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
        await storeTokensForEmail(email, credentials);
        return await actionFn();
      } catch (refreshErr) {
        console.warn('Token refresh failed for', email, refreshErr.message);
        throw new Error('Authentication expired - please re-authenticate');
      }
    }
    throw err;
  }
}

/**
 * Verify email has valid tokens
 */
async function verifyEmail(email) {
  if (!email || typeof email !== 'string') {
    return null;
  }
  
  const emailLower = email.toLowerCase().trim();
  const { getUserByEmail } = require('../storage/users');
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

module.exports = {
  getCredentialsForEmail,
  callWithAutoRefresh,
  verifyEmail
};
