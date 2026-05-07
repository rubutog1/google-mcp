const fs = require('fs');
const path = require('path');
const lockfile = require('proper-lockfile');
const { tokensDir, TOKEN_EXPIRY_MS } = require('../config/config');
const { encryptTokensIfConfigured, decryptTokensIfNeeded } = require('../helpers/encryption');
const { emailToFilename } = require('./users');

/**
 * Store tokens for a user (by email)
 */
async function storeTokensForEmail(email, tokens) {
  const emailLower = email.toLowerCase().trim();
  const tokenPath = path.join(tokensDir, `${emailToFilename(emailLower)}.json`);

  const wrapped = encryptTokensIfConfigured(tokens);
  const tokenData = {
    email: emailLower,
    encrypted: wrapped.encrypted,
    tokens: wrapped.tokens,
    updated_at: new Date().toISOString(),
    last_used: new Date().toISOString() // Track last usage for expiration
  };

  let release;
  try {
    try {
      release = await lockfile.lock(tokenPath, {
        stale: 5000,
        retries: { retries: 3, minTimeout: 100 }
      });
    } catch {
      // If lock acquisition fails, continue with best-effort write
    }

    fs.writeFileSync(tokenPath, JSON.stringify(tokenData, null, 2), {
      encoding: 'utf8',
      mode: 0o600
    });
    console.log('Stored tokens for email:', emailLower);
    return true;
  } catch (e) {
    console.error('Failed to store tokens for', emailLower, ':', e.message);
    return false;
  } finally {
    if (release) {
      try {
        await release();
      } catch {}
    }
  }
}

/**
 * Load tokens for a user (by email)
 * Checks for token expiration (8 hours of inactivity)
 */
function loadTokensForEmail(email) {
  const emailLower = email.toLowerCase().trim();
  const tokenPath = path.join(tokensDir, `${emailToFilename(emailLower)}.json`);
  
  if (!fs.existsSync(tokenPath)) {
    return null;
  }
  
  try {
    const data = JSON.parse(fs.readFileSync(tokenPath, 'utf8'));
    
    // Check token expiration
    if (data.last_used) {
      const lastUsed = new Date(data.last_used).getTime();
      const now = Date.now();
      
      if (now - lastUsed > TOKEN_EXPIRY_MS) {
        console.log(`Tokens expired for ${emailLower} (last used: ${data.last_used})`);
        // Delete expired token file
        try {
          fs.unlinkSync(tokenPath);
          console.log(`Deleted expired tokens for ${emailLower}`);
        } catch (e) {
          console.warn('Failed to delete expired tokens:', e.message);
        }
        return null;
      }
    }
    
    // Update last_used timestamp
    data.last_used = new Date().toISOString();
    try {
      fs.writeFileSync(tokenPath, JSON.stringify(data, null, 2), {
        encoding: 'utf8',
        mode: 0o600
      });
    } catch (e) {
      console.warn('Failed to update last_used timestamp:', e.message);
    }
    
    if (data.encrypted) {
      return decryptTokensIfNeeded(data);
    }
    return data.tokens;
  } catch (e) {
    console.warn('Failed to load tokens for', emailLower, ':', e.message);
    return null;
  }
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

module.exports = {
  storeTokensForEmail,
  loadTokensForEmail,
  listAuthenticatedEmails
};
