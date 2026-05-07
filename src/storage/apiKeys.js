const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { API_KEYS_DIR } = require('../config/config');
const { emailToFilename } = require('./users');
const { hashApiKey } = require('../helpers/encryption');
const { logAudit } = require('../helpers/audit');

/**
 * Get API key file path for email
 */
function getApiKeyFilePathForEmail(email) {
  const emailLower = String(email || '').toLowerCase().trim();
  return path.join(API_KEYS_DIR, `${emailToFilename(emailLower)}.json`);
}

/**
 * Create or rotate API key
 */
function createOrRotateApiKey(email) {
  const emailLower = String(email || '').toLowerCase().trim();
  const apiKey = crypto.randomBytes(32).toString('hex');
  const hash = hashApiKey(apiKey);
  const filePath = getApiKeyFilePathForEmail(emailLower);
  const now = new Date().toISOString();

  let record = { email: emailLower, keys: [] };
  try {
    if (fs.existsSync(filePath)) {
      const existing = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      if (existing && typeof existing === 'object') {
        record = {
          email: existing.email || emailLower,
          keys: Array.isArray(existing.keys) ? existing.keys : []
        };
      }
    }
  } catch (e) {
    console.warn('Failed to read existing API key record for', emailLower, e && e.message);
  }

  record.keys.forEach((k) => {
    if (k && typeof k === 'object') {
      k.revoked = true;
    }
  });

  record.keys.push({ hash, created_at: now, revoked: false });
  record.active_hash = hash;

  try {
    fs.writeFileSync(filePath, JSON.stringify(record, null, 2), {
      encoding: 'utf8',
      mode: 0o600
    });
    logAudit({ type: 'api_key_issued', email: emailLower });
  } catch (e) {
    console.error('Failed to write API key file for', emailLower, e && e.message);
  }

  return apiKey;
}

/**
 * Find email for API key
 */
function findEmailForApiKey(apiKey) {
  const hash = hashApiKey(apiKey);
  if (!fs.existsSync(API_KEYS_DIR)) return null;

  try {
    const files = fs.readdirSync(API_KEYS_DIR).filter((f) => f.endsWith('.json'));
    for (const file of files) {
      try {
        const fullPath = path.join(API_KEYS_DIR, file);
        const data = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
        if (!data || typeof data !== 'object') continue;
        const keys = Array.isArray(data.keys) ? data.keys : [];
        const match = keys.find((k) => k && k.hash === hash && !k.revoked);
        if (match) {
          return data.email || null;
        }
      } catch (e) {
        console.warn('Failed to inspect API key file', file, e && e.message);
      }
    }
  } catch (e) {
    console.warn('Failed to scan API keys directory:', e && e.message);
  }

  return null;
}

module.exports = {
  getApiKeyFilePathForEmail,
  createOrRotateApiKey,
  findEmailForApiKey
};
