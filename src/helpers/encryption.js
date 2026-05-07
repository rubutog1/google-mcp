const crypto = require('crypto');
const { TOKEN_ENCRYPTION_KEY } = require('../config/config');

/**
 * Get encryption key from environment
 */
function getEncryptionKey() {
  if (!TOKEN_ENCRYPTION_KEY) return null;
  try {
    return crypto.createHash('sha256').update(TOKEN_ENCRYPTION_KEY).digest();
  } catch {
    return null;
  }
}

/**
 * Encrypt tokens if configured
 */
function encryptTokensIfConfigured(tokens) {
  const key = getEncryptionKey();
  if (!key) return { encrypted: false, tokens };

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = JSON.stringify(tokens);
  let ciphertext = cipher.update(plaintext, 'utf8', 'base64');
  ciphertext += cipher.final('base64');
  const tag = cipher.getAuthTag().toString('base64');

  return {
    encrypted: true,
    tokens: {
      iv: iv.toString('base64'),
      tag,
      ciphertext
    }
  };
}

/**
 * Decrypt tokens if needed
 */
function decryptTokensIfNeeded(record) {
  if (!record) return null;
  if (!record.encrypted) {
    return record.tokens || null;
  }

  const key = getEncryptionKey();
  if (!key) {
    console.warn('Encrypted tokens present but TOKEN_ENCRYPTION_KEY not set');
    return null;
  }

  try {
    const { iv, tag, ciphertext } = record.tokens || {};
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'));
    decipher.setAuthTag(Buffer.from(tag, 'base64'));
    let plaintext = decipher.update(ciphertext, 'base64', 'utf8');
    plaintext += decipher.final('utf8');
    return JSON.parse(plaintext);
  } catch (e) {
    console.error('Failed to decrypt tokens:', e && e.message);
    return null;
  }
}

/**
 * Hash API key
 */
function hashApiKey(apiKey) {
  return crypto.createHash('sha256').update(String(apiKey)).digest('hex');
}

module.exports = {
  getEncryptionKey,
  encryptTokensIfConfigured,
  decryptTokensIfNeeded,
  hashApiKey
};
