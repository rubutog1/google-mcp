/**
 * Email validation - RFC 5322-inspired with practical limits
 */
function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  if (email.length > 254) return false;

  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  if (!emailRegex.test(email)) return false;

  const parts = email.split('@');
  if (parts.length !== 2) return false;
  const [local, domain] = parts;
  if (!local || !domain) return false;
  if (local.length > 64) return false;

  return true;
}

/**
 * Google Drive file ID validation
 */
function validateFileId(fileId) {
  if (!fileId || typeof fileId !== 'string') {
    throw new Error('Invalid file ID');
  }
  // Google Drive file IDs are typically 25-50 chars, alphanumeric with hyphens/underscores
  if (!/^[a-zA-Z0-9_-]{25,50}$/.test(fileId)) {
    throw new Error('File ID format invalid');
  }
  return fileId;
}

/**
 * Sanitize file names to prevent path traversal and invalid characters
 */
function sanitizeFileName(name) {
  if (!name || typeof name !== 'string') {
    throw new Error('Invalid file name');
  }
  return name
    .replace(/[\/\\]/g, '') // strip path separators
    .replace(/\.\./g, '') // prevent parent directory traversal
    .trim()
    .substring(0, 255);
}

module.exports = {
  isValidEmail,
  validateFileId,
  sanitizeFileName
};
