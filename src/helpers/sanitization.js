/**
 * Mask sensitive data in logs
 */
function mask(str) {
  try {
    return String(str)
      .replace(/ya29\.[\w\-.]+/g, 'ya29.[redacted]')
      .replace(/(Authorization:\s*Bearer\s+)[^\s]+/gi, '$1[redacted]');
  } catch {
    return '[redacted]';
  }
}

/**
 * Sanitize object for logging (remove tokens)
 */
function sanitizeForLog(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(sanitizeForLog);
  const copy = { ...obj };
  if (copy.access_token) copy.access_token = '[redacted]';
  if (copy.refresh_token) copy.refresh_token = '[redacted]';
  if (copy.id_token) copy.id_token = '[redacted]';
  if (copy.tokens && typeof copy.tokens === 'object') copy.tokens = '[redacted]';
  return copy;
}

module.exports = {
  mask,
  sanitizeForLog
};
