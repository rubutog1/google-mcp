const fs = require('fs');
const { AUDIT_LOG_PATH } = require('../config/config');
const { sanitizeForLog } = require('./sanitization');

/**
 * Log audit event
 */
function logAudit(event) {
  try {
    const entry = {
      timestamp: new Date().toISOString(),
      ...event
    };
    const sanitized = sanitizeForLog(entry);
    fs.appendFile(AUDIT_LOG_PATH, JSON.stringify(sanitized) + '\n', { encoding: 'utf8' }, () => {});
  } catch (e) {
    console.warn('Failed to write audit log:', e && e.message);
  }
}

module.exports = {
  logAudit
};
