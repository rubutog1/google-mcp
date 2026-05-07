const cors = require('cors');
const { ALLOWED_ORIGINS } = require('../config/config');

/**
 * Configure CORS middleware
 */
function configureCors() {
  return cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes('*')) {
        return callback(null, true);
      }
      if (ALLOWED_ORIGINS.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error('Not allowed by CORS'), false);
    },
    exposedHeaders: ['Mcp-Session-Id'],
    allowedHeaders: [
      'Content-Type',
      'authorization',
      'mcp-session-id',
      'Mcp-Session-Id',
      'mcp-protocol-version',
      'Mcp-Protocol-Version',
      'ngrok-skip-browser-warning',
      'x-api-key',
      'X-Api-Key'
    ]
  });
}

/**
 * Configure HTTPS enforcement middleware
 */
function configureHttpsEnforcement(enforceHttps) {
  if (!enforceHttps) {
    return (req, res, next) => next();
  }

  return (req, res, next) => {
    try {
      const hdr = req.headers['x-forwarded-proto'] || req.protocol || '';
      const proto = String(hdr).split(',')[0].trim().toLowerCase();
      if (proto && proto !== 'https') {
        return res.status(403).json({ error: 'HTTPS is required. Please use an https:// URL.' });
      }
    } catch {}
    next();
  };
}

module.exports = {
  configureCors,
  configureHttpsEnforcement
};
