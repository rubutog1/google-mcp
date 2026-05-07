const { BEARER, ALLOW_ANONYMOUS } = require('../config/config');
const { logAudit } = require('../helpers/audit');

/**
 * Bearer token authentication middleware
 */
function checkAuth(req, res, next) {
  if (!BEARER) {
    if (ALLOW_ANONYMOUS) return next();
    return res.status(401).json({ error: 'Missing server bearer token configuration' });
  }
  const h = req.headers['authorization'] || req.headers['Authorization'];
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing Authorization' });
  const token = h.slice(7).trim();
  if (token !== BEARER) return res.status(403).json({ error: 'Forbidden' });
  next();
}

/**
 * API key authentication middleware
 */
function apiKeyAuth(req, res, next) {
  const header = req.headers['x-api-key'];
  const apiKey = typeof header === 'string' ? header.trim() : null;

  if (!apiKey) {
    logAudit({ type: 'api_key_missing', path: req.path });
    return res.status(401).json({
      jsonrpc: '2.0',
      error: {
        code: -32003,
        message: 'X-API-Key header required. Use the server API key from AUTH_BEARER_TOKEN.'
      },
      id: (req.body && req.body.id) || null
    });
  }

  if (apiKey !== BEARER) {
    logAudit({ type: 'api_key_invalid', path: req.path });
    return res.status(401).json({
      jsonrpc: '2.0',
      error: {
        code: -32004,
        message: 'Invalid API key. Use the server API key from AUTH_BEARER_TOKEN.'
      },
      id: (req.body && req.body.id) || null
    });
  }

  next();
}

module.exports = {
  checkAuth,
  apiKeyAuth
};
