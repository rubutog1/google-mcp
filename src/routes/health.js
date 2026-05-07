const { listAuthenticatedEmails } = require('../storage/tokens');
const { OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET } = require('../config/config');

/**
 * Health check endpoint
 */
function healthHandler(req, res) {
  const authenticated = listAuthenticatedEmails();
  
  res.json({
    ok: true,
    mode: 'email-based',
    authenticated_emails_count: authenticated.length,
    oauth_configured: !!(OAUTH_CLIENT_ID && OAUTH_CLIENT_SECRET)
  });
}

module.exports = {
  healthHandler
};
