const { listAuthenticatedEmails } = require('../storage/tokens');
const { PUBLIC_BASE_URL, PORT } = require('../config/config');

/**
 * Root endpoint - API documentation
 */
function rootHandler(req, res) {
  res.json({
    service: 'Email-Based Google Workspace MCP Server',
    version: '0.2.0',
    authentication: 'Email-based (no session dependency)',
    endpoints: {
      '/': 'API documentation',
      '/auth/start': 'HTML page to start OAuth (requires ?email=...)',
      '/auth?email=...': 'Start OAuth flow for email',
      '/auth/callback': 'OAuth callback handler',
      '/check-auth?email=...': 'Check if email is authenticated',
      '/whoami?email=...': 'Get user info for email',
      '/health': 'Health check',
      '/mcp': 'MCP protocol endpoint (POST)'
    },
    usage: {
      step_1: 'Call check_google_auth tool with user email',
      step_2a: 'If authenticated=true, use tools with email parameter',
      step_2b: 'If authenticated=false, user visits auth_url',
      step_3: 'After OAuth, all tools work with that email',
      note: 'Multiple sessions can use the same authenticated email'
    },
    authenticated_emails: listAuthenticatedEmails()
  });
}

/**
 * OAuth discovery stub - tells MCP Inspector OAuth not supported
 */
function registerStub(_req, res) {
  res.status(405).json({ error: 'invalid_client', error_description: 'OAuth not supported. Use X-API-Key header.' });
}

/**
 * OAuth discovery stub
 */
function oauthDiscoveryStub(_req, res) {
  res.status(404).json({ error: 'invalid_client', error_description: 'OAuth not supported. Use X-API-Key header.' });
}

module.exports = {
  rootHandler,
  registerStub,
  oauthDiscoveryStub
};
