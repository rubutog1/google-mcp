const express = require('express');
const { PORT, PUBLIC_BASE_URL, BEARER, ENFORCE_HTTPS, ALLOWED_ORIGINS } = require('./config/config');
const { configureCors, configureHttpsEnforcement } = require('./middleware/cors');
const { checkAuth, apiKeyAuth } = require('./middleware/auth');
const { listAuthenticatedEmails } = require('./storage/tokens');
const authRoutes = require('./routes/auth');
const mainRoutes = require('./routes/main');
const healthRoutes = require('./routes/health');
const mcpRoutes = require('./routes/mcp');

/**
 * Initialize Express app with middleware
 */
function initializeApp() {
  const app = express();
  
  app.use(express.json({ limit: '10mb' }));
  app.use(configureCors());
  
  if (ENFORCE_HTTPS) {
    app.enable('trust proxy');
    app.use(configureHttpsEnforcement(true));
  }
  
  return app;
}

/**
 * Register all routes
 */
function registerRoutes(app) {
  // Main routes
  app.get('/', mainRoutes.rootHandler);
  
  // Auth routes
  app.get('/auth/start', authRoutes.authStartHandler);
  app.get('/auth', authRoutes.authHandler);
  app.get('/auth/callback', authRoutes.authCallbackHandler);
  
  // Check auth
  app.get('/check-auth', authRoutes.checkAuthHandler);
  
  // Whoami endpoint
  app.get('/whoami', checkAuth, authRoutes.whoamiHandler);
  
  // OAuth discovery stubs
  app.post('/register', mainRoutes.registerStub);
  app.get('/.well-known/oauth-authorization-server', mainRoutes.oauthDiscoveryStub);
  
  // Health check
  app.get('/health', healthRoutes.healthHandler);
  
  // MCP endpoints
  app.post('/mcp', apiKeyAuth, mcpRoutes.mcpPostHandler);
  app.get('/mcp', apiKeyAuth, mcpRoutes.mcpGetHandler);
  app.delete('/mcp', apiKeyAuth, mcpRoutes.mcpDeleteHandler);
}

/**
 * Start server
 */
function startServer() {
  const app = initializeApp();
  registerRoutes(app);
  
  const httpServer = app.listen(PORT, () => {
    console.log(`\n${'='.repeat(60)}`);
    console.log('📧 Email-Based Google Workspace MCP Server');
    console.log(`${'='.repeat(60)}`);
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`🌐 Base URL: ${PUBLIC_BASE_URL}`);
    console.log(`🔑 Auth Mode: Shared server API key + Client-level account binding`);
    console.log(`🔐 Server API Key: ${BEARER || 'Not configured'}`);
    
    const authenticated = listAuthenticatedEmails();
    if (authenticated.length > 0) {
      console.log(`\n✅ Authenticated emails (${authenticated.length}):`);
      authenticated.forEach(email => console.log(`   - ${email}`));
    } else {
      console.log(`\n⚠️  No authenticated emails yet`);
    }
    
    console.log(`\n📚 To authenticate a new email:`);
    console.log(`   1. Visit: ${PUBLIC_BASE_URL}/auth/start`);
    console.log(`   2. Enter email address`);
    console.log(`   3. Complete Google OAuth`);
    console.log(`   4. Use the server API key (${BEARER || 'AUTH_BEARER_TOKEN'}) in X-API-Key header`);
    console.log(`   5. Specify the email in MCP tool calls`);
    console.log(`\n🔒 Security: One account per client at a time. Close all sessions to switch accounts.`);
    console.log(`⏰ Token Expiry: Tokens expire after 8 hours of inactivity.\n`);
    console.log(`${'='.repeat(60)}\n`);
  });

  function gracefulShutdown() {
    console.log('\n🛑 Graceful shutdown initiated...');
    
    try {
      if (httpServer && typeof httpServer.close === 'function') {
        httpServer.close(() => {
          console.log('✅ HTTP server closed');
          process.exit(0);
        });
        
        setTimeout(() => {
          console.warn('⚠️  Forcing shutdown after timeout');
          process.exit(1);
        }, 5000);
      } else {
        process.exit(0);
      }
    } catch (e) {
      console.error('❌ Shutdown error:', e);
      process.exit(1);
    }
  }

  process.on('SIGINT', gracefulShutdown);
  process.on('SIGTERM', gracefulShutdown);
  process.on('uncaughtException', (e) => {
    console.error('❌ Uncaught exception:', e);
  });
  process.on('unhandledRejection', (e) => {
    console.error('❌ Unhandled rejection:', e);
  });

  return httpServer;
}

module.exports = {
  initializeApp,
  registerRoutes,
  startServer
};
