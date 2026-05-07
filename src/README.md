# src/ Directory Structure

This directory contains the modularized source code for the Email-Based Google Workspace MCP Server.

## Quick Start

```
src/
├── index.js              # Application entry point
├── app.js                # Express app setup & route registration
├── config/               # Configuration & environment variables
├── middleware/           # Express middleware
├── helpers/              # Utility functions
├── storage/              # User, token & API key storage
├── google/               # Google APIs integration
├── mcp/                  # MCP server & tools
└── routes/               # HTTP route handlers
```

## File Purposes

### Core Files
- **index.js** - Starts the server (calls src/app.js)
- **app.js** - Initializes Express, registers all routes and middleware

### Configuration
- **config/config.js** - All environment variables, ports, paths, API keys, OAuth config

### Middleware
- **middleware/auth.js** - Bearer token & API key authentication
- **middleware/cors.js** - CORS setup and HTTPS enforcement

### Helper Utilities
- **helpers/validation.js** - Email, file ID, and filename validation
- **helpers/encryption.js** - Token encryption/decryption
- **helpers/sanitization.js** - Log masking and sanitization
- **helpers/audit.js** - Audit event logging
- **helpers/errorHandling.js** - Consistent error responses for tools

### Storage Layer
- **storage/users.js** - User creation, retrieval, login tracking
- **storage/tokens.js** - Token storage, expiration, encryption
- **storage/apiKeys.js** - API key generation and validation

### Google Integration
- **google/credentials.js** - OAuth2 client, token refresh
- **google/oauth.js** - OAuth flow, authorization URL generation
- **google/gmail.js** - Gmail-specific helpers (body extraction, message fetching)

### MCP Server
- **mcp/server.js** - MCP server creation, tool definition & handlers
- **mcp/tools/drive.js** - Google Drive tool implementations
- **mcp/tools/gmail.js** - Gmail tool implementations
- **mcp/tools/calendar.js** - Google Calendar tool implementations
- **mcp/tools/tasks.js** - Google Tasks tool implementations
- **mcp/tools/specialized.js** - Dashboard & study session tools

### Routes
- **routes/main.js** - Root endpoint, OAuth discovery stubs
- **routes/auth.js** - Authentication endpoints (OAuth flow, status checks)
- **routes/health.js** - Health check endpoint
- **routes/mcp.js** - MCP protocol endpoints (POST/GET/DELETE)

## How to Add New Features

### Add a new route
1. Create or modify a file in `routes/`
2. Export a handler function
3. Register it in `app.js` with `app.get()`, `app.post()`, etc.

### Add a new MCP tool
1. Add the tool to the appropriate file in `mcp/tools/`
2. Implement the handler function
3. Add the tool definition to `mcp/server.js` (in ListToolsRequestSchema)
4. Add the tool case handler in `mcp/server.js` (in CallToolRequestSchema)

### Add a helper function
1. Create or modify a file in `helpers/`
2. Export the function
3. Import it where needed

### Change configuration
1. Update `config/config.js`
2. Import `{ CONFIG_VAR }` from there in other files

## Imports

Each file imports only what it needs:

```javascript
// Config
const { PORT, BEARER } = require('../config/config');

// Helpers
const { isValidEmail } = require('../helpers/validation');
const { encryptTokensIfConfigured } = require('../helpers/encryption');
const { logAudit } = require('../helpers/audit');

// Storage
const { getUserByEmail } = require('../storage/users');
const { loadTokensForEmail } = require('../storage/tokens');

// Google APIs
const { getCredentialsForEmail } = require('../google/credentials');
const { extractEmailBody } = require('../google/gmail');

// Middleware
const { checkAuth } = require('../middleware/auth');
```

## Error Handling

Use `handleToolError()` for consistent tool error responses:

```javascript
const { handleToolError } = require('../helpers/errorHandling');

// In a tool handler
try {
  // ... tool logic
} catch (err) {
  return handleToolError(err, 'tool_name', email);
}
```

## Logging

Audit important events:

```javascript
const { logAudit } = require('../helpers/audit');

logAudit({ 
  type: 'event_name',
  email: user_email,
  details: 'any relevant info'
});
```

## Testing

Each module can be tested independently:

```javascript
// Test config
const config = require('./config/config');
console.assert(config.PORT === 3001);

// Test helpers
const { isValidEmail } = require('./helpers/validation');
console.assert(isValidEmail('test@example.com') === true);
console.assert(isValidEmail('invalid') === false);

// Test storage
const { getUserByEmail } = require('./storage/users');
const user = getUserByEmail('test@example.com');
```

## See Also

- **REFACTORING_GUIDE.md** - Detailed migration guide from old index.js
- **../README.md** - Project overview
- **../package.json** - Dependencies
