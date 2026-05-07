const crypto = require('crypto');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const { isInitializeRequest } = require('@modelcontextprotocol/sdk/types.js');
const { createMcpServer } = require('../mcp/server');
const { RATE_WINDOW_MS, RATE_MAX_REQUESTS, TRANSPORT_TTL_MS } = require('../config/config');
const { logAudit } = require('../helpers/audit');

// MCP session management
const transports = {};
const transportMeta = {};
let rateWindowStart = 0;
let rateCount = 0;
const sessionEmails = {};
const clientSessions = {};
const sessionToClient = {};

/**
 * Get client identifier from request
 */
function getClientId(req) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
             req.headers['x-real-ip'] ||
             req.socket?.remoteAddress ||
             req.connection?.remoteAddress ||
             'unknown';
  
  const ua = req.headers['user-agent'] || '';
  const uaHash = crypto.createHash('md5').update(ua).digest('hex').substring(0, 8);
  
  return `${ip}-${uaHash}`;
}

/**
 * Cleanup stale transports
 */
function cleanupTransports() {
  const now = Date.now();
  for (const id of Object.keys(transportMeta)) {
    const meta = transportMeta[id];
    if (!meta) continue;
    if (now - meta.lastUsed > TRANSPORT_TTL_MS) {
      const t = transports[id];
      if (t && typeof t.close === 'function') {
        try {
          t.close();
        } catch (e) {
          console.warn('Error closing stale transport', id, e && e.message);
        }
      }
      delete transports[id];
      delete transportMeta[id];
      delete sessionEmails[id];
      
      const clientId = sessionToClient[id];
      if (clientId && clientSessions[clientId]) {
        clientSessions[clientId] = clientSessions[clientId].filter(s => s.sessionId !== id);
        if (clientSessions[clientId].length === 0) {
          delete clientSessions[clientId];
        }
      }
      delete sessionToClient[id];
      
      console.log('[MCP] Cleaned up stale session:', id);
    }
  }
}

/**
 * Check global rate limit
 */
function checkGlobalRateLimit() {
  const now = Date.now();
  if (!rateWindowStart || now - rateWindowStart > RATE_WINDOW_MS) {
    rateWindowStart = now;
    rateCount = 0;
  }
  rateCount += 1;
  return rateCount > RATE_MAX_REQUESTS;
}

/**
 * MCP POST handler
 */
async function mcpPostHandler(req, res) {
  try {
    cleanupTransports();
    if (checkGlobalRateLimit()) {
      logAudit({ type: 'rate_limit', message: 'Global MCP rate limit exceeded' });
      return res.status(429).json({
        jsonrpc: '2.0',
        error: { code: -32001, message: 'Rate limit exceeded, try again later' },
        id: (req.body && req.body.id) || null
      });
    }

    console.log('[MCP POST] Received request');

    const sessionHeader = req.headers['mcp-session-id'] || req.headers['Mcp-Session-Id'];
    const clientId = getClientId(req);

    // Session binding for multi-account protection
    if (req.body && req.body.method === 'tools/call') {
      const toolName = req.body.params && req.body.params.name;
      const args = (req.body.params && req.body.params.arguments) || {};

      if (toolName === 'get_user_email') {
        const userEmail = args && typeof args.user_provided_email === 'string'
          ? args.user_provided_email.toLowerCase().trim()
          : null;

        if (userEmail && clientId) {
          const existingSessions = clientSessions[clientId] || [];
          const differentEmailSession = existingSessions.find(s => s.email !== userEmail);
          
          if (differentEmailSession) {
            logAudit({
              type: 'client_multi_account_violation',
              client_id: clientId,
              active_email: differentEmailSession.email,
              attempted_email: userEmail
            });

            return res.status(403).json({
              jsonrpc: '2.0',
              error: {
                code: -32007,
                message: `Access denied. You are already authenticated as ${differentEmailSession.email} in another session. Please close that session before authenticating as ${userEmail}.`
              },
              id: req.body.id || null
            });
          }

          if (sessionHeader) {
            sessionEmails[sessionHeader] = userEmail;
            sessionToClient[sessionHeader] = clientId;
            
            if (!clientSessions[clientId]) {
              clientSessions[clientId] = [];
            }
            if (!clientSessions[clientId].find(s => s.sessionId === sessionHeader)) {
              clientSessions[clientId].push({ sessionId: sessionHeader, email: userEmail });
            }
            
            console.log(`[SESSION BINDING] Session ${sessionHeader} bound to email: ${userEmail}`);
          }
        }
      }

      const requestedEmail = args && typeof args.email === 'string'
        ? args.email.toLowerCase().trim()
        : null;

      if (requestedEmail && sessionHeader) {
        const boundEmail = sessionEmails[sessionHeader];
        
        if (boundEmail && requestedEmail !== boundEmail) {
          logAudit({
            type: 'session_email_violation',
            tool: toolName,
            bound_email: boundEmail,
            requested_email: requestedEmail
          });

          return res.status(403).json({
            jsonrpc: '2.0',
            error: {
              code: -32006,
              message: `Access denied. This session is bound to ${boundEmail}. Cannot access ${requestedEmail} in the same session.`
            },
            id: req.body.id || null
          });
        }
      }
    }

    let transport;

    if (sessionHeader && transports[sessionHeader]) {
      console.log('[MCP POST] Reusing existing transport for session:', sessionHeader);
      transport = transports[sessionHeader];
      if (transportMeta[sessionHeader]) {
        transportMeta[sessionHeader].lastUsed = Date.now();
      }
    } else if (isInitializeRequest(req.body)) {
      const sess = sessionHeader || crypto.randomUUID();
      console.log('[MCP POST] Initializing new session:', sess);
      
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => sess,
        onsessioninitialized: (id) => {
          transports[id] = transport;
          transportMeta[id] = {
            createdAt: Date.now(),
            lastUsed: Date.now()
          };
          console.log('[MCP] Session initialized:', id);
        }
      });

      const server = createMcpServer();
      await server.connect(transport);
      console.log('[MCP] Server connected to transport');
    } else {
      console.log('[MCP POST] Invalid request - not an initialize request and no session');
      return res.status(400).json({
        jsonrpc: '2.0',
        error: { code: -32000, message: 'Initialize with session first' },
        id: null
      });
    }

    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    console.error('[MCP POST] Error:', err);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: '2.0',
        error: { code: -32603, message: String(err) },
        id: null
      });
    }
  }
}

/**
 * MCP GET handler
 */
async function mcpGetHandler(req, res) {
  try {
    cleanupTransports();
    const sessionId = req.headers['mcp-session-id'] || req.query.sessionId;
    console.log('[MCP GET] Session:', sessionId);
    
    if (!sessionId || !transports[sessionId]) {
      return res.status(400).json({ ok: false, error: 'Invalid or missing session ID' });
    }
    
    const transport = transports[sessionId];
    if (transportMeta[sessionId]) {
      transportMeta[sessionId].lastUsed = Date.now();
    }
    await transport.handleRequest(req, res);
  } catch (err) {
    console.error('[MCP GET] Error:', err);
    if (!res.headersSent) {
      res.status(500).send('Internal server error');
    }
  }
}

/**
 * MCP DELETE handler
 */
async function mcpDeleteHandler(req, res) {
  try {
    cleanupTransports();
    const sessionId = req.headers['mcp-session-id'];
    console.log('[MCP DELETE] Closing session:', sessionId);
    
    if (!sessionId || !transports[sessionId]) {
      return res.status(400).send('Invalid or missing session ID');
    }
    
    const t = transports[sessionId];
    if (t && typeof t.close === 'function') t.close();
    delete transports[sessionId];
    delete transportMeta[sessionId];
    delete sessionEmails[sessionId];
    
    const clientId = sessionToClient[sessionId];
    if (clientId && clientSessions[clientId]) {
      clientSessions[clientId] = clientSessions[clientId].filter(s => s.sessionId !== sessionId);
      if (clientSessions[clientId].length === 0) {
        delete clientSessions[clientId];
      }
      console.log(`[CLIENT TRACKING] Removed session ${sessionId} from client ${clientId}`);
    }
    delete sessionToClient[sessionId];
    
    res.status(200).send('OK');
  } catch (err) {
    console.error('[MCP DELETE] Error:', err);
    res.status(500).send('Internal server error');
  }
}

module.exports = {
  mcpPostHandler,
  mcpGetHandler,
  mcpDeleteHandler
};
