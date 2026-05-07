const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const {
  isInitializeRequest,
  CallToolRequestSchema,
  ListToolsRequestSchema
} = require('@modelcontextprotocol/sdk/types.js');
const { verifyEmail, getCredentialsForEmail } = require('../google/credentials');
const { handleToolError } = require('../helpers/errorHandling');
const { logAudit } = require('../helpers/audit');
const { isValidEmail } = require('../helpers/validation');

/**
 * Create MCP Server with tool handlers
 * 
 * Note: This file imports tool implementations from:
 * - src/mcp/tools/drive.js
 * - src/mcp/tools/gmail.js
 * - src/mcp/tools/calendar.js
 * - src/mcp/tools/tasks.js
 * - src/mcp/tools/specialized.js
 * 
 * Each tool module should export handler functions that are referenced
 * in the tool call handler below.
 */
function createMcpServer() {
  const server = new Server(
    { name: 'gdrive-http-email', version: '0.2.0' },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const { PUBLIC_BASE_URL } = require('../config/config');
    const connectUrl = `${PUBLIC_BASE_URL.replace(/\/$/, '')}/auth/start`;

    const tools = [
      {
        name: 'get_user_email',
        description: `CRITICAL: Call this FIRST to get the user's email address. Ask the user "What is your email address?" and use their response. This email is required for ALL other tools.`,
        inputSchema: {
          type: 'object',
          properties: {
            user_provided_email: { 
              type: 'string', 
              description: 'The email address the user told you when you asked "What is your email?"' 
            }
          },
          required: ['user_provided_email']
        }
      },
      {
        name: 'check_google_auth',
        description: `Check if a user's email is authenticated. Returns auth status and auth_url if needed. Call this SECOND (after get_user_email) before using other tools.`,
        inputSchema: {
          type: 'object',
          properties: {
            email: { type: 'string', description: 'User email address from get_user_email' }
          },
          required: ['email']
        }
      },
      // Add more tools here as they're implemented
      // See REFACTORING_GUIDE.md for how to add each tool
    ];

    return { tools };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    try {
      console.log(`[TOOL CALL] ${request.params.name}`, JSON.stringify(request.params.arguments || {}));
      logAudit({
        type: 'tool_call',
        tool: request.params.name,
        email: request.params.arguments?.email || null,
        arguments: request.params.arguments || null
      });

      const email = request.params.arguments?.email;
      const { PUBLIC_BASE_URL } = require('../config/config');

      // get_user_email tool
      if (request.params.name === 'get_user_email') {
        const userEmail = request.params.arguments?.user_provided_email;
        
        if (!userEmail) {
          return {
            content: [{
              type: 'text',
              text: '❌ Please ask the user: "What is your email address?" and try again with their response.'
            }],
            isError: false
          };
        }

        if (!isValidEmail(userEmail)) {
          return {
            content: [{
              type: 'text',
              text: `❌ "${userEmail}" is not a valid email address. Please ask the user for a valid email.`
            }],
            isError: false
          };
        }

        const emailLower = userEmail.toLowerCase().trim();
        
        return {
          content: [
            {
              type: 'text',
              text: `✅ Got user email: ${emailLower}. Now call check_google_auth with this email to verify authentication.`
            },
            {
              type: 'text',
              text: `DATA:\n${JSON.stringify({
                success: true,
                email: emailLower,
                message: `✅ Got user email: ${emailLower}. Now use this email in all other tool calls.`,
                next_step: `Call check_google_auth with email="${emailLower}" to verify authentication`
              }, null, 2)}`
            }
          ],
          isError: false
        };
      }

      // check_google_auth tool
      if (request.params.name === 'check_google_auth') {
        if (!email) {
          return {
            content: [{
              type: 'text',
              text: '❌ Email parameter is required'
            }],
            isError: false
          };
        }

        const { getUserByEmail } = require('../storage/users');
        const { loadTokensForEmail } = require('../storage/tokens');
        
        const user = getUserByEmail(email);
        
        if (!user) {
          const authUrl = `${PUBLIC_BASE_URL}/auth/start?email=${encodeURIComponent(email)}`;
          return {
            content: [{
              type: 'text',
              text: `DATA:\n${JSON.stringify({
                authenticated: false,
                email: email,
                message: 'User not found. Please complete Google OAuth.',
                auth_url: authUrl,
                next_step: 'Visit auth_url to grant Google permissions'
              }, null, 2)}`
            }],
            isError: false
          };
        }

        const tokens = loadTokensForEmail(email);
        if (!tokens) {
          const authUrl = `${PUBLIC_BASE_URL}/auth/start?email=${encodeURIComponent(email)}`;
          return {
            content: [{
              type: 'text',
              text: `DATA:\n${JSON.stringify({
                authenticated: false,
                email: email,
                user_id: user.user_id,
                message: 'User exists but not authenticated. Please complete OAuth.',
                auth_url: authUrl
              }, null, 2)}`
            }],
            isError: false
          };
        }

        return {
          content: [{
            type: 'text',
            text: `DATA:\n${JSON.stringify({
              authenticated: true,
              email: email,
              user_id: user.user_id,
              display_name: user.display_name,
              message: 'User is authenticated. You can now use Google tools.'
            }, null, 2)}`
          }],
          isError: false
        };
      }

      throw new Error(`Tool not found: ${request.params.name}`);
    } catch (err) {
      console.error('[TOOL ERROR]', err);
      return {
        content: [{
          type: 'text',
          text: `❌ Error: ${err.message || String(err)}`
        }],
        isError: false
      };
    }
  });

  return server;
}

module.exports = { createMcpServer };
