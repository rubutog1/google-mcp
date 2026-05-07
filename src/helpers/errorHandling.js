const { PUBLIC_BASE_URL } = require('../config/config');
const { logAudit } = require('../helpers/audit');

/**
 * Handle tool errors with appropriate responses
 */
function handleToolError(err, toolName, email) {
  console.error(`[${toolName}] Error:`, err && (err.stack || err));
  logAudit({
    type: 'tool_error',
    tool: toolName,
    email,
    error: err && (err.message || String(err)),
    stack: err && err.stack ? err.stack.split('\n').slice(0, 5).join('\n') : null,
    code: err && err.code
  });
  
  if (err.message && err.message.includes('Authentication expired')) {
    return {
      content: [{
        type: 'text',
        text: `❌ Authentication expired for ${email}. Please re-authenticate:\n${PUBLIC_BASE_URL}/auth/start?email=${encodeURIComponent(email)}`
      }],
      isError: false
    };
  }
  
  if (err.message && err.message.includes('No tokens found')) {
    return {
      content: [{
        type: 'text',
        text: `❌ No credentials found for ${email}. Please authenticate:\n${PUBLIC_BASE_URL}/auth/start?email=${encodeURIComponent(email)}`
      }],
      isError: false
    };
  }
  
  return {
    content: [{
      type: 'text',
      text: `❌ Error in ${toolName}: ${err.message || String(err)}`
    }],
    isError: false
  };
}

module.exports = {
  handleToolError
};
