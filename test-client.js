const { StreamableHTTPClientTransport } = require('./node_modules/@modelcontextprotocol/sdk/dist/cjs/client/streamableHttp.js');
const { Client } = require('./node_modules/@modelcontextprotocol/sdk/dist/cjs/client/index.js');

(async () => {
  try {
  // Let the server issue a session id by not providing one here
  // TARGET_MCP_URL env var can override the target (useful for testing ngrok/public endpoints)
  const target = process.env.TARGET_MCP_URL || 'http://localhost:3100/mcp';
  console.log('Using MCP endpoint:', target);
  const transport = new StreamableHTTPClientTransport(target, { requestInit: { headers: { 'Authorization': 'Bearer changeme' } } });
  const client = new Client({ name: 'test-client', version: '0.1.0' });
  await client.connect(transport);
    const res = await client.listTools();
    console.log('tools.list result:', JSON.stringify(res, null, 2));
    // Optionally call gdrive_search with an empty query to list recent files
    if (process.argv.includes('--search-empty')) {
      console.log('Calling gdrive_search with empty query...');
      const searchRes = await client.callTool({ name: 'gdrive_search', arguments: { query: '' } });
      console.log('gdrive_search result:', JSON.stringify(searchRes, null, 2));
    }

    // Keep the transport/session alive so the server can complete OAuth callbacks
    // By default we wait for the user to press ENTER (or Ctrl+C). Pass --no-wait to exit immediately.
    if (process.argv.includes('--no-wait')) {
      await transport.terminateSession();
      await transport.close();
      console.log('Exited (no-wait).');
      return;
    }

    console.log('Transport is active. Press ENTER to terminate the session and exit.');
    const readline = require('readline');
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

    // On ENTER, terminate session and exit cleanly
    rl.on('line', async (line) => {
      const trimmed = String(line || '').trim();
      if (!trimmed) {
        // empty line => terminate
        try {
          console.log('Terminating session...');
          await transport.terminateSession();
          await transport.close();
          rl.close();
          console.log('Session terminated, exiting.');
          process.exit(0);
        } catch (err) {
          console.error('Error terminating transport:', err);
          process.exit(1);
        }
      }

      // REPL format: toolName: { "key": "value" }
      const m = trimmed.match(/^\s*([a-zA-Z0-9_]+)\s*:\s*(\{.*\})\s*$/);
      if (!m) { console.log('Format: toolName: { "key": "value" }'); return; }
      const name = m[1];
      let args;
      try { args = JSON.parse(m[2]); } catch { console.log('Bad JSON args'); return; }

      try {
        const toolRes = await client.callTool({ name, arguments: args });
        try { console.log('Tool response:', JSON.stringify(toolRes, null, 2)); } catch { console.log('Tool response (raw):', toolRes); }
      } catch (err) {
        console.error('Tool call failed:', err && err.message ? err.message : err);
      }
    });

    // Also handle SIGINT so Ctrl+C works
    process.on('SIGINT', async () => {
      try {
        console.log('\nCaught SIGINT, terminating session...');
        await transport.terminateSession();
        await transport.close();
      } catch (err) {
        // ignore
      }
      process.exit(0);
    });
  } catch (e) {
    console.error('client error:', e);
    process.exit(1);
  }
})();