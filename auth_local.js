const http = require('http');
const fs = require('fs');
const path = require('path');
const {google} = require('googleapis');
const open = require('child_process').exec;

const CLIENT_JSON_PATH = path.resolve(__dirname, '..', 'gdrive-mcp-server', 'credentials', 'gcp-oauth.keys.json');
const TOKEN_PATH = path.resolve(__dirname, '..', 'gdrive-mcp-server', 'credentials', '.gdrive-server-credentials.json');
// Default port for the local OAuth callback. Use PORT env to override.
// Use 3001 by default so it won't conflict with the MCP server which often runs on 3000.
const DEFAULT_PORT = process.env.PORT ? Number(process.env.PORT) : 3001;
const CALLBACK_PATH = '/oauth2callback';

// Find an available port starting at startPort, try up to maxTrials ports.
async function findAvailablePort(startPort, maxTrials = 10) {
  for (let i = 0; i < maxTrials; i++) {
    const p = startPort + i;
    // Try to bind a temporary server to test availability
    try {
      await new Promise((resolve, reject) => {
        const t = http.createServer();
        t.once('error', (err) => {
          t.close?.();
          reject(err);
        });
        t.listen(p, () => {
          t.close(() => resolve());
        });
      });
      return p;
    } catch (err) {
      if (err && err.code === 'EADDRINUSE') {
        // try next port
        continue;
      }
      // for other errors, rethrow
      // eslint-disable-next-line no-unsafe-finally
      throw err;
    }
  }
  throw new Error(`No available ports found starting at ${startPort}`);
}

function loadClient() {
  if (!fs.existsSync(CLIENT_JSON_PATH)) {
    console.error('OAuth client JSON not found at', CLIENT_JSON_PATH);
    process.exit(2);
  }
  const raw = fs.readFileSync(CLIENT_JSON_PATH, 'utf8');
  const parsed = JSON.parse(raw);
  return parsed.installed || parsed.web || parsed;
}

async function main() {
  const client = loadClient();
  const clientId = client.client_id;
  const clientSecret = client.client_secret;
  if (!clientId || !clientSecret) {
    console.error('client_id or client_secret missing from client JSON');
    process.exit(2);
  }

  // Pick an available port for the callback (DEFAULT_PORT or env override). This avoids
  // clashing with a running MCP server on port 3000.
  let serverPort;
  try {
    serverPort = await findAvailablePort(DEFAULT_PORT, 20);
  } catch (err) {
    console.error('Unable to find an available port for the OAuth callback:', err && err.message);
    process.exit(2);
  }
  if (serverPort !== DEFAULT_PORT) console.log(`Port ${DEFAULT_PORT} in use — using ${serverPort} for OAuth callback`);

  const redirect = `http://localhost:${serverPort}${CALLBACK_PATH}`;
  const oAuth2Client = new google.auth.OAuth2(clientId, clientSecret, redirect);

  const authUrl = oAuth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: ['https://www.googleapis.com/auth/drive.readonly'],
    prompt: 'consent',
  });

  console.log('\nOpen this URL in your browser (or wait, I will try to open it):\n');
  console.log(authUrl, '\n');

  // Try to open in default browser (best-effort)
  try {
    const cmd = process.platform === 'win32' ? `start "" "${authUrl}"` : `xdg-open "${authUrl}"`;
    open(cmd, (err) => { /* ignore errors */ });
  } catch (e) { /* ignore */ }

  // Create the HTTP server and bind it to the chosen serverPort
  let server;
  let codeHandled = false; // avoid double-processing when manual paste + redirect happen

  // Provide a manual-paste fallback: if you don't get redirected with a code,
  // paste the code into this terminal and press Enter.
  console.log('If the browser redirect shows "No code received", copy the code parameter from the URL and paste it here, then press Enter.');
  process.stdin.setEncoding('utf8');
  process.stdin.resume();
  process.stdin.on('data', async (chunk) => {
    const pasted = (chunk || '').toString().trim();
    if (!pasted) return;
    if (codeHandled) return;
    // If user pasted a full URL, try to extract the code param
    let maybeCode = pasted;
    try {
      if (pasted.startsWith('http')) {
        const u = new URL(pasted);
        maybeCode = u.searchParams.get('code') || maybeCode;
      }
    } catch (e) { /* ignore */ }

    if (!maybeCode) {
      console.error('No code found in the pasted text. Paste the full URL or the code parameter value.');
      return;
    }
    codeHandled = true;
    try {
      const { tokens } = await oAuth2Client.getToken(maybeCode);
      fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokens, null, 2));
      console.log('Saved OAuth tokens to', TOKEN_PATH);
    } catch (err) {
      console.error('Error exchanging pasted code for token:', err && err.message ? err.message : err);
      process.exit(1);
    } finally {
      try { server && server.close(); } catch (e) {}
      process.exit(0);
    }
  });

  server = http.createServer(async (req, res) => {
    if (req.url && req.url.startsWith(CALLBACK_PATH)) {
      const urlObj = new URL(req.url, `http://localhost:${serverPort}`);
      const code = urlObj.searchParams.get('code');
      res.writeHead(200, { 'Content-Type': 'text/html' });
      if (!code) {
        res.end('<html><body><h1>No code received</h1><p>Close this window and paste the code into the CLI if needed.</p></body></html>');
        console.error('No code query param received');
        return;
      }
      // mark handled to avoid the manual-paste handler also trying to exchange
      codeHandled = true;
      res.end('<html><body><h1>Authentication complete</h1><p>You can close this window.</p></body></html>');

      try {
        const {tokens} = await oAuth2Client.getToken(code);
        fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokens, null, 2));
        console.log('Saved OAuth tokens to', TOKEN_PATH);
      } catch (err) {
        console.error('Error exchanging code for token:', err.message || err);
      } finally {
        try { server && server.close(); } catch (e) {}
        process.exit(0);
      }
    } else {
      res.writeHead(404);
      res.end('Not found');
    }
  });

  server.listen(serverPort, () => {
    console.log(`Listening for OAuth callback on http://localhost:${serverPort}${CALLBACK_PATH}`);
    console.log('If you have a Google OAuth client configured for a different redirect URI, update it to this URL before continuing.');
  });
}

main();
