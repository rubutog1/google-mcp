const fs = require('fs');
const path = require('path');
const readline = require('readline');
const {google} = require('googleapis');

const CLIENT_JSON_PATH = path.resolve(__dirname, '..', 'gdrive-mcp-server', 'credentials', 'gcp-oauth.keys.json');
const TOKEN_PATH = path.resolve(__dirname, '..', 'gdrive-mcp-server', 'credentials', '.gdrive-server-credentials.json');

function loadClient() {
  if (!fs.existsSync(CLIENT_JSON_PATH)) {
    console.error('OAuth client JSON not found at', CLIENT_JSON_PATH);
    process.exit(2);
  }
  const raw = fs.readFileSync(CLIENT_JSON_PATH, 'utf8');
  const parsed = JSON.parse(raw);
  // Support both "installed" and "web" formats
  return parsed.installed || parsed.web || parsed;
}

async function run() {
  const client = loadClient();
  const clientId = client.client_id || client.clientId;
  const clientSecret = client.client_secret || client.clientSecret;
  const redirectUris = client.redirect_uris || client.redirectUris || [];

  const redirect = redirectUris[0] || 'urn:ietf:wg:oauth:2.0:oob';
  const oAuth2Client = new google.auth.OAuth2(clientId, clientSecret, redirect);

  const authUrl = oAuth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: ['https://www.googleapis.com/auth/drive.readonly'],
    prompt: 'consent',
  });

  console.log('\nOpen this URL in your browser and grant access:');
  console.log(authUrl);
  console.log('\nAfter approving, you will be shown a code. Paste it below.');

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  rl.question('\nEnter the authorization code: ', async (code) => {
    rl.close();
    try {
      const {tokens} = await oAuth2Client.getToken(code.trim());
      fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokens, null, 2));
      console.log('Saved OAuth tokens to', TOKEN_PATH);
      process.exit(0);
    } catch (err) {
      console.error('Error while exchanging code for token:', err.message || err);
      process.exit(1);
    }
  });
}

run();
