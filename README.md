GDrive MCP HTTP wrapper

This small project exposes a Streamable HTTP MCP endpoint that connects to Google Drive using saved OAuth credentials.

Files of interest
- `index.js` — the Express wrapper implementing `/mcp` POST/GET/DELETE using the SDK Streamable HTTP transport.
- `Dockerfile` — container image for deployment.

Environment variables
- `GOOGLE_APPLICATION_CREDENTIALS` — path to your OAuth client JSON (defaults to `../gdrive-mcp-server/credentials/gcp-oauth.keys.json`).
- `MCP_GDRIVE_CREDENTIALS` — path to your saved user tokens (defaults to `../gdrive-mcp-server/credentials/.gdrive-server-credentials.json`).
- `AUTH_BEARER_TOKEN` — optional bearer token to protect the endpoint. If set, include `Authorization: Bearer <token>` in FlyerGPT headers.
- `PORT` — port to listen on (default 3000).

Run locally (PowerShell)
```powershell
cd workspace\gdrive-mcp-server-http
npm install
$env:GOOGLE_APPLICATION_CREDENTIALS = (Resolve-Path ..\gdrive-mcp-server\credentials\gcp-oauth.keys.json)
$env:MCP_GDRIVE_CREDENTIALS = (Resolve-Path ..\gdrive-mcp-server\credentials\.gdrive-server-credentials.json)
$env:AUTH_BEARER_TOKEN = 'choose-a-secret'
npm start
```

Run with Docker
```powershell
docker build -t gdrive-mcp-http .
docker run -p 3000:3000 -e GOOGLE_APPLICATION_CREDENTIALS=/credentials/gcp-oauth.keys.json -e MCP_GDRIVE_CREDENTIALS=/credentials/.gdrive-server-credentials.json -e AUTH_BEARER_TOKEN=choose-a-secret -v C:\path\to\credentials:/credentials gdrive-mcp-http
```

Connecting FlyerGPT
- URL: `https://your-domain.example.com/mcp` (make sure your reverse proxy forwards TLS to the running app)
- Headers: `Authorization: Bearer choose-a-secret` (if you set `AUTH_BEARER_TOKEN`)

Notes
- You must run the felores auth flow once (on your laptop or server) to generate the saved credentials file (`.gdrive-server-credentials.json`). Place it under `gdrive-mcp-server/credentials` or point `MCP_GDRIVE_CREDENTIALS` at it.
- This wrapper uses the official MCP SDK Streamable HTTP transport; no extra paid services are needed.
