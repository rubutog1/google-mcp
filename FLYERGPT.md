# FlyerGPT integration notes

This file shows the minimal headers and JSON-RPC examples FlyerGPT (or any MCP client) needs to call the Streamable HTTP MCP endpoint exposed by this service.

## Required HTTP headers

- `Accept: application/json, text/event-stream`  -- required so the server responds with the Streamable HTTP / SSE payload.
- `Content-Type: application/json`
- `Authorization: Bearer <YOUR_TOKEN>` -- optional but recommended. Set the same value as `AUTH_BEARER_TOKEN` used when starting the container.

If you set `AUTH_BEARER_TOKEN` in the container (or via Cloud Run secret), FlyerGPT must send the same bearer token.

## Stateless JSON-RPC (recommended for FlyerGPT)

1) List resources (Drive files)

Request (curl):

```bash
curl -v -H "Accept: application/json, text/event-stream" \
     -H "Authorization: Bearer changeme" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","id":"req-1","method":"resources/list","params":{"pageSize":5}}' \
     https://<your-host>/mcp
```

PowerShell equivalent (what we used during testing):

```powershell
$body = '{"jsonrpc":"2.0","id":"req-1","method":"resources/list","params":{"pageSize":5}}'
Invoke-WebRequest -Uri 'https://<your-host>/mcp' -Method Post -Body $body -ContentType 'application/json' \
  -Headers @{ Accept='application/json, text/event-stream'; Authorization='Bearer changeme' } -UseBasicParsing
```

Response (SSE snippet):

```
event: message
data: {"result":{"resources":[{"uri":"gdrive:///FILE_ID","mimeType":"...","name":"..."}, ...],"nextCursor":"..."},"jsonrpc":"2.0","id":"req-1"}
```

The client should parse the SSE `data` payload as JSON and read `result.resources[]`. Each resource URI will be of the form `gdrive:///FILE_ID`.

2) Read a resource (by URI)

After obtaining a `uri` from `resources/list`, request the contents:

Request body:

```json
{"jsonrpc":"2.0","id":"req-2","method":"resources/read","params":{"uri":"gdrive:///FILE_ID"}}
```

The response will include `contents` with either `text` or a base64 `blob` depending on file type. Google Workspace native docs are exported to text/markdown or CSV as appropriate.

## Tools (optional)

This server exposes two simple tools via the MCP `tools` API:

- `gdrive_search` — input: `{ "query": "some text" }` — returns a short textual listing of matches.
- `gdrive_read_file` — input: `{ "file_id": "<FILE_ID>" }` — reads a file like `resources/read`.

Call tools using the `call_tool` JSON-RPC method (see the MCP types). Example `call_tool` body:

```json
{"jsonrpc":"2.0","id":"tool-1","method":"call_tool","params":{"name":"gdrive_search","arguments":{"query":"budget"}}}
```

## Notes and gotchas

- ngrok free tunnels sometimes show an interstitial (ERR_NGROK_6024) for browser-style GET requests (you might see this visiting `/health` in a browser). POST requests used by FlyerGPT are proxied correctly in my testing. To avoid the interstitial use a proper public deployment (Cloud Run) or restart the tunnel.
- Make sure the client sets the `Accept` header exactly as above — otherwise the SDK/server may not return the SSE stream format expected for streaming messages.
- Protect the endpoint: set `AUTH_BEARER_TOKEN` to a strong secret and supply it to FlyerGPT. For production, store the secret in Cloud Run Secret Manager or similar.
- If you deploy to Cloud Run, you can provide the OAuth client JSON and saved credentials via environment variables or Secrets; the server supports `GOOGLE_OAUTH_JSON` and `MCP_GDRIVE_CREDENTIALS_JSON` for this use.

## Quick checklist for FlyerGPT integration

- [ ] Ensure the MCP server is reachable (ngrok or Cloud Run URL).
- [ ] Configure `AUTH_BEARER_TOKEN` and give FlyerGPT the token.
- [ ] Use POST /mcp with the headers above and start with `resources/list`.
- [ ] Use the returned `uri` values and call `resources/read` to fetch file contents.

That's it — if you want, I can add a tiny example that converts an SSE response into a single JSON object (client-side) or add a short README section showing how to wire this into FlyerGPT's tool config.
FlyerGPT integration guide for gdrive-mcp-server-http
===============================================

This document explains how to connect FlyerGPT to the local/hosted MCP Streamable HTTP wrapper for Google Drive.

Required server behavior
- The MCP endpoint must be reachable over HTTPS (FlyerGPT requires HTTPS for external connections).
- The endpoint must accept the Streamable HTTP transport and JSON-RPC 2.0 method names used by the MCP SDK.

Recommended configuration
- Host the container or Node process behind a public HTTPS endpoint (Cloud Run is easiest). Alternatively use ngrok for short-lived testing.
- Protect the endpoint with a static bearer token. Set the environment variable `AUTH_BEARER_TOKEN` when starting the server.

Connection details to give FlyerGPT
- URL: https://your-host.example.com/mcp
- Headers:
  - Authorization: Bearer <AUTH_BEARER_TOKEN>
  - Accept: application/json, text/event-stream
  - Content-Type: application/json

Minimal JSON-RPC test body
```
{ "jsonrpc": "2.0", "id": "req-1", "method": "resources/list", "params": { "pageSize": 5 } }
```

Health check
- A `/health` endpoint is available for quick verification. It reports whether OAuth client JSON and saved credentials exist and performs a tiny Drive API list to verify access.
- Example (PowerShell):
```
Invoke-RestMethod -Uri http://localhost:3000/health -Method GET
```

Notes and troubleshooting
- Make sure the Google Drive API is enabled for the project that owns your OAuth client ID.
- Saved user credentials must include a `refresh_token` so the server can refresh access when tokens expire.
- The server enforces that client requests include Accept header with both `application/json` and `text/event-stream`.
- If you run behind a proxy, forward the `mcp-session-id` header and `Authorization` header through unchanged.

Deploy suggestions
- Cloud Run (Dockerfile present): build the Docker image, push to a registry, and create a Cloud Run service with HTTPS. Set `AUTH_BEARER_TOKEN` as a service environment variable.
- ngrok (quick test): run `ngrok http 3000` and use the HTTPS url it gives; good for short-lived tests.

If you'd like, I can prepare a Cloud Run deployment script or an ngrok quick-start snippet and test the deployed endpoint from here.
