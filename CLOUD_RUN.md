Cloud Run deployment and Secret Manager notes
===========================================

This guide shows a simple way to build and deploy the `gdrive-mcp-server-http` Docker image to Cloud Run, and how to use Secret Manager to provide the OAuth client JSON and saved credentials securely.

Quick deploy (build & push & deploy)
-----------------------------------
1. Install and authenticate with the Google Cloud SDK (gcloud) and enable required APIs:

```powershell
gcloud auth login
gcloud config set project <PROJECT_ID>
gcloud services enable run.googleapis.com cloudbuild.googleapis.com secretmanager.googleapis.com
```

2. Build and deploy using the provided PowerShell helper:

```powershell
.\deploy-cloudrun.ps1 -ProjectId <PROJECT_ID> -ServiceName gdrive-mcp-http -Region us-central1
```

This script builds the image with Cloud Build, pushes to Container Registry, and deploys to Cloud Run with `AUTH_BEARER_TOKEN` set interactively.

Using Secret Manager (recommended)
----------------------------------
Instead of passing credential files into the container image or environment directly, use Secret Manager and inject secrets as environment variables into Cloud Run.

1. Create secrets:

```powershell
gcloud secrets create google-oauth-json --data-file="C:\path\to\gcp-oauth.keys.json" --project=<PROJECT_ID>
gcloud secrets create gdrive-saved-creds --data-file="C:\path\to\.gdrive-server-credentials.json" --project=<PROJECT_ID>
```

2. Grant Cloud Run service account access to the secrets (replace SERVICE_ACCOUNT with the Cloud Run runtime service account email):

```powershell
gcloud secrets add-iam-policy-binding google-oauth-json --member="serviceAccount:SERVICE_ACCOUNT" --role="roles/secretmanager.secretAccessor" --project=<PROJECT_ID>
gcloud secrets add-iam-policy-binding gdrive-saved-creds --member="serviceAccount:SERVICE_ACCOUNT" --role="roles/secretmanager.secretAccessor" --project=<PROJECT_ID>
```

3. Deploy and attach secrets as environment variables (Cloud Run supports referencing secrets as env vars):

```powershell
gcloud run deploy gdrive-mcp-http --image gcr.io/<PROJECT_ID>/gdrive-mcp-http --region us-central1 --platform managed --project <PROJECT_ID> --allow-unauthenticated \
  --set-secrets "GOOGLE_OAUTH_JSON=google-oauth-json:latest","MCP_GDRIVE_CREDENTIALS_JSON=gdrive-saved-creds:latest" \
  --set-env-vars "AUTH_BEARER_TOKEN=<your-token>"
```

4. Notes:
- The code in `index.js` looks for `GOOGLE_OAUTH_JSON` and `MCP_GDRIVE_CREDENTIALS_JSON` env vars and will write them to `/tmp` so the code can read them as files. This avoids baking secrets into the container image.
- For production, consider rotating tokens and using Secret Manager versions.

Post-deploy
-----------
- After deployment, Cloud Run will provide an HTTPS endpoint. Use that as the FlyerGPT MCP URL:
  - URL: https://<service>-<hash>-uc.a.run.app/mcp
  - Headers: Authorization: Bearer <AUTH_BEARER_TOKEN>, Accept: application/json, text/event-stream, Content-Type: application/json
- Verify `/health` at the service URL (e.g., https://.../health) to confirm credentials are accessible and Drive calls succeed.
