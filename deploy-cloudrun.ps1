param(
  [string]$ProjectId,
  [string]$ServiceName = 'gdrive-mcp-http',
  [string]$Region = 'us-central1',
  [string]$ImageName = '',
  [string]$AuthToken = ''
)

if (-not $ProjectId) { Write-Error 'ProjectId is required (gcloud project id)'; exit 1 }
if (-not $ImageName) { $ImageName = "gcr.io/$ProjectId/$ServiceName" }
if (-not $AuthToken) { $AuthToken = Read-Host -Prompt 'Enter AUTH_BEARER_TOKEN to set on the service (will be required by clients)' }

Write-Output "Building and pushing image $ImageName..."
gcloud builds submit --tag $ImageName

Write-Output "Deploying to Cloud Run ($ServiceName) in $Region..."
gcloud run deploy $ServiceName --image $ImageName --platform managed --region $Region --allow-unauthenticated --project $ProjectId --update-env-vars "AUTH_BEARER_TOKEN=$AuthToken"

Write-Output 'Deployment complete. Run `gcloud run services describe <service> --platform managed --region <region> --project <project>` to get the URL.'

Write-Output 'Notes: For production, use Secret Manager and set the GOOGLE_OAUTH_JSON and MCP_GDRIVE_CREDENTIALS_JSON env vars from secrets instead of baking credentials into the image.'
