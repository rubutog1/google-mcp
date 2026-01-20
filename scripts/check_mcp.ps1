param(
  [string]$BaseUrl = 'http://localhost:3000',
  [string]$Token = 'changeme'
)

Write-Output "Checking $BaseUrl/health ..."
try {
  $hdr = @{}
  if ($Token) { $hdr['Authorization'] = "Bearer $Token" }
  $h = Invoke-RestMethod -Uri "$BaseUrl/health" -Method Get -Headers $hdr -ErrorAction Stop
  $h | ConvertTo-Json -Depth 5
} catch {
  Write-Output "Health error: $_"
}

Write-Output "\nPosting resources/list to $BaseUrl/mcp ..."
$body = '{"jsonrpc":"2.0","id":"req-1","method":"resources/list","params":{"pageSize":5}}'
try {
  $hdr = @{ 'Accept' = 'application/json, text/event-stream'; 'Content-Type' = 'application/json' }
  if ($Token) { $hdr['Authorization'] = "Bearer $Token" }
  $r = Invoke-WebRequest -Uri "$BaseUrl/mcp" -Method Post -Body $body -ContentType 'application/json' -Headers $hdr -ErrorAction Stop
  Write-Output "Status: $($r.StatusCode)"
  Write-Output "Content:"; Write-Output $r.Content
} catch {
  Write-Output "POST error: $_"
}
