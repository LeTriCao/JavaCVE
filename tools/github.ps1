param([ValidateSet('Status','Release','Dispatch')][string]$Action='Status')
$ErrorActionPreference='Stop'
# Credentials remain only in process memory. Never write the credential output.
$credentialLines = "protocol=https`nhost=github.com`nusername=LeTriCao`n`n" | git credential fill
if ($LASTEXITCODE -ne 0) { throw 'GitHub credential lookup failed' }
$fields=@{}
foreach ($line in $credentialLines) { if ($line -match '^([^=]+)=(.*)$') { $fields[$matches[1]]=$matches[2] } }
if (-not $fields['password']) { throw 'No authenticated GitHub credential' }
$headers=@{Authorization=('Bearer '+$fields['password']); Accept='application/vnd.github+json'; 'X-GitHub-Api-Version'='2022-11-28'; 'User-Agent'='JavaCVE-release'}
$api='https://api.github.com/repos/LeTriCao/JavaCVE'
$owner=Invoke-RestMethod -Uri 'https://api.github.com/user' -Headers $headers
if ($owner.login -ne 'LeTriCao') { throw ('Wrong authenticated owner: '+$owner.login) }
$repository=Invoke-RestMethod -Uri $api -Headers $headers
if (-not $repository.private) { throw 'Expected private JavaCVE repository' }
if ($Action -eq 'Status') {
 $repository | Select-Object full_name,html_url,private,default_branch
 $workflowRuns=Invoke-RestMethod -Uri ($api+'/actions/runs?per_page=6') -Headers $headers
 $workflowRuns.workflow_runs | Select-Object id,head_sha,status,conclusion,html_url | Format-Table -AutoSize
 foreach ($workflow in ($workflowRuns.workflow_runs | Select-Object -First 2)) {
  Write-Output ('Jobs for workflow '+$workflow.id+' event='+$workflow.event)
  $jobs=Invoke-RestMethod -Uri ($api+'/actions/runs/'+$workflow.id+'/jobs') -Headers $headers
  $jobs.jobs | Select-Object name,status,conclusion,html_url | Format-Table -AutoSize
 }
} elseif ($Action -eq 'Dispatch') {
 Invoke-RestMethod -Method Post -Uri ($api+'/actions/workflows/verify.yml/dispatches') -Headers $headers -ContentType 'application/json' -Body '{"ref":"main"}' | Out-Null
 Write-Output 'Requested verify.yml including source security check on main.'
} else {
 $commit=(git rev-parse 'v0.2.0^{}').Trim()
 if ($LASTEXITCODE -ne 0) { throw 'Create and push v0.2.0 tag first' }
 $note=[IO.File]::ReadAllText((Join-Path $PSScriptRoot '../RELEASE_NOTES.md'))
 try { $release=Invoke-RestMethod -Uri ($api+'/releases/tags/v0.2.0') -Headers $headers } catch {
  if ([int]$_.Exception.Response.StatusCode -ne 404) { throw }
  $body=@{tag_name='v0.2.0'; target_commitish=$commit; name='JavaCVE v0.2.0'; body=$note; draft=$false; prerelease=$false} | ConvertTo-Json
  $release=Invoke-RestMethod -Method Post -Uri ($api+'/releases') -Headers $headers -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body))
 }
 foreach ($name in @('JavaCVE-v0.2.0.zip','SHA256SUMS.txt','JavaCVE-v0.2.0-report.docx')) {
  $path=Join-Path $PSScriptRoot ('../dist/'+$name)
  if (-not (Test-Path -LiteralPath $path)) { throw ('Missing release asset: '+$name) }
  $existing=@($release.assets | Where-Object { $_.name -eq $name })
  if ($existing.Count -eq 0) {
   $url=$release.upload_url.Split('{')[0]+'?name='+[Uri]::EscapeDataString($name)
   $asset=Invoke-RestMethod -Method Post -Uri $url -Headers $headers -ContentType 'application/octet-stream' -InFile $path
   $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
   if ($asset.digest -and $asset.digest -ne ('sha256:'+$hash)) { throw ('Uploaded asset digest differs: '+$name) }
   Write-Output ('Uploaded '+$asset.name+' bytes='+$asset.size)
  } else { Write-Output ('Existing release asset retained: '+$name) }
 }
 Write-Output $release.html_url
 Write-Output ('Tag commit: '+$commit)
}
