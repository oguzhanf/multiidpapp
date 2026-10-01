[CmdletBinding()]
param([Parameter(Mandatory)][guid]$TenantId, [string]$StateDirectory=(Join-Path $env:LOCALAPPDATA 'MultiIdpPoC'))
. (Join-Path $PSScriptRoot 'Poc.Common.ps1')
$stateRoot=Get-PocStateDirectory $StateDirectory
$context=Get-PocGraphContext -TenantId $TenantId -TenantKind External
$flowState=Read-PocJson (Join-Path $stateRoot 'external-flow.json')
if (-not $flowState -or $flowState.tenantId -ne "$TenantId") { throw 'Configure the tenant-bound external flow first.' }
$flow=Invoke-PocGraph $context ('/identity/authenticationEventsFlows/'+$flowState.flowId)
if ($flow.onInteractiveAuthFlowStart.isSignUpAllowed -ne $false) { throw 'Expected invitation-only directory provisioning with public signup disabled.' }
$name='MultiIdp Net48 invitation password setup'
$tag='multiidp-net48-password-setup-v1'
$existing=@(Get-PocGraphCollection $context ('/applications?$filter='+[uri]::EscapeDataString("displayName eq '$name'")))
if ($existing.Count -gt 1 -or ($existing.Count -eq 1 -and $tag -notin $existing[0].tags)) { throw 'Password setup application ownership is ambiguous.' }
$definition=@{displayName=$name;tags=@($tag);signInAudience='AzureADMyOrg';isFallbackPublicClient=$true;nativeAuthenticationApisEnabled='all';requiredResourceAccess=@();web=@{redirectUris=@();implicitGrantSettings=@{enableIdTokenIssuance=$false;enableAccessTokenIssuance=$false}}}
if ($existing.Count -eq 0) { $application=Invoke-PocGraph $context '/applications' -Method POST -Body $definition }
else { $application=$existing[0]; $null=Invoke-PocGraph $context ('/applications/'+$application.id) -Method PATCH -Body $definition }
$principals=@(Get-PocGraphCollection $context ("/servicePrincipals?`$filter=appId eq '$($application.appId)'"))
if ($principals.Count -gt 1) { throw 'Duplicate setup service principals.' }
if ($principals.Count -eq 0) { $principal=Invoke-PocGraph $context '/servicePrincipals' -Method POST -Body @{appId=$application.appId;tags=@($tag);accountEnabled=$true} }
else { $principal=$principals[0]; if ($tag -notin $principal.tags) { throw 'Setup service principal ownership mismatch.' } }
$associated=@($flow.conditions.applications.includeApplications | ForEach-Object {$_.appId})
if ($application.appId -notin $associated) { $null=Invoke-PocGraph $context ('/identity/authenticationEventsFlows/'+$flow.id+'/conditions/applications/includeApplications') -Method POST -Body @{appId=$application.appId} }
$after=Invoke-PocGraph $context ('/applications/'+$application.id+'?$select=appId,nativeAuthenticationApisEnabled,isFallbackPublicClient,requiredResourceAccess')
$afterFlow=Invoke-PocGraph $context ('/identity/authenticationEventsFlows/'+$flow.id)
if ($after.nativeAuthenticationApisEnabled -ne 'all' -or $after.isFallbackPublicClient -ne $true -or @($after.requiredResourceAccess).Count -ne 0 -or $afterFlow.onInteractiveAuthFlowStart.isSignUpAllowed -ne $false) { throw 'Setup registration verification failed.' }
Write-PocJson (Join-Path $stateRoot 'password-setup.json') @{tenantId="$TenantId";ownerTag=$tag;clientId=$application.appId;applicationObjectId=$application.id;servicePrincipalId=$principal.id;flowId=$flow.id}
foreach($appId in @('sampleapp01','sampleapp02')) {
    $path=Join-Path $stateRoot "configuration\$appId.registration.json"
    $config=Read-PocJson $path
    if ($config.external.tenantId -ne "$TenantId") { throw 'Registration tenant mismatch.' }
    $config.external|Add-Member -NotePropertyName passwordSetupClientId -NotePropertyValue $application.appId -Force
    Write-PocJson $path $config
}
Write-Output 'Invitation password setup configured. Separate native client; no API permissions; public signup remains disabled.'
