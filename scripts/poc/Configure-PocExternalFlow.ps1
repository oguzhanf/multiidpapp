[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][Guid]$TenantId, [string]$StateDirectory = (Join-Path $env:LOCALAPPDATA 'MultiIdpPoC'))
. (Join-Path $PSScriptRoot 'Poc.Common.ps1')
if (-not $PSCmdlet.ShouldProcess("$TenantId", 'Create sign-in-only email/password flow for the two owned External ID registrations')) { return }
$stateRoot = Get-PocStateDirectory $StateDirectory
$context = Get-PocGraphContext -TenantId $TenantId -TenantKind External
$manifest = Read-PocJson (Get-PocManifestPath -StateDirectory $stateRoot -TenantKind External -TenantId $TenantId)
if (-not $manifest -or $manifest.ownerTag -ne 'multiidp-net48-poc-v1' -or @($manifest.apps).Count -ne 2) { throw 'Configure the two external registrations first.' }
$name = 'MultiIdpNet48ControlledSignIn'
$flows = @(Get-PocGraphCollection -Context $context -Path '/identity/authenticationEventsFlows')
$existing = @($flows | Where-Object {$_.displayName -eq $name})
$setupState = Read-PocJson (Join-Path $stateRoot 'password-setup.json')
$flowApplications = @($manifest.apps | ForEach-Object {@{appId=$_.clientId}})
if ($setupState -and $setupState.tenantId -eq "$TenantId" -and $setupState.ownerTag -eq 'multiidp-net48-password-setup-v1') { $flowApplications += @{appId=$setupState.clientId} }
if ($existing.Count -gt 1) { throw 'Duplicate flow names. Resolve before making changes.' }
$body = @{
    '@odata.type'='#microsoft.graph.externalUsersSelfServiceSignUpEventsFlow'
    displayName=$name
    description='Registered PoC customer accounts only; application admission requires assignment and business entitlement.'
    conditions=@{applications=@{includeAllApplications=$false;includeApplications=$flowApplications}}
    onAuthenticationMethodLoadStart=@{'@odata.type'='#microsoft.graph.onAuthenticationMethodLoadStartExternalUsersSelfServiceSignUp';identityProviders=@(@{id='EmailPassword-OAUTH'})}
    onInteractiveAuthFlowStart=@{'@odata.type'='#microsoft.graph.onInteractiveAuthFlowStartExternalUsersSelfServiceSignUp';isSignUpAllowed=$false}
}
if ($existing.Count -eq 1) {
    $flowId = $existing[0].id
    $body.Remove('conditions')
    $null = Invoke-PocGraph -Context $context -Method PATCH -Path "/identity/authenticationEventsFlows/$flowId" -Body $body
} else {
    $created = Invoke-PocGraph -Context $context -Method POST -Path '/identity/authenticationEventsFlows' -Body $body
    $flowId = $created.id
}
$linked = @(Get-PocGraphCollection -Context $context -Path "/identity/authenticationEventsFlows/$flowId/conditions/applications/includeApplications" | ForEach-Object {$_.appId})
foreach ($target in $flowApplications) {
    if ($target.appId -notin $linked) { $null = Invoke-PocGraph -Context $context -Method POST -Path "/identity/authenticationEventsFlows/$flowId/conditions/applications/includeApplications" -Body @{appId=$target.appId} }
}
$after = Invoke-PocGraph -Context $context -Path "/identity/authenticationEventsFlows/$flowId"
if ($after.onInteractiveAuthFlowStart.isSignUpAllowed -ne $false) { throw 'Sign-up remains enabled; inspect before testing admission.' }
$associated = @($after.conditions.applications.includeApplications | ForEach-Object {$_.appId})
foreach ($app in $manifest.apps) { if ($app.clientId -notin $associated) { throw 'Application association failed verification.' } }
Write-PocJson -Path (Join-Path $stateRoot 'external-flow.json') -Value @{tenantId="$TenantId";flowId=$flowId;displayName=$name;isSignUpAllowed=$false;applications=$associated}
Write-Output 'External flow verified: email/password, sign-up disabled, both applications associated.'
