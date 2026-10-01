[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][guid]$TenantId,
    [Parameter(Mandatory = $true)][ValidateSet('Workforce', 'External')][string]$TenantKind,
    [Parameter(Mandatory = $true)][string]$App01BaseUrl,
    [Parameter(Mandatory = $true)][string]$App02BaseUrl,
    [string]$LocalApp01BaseUrl = 'https://localhost:44371',
    [string]$LocalApp02BaseUrl = 'https://localhost:44372',
    [string]$CiamDomain,
    [string]$StateDirectory = (Join-Path $env:LOCALAPPDATA 'MultiIdpPoC')
)
. (Join-Path $PSScriptRoot 'Poc.Common.ps1')

$roots = @((Get-PocHttpsRoot $App01BaseUrl), (Get-PocHttpsRoot $App02BaseUrl))
$localRoots = @((Get-PocHttpsRoot $LocalApp01BaseUrl), (Get-PocHttpsRoot $LocalApp02BaseUrl))
if (-not $PSCmdlet.ShouldProcess($TenantId.ToString(), 'Create or reconcile two owned PoC app registrations, baseline OIDC consent and assignment-required service principals')) { return }
$stateRoot = Get-PocStateDirectory $StateDirectory
$context = Get-PocGraphContext -TenantId $TenantId -TenantKind $TenantKind
if ($TenantKind -eq 'External' -and -not $CiamDomain) {
    $organization = @(Get-PocGraphCollection -Context $context -Path '/organization?$select=id,verifiedDomains')
    if ($organization.Count -ne 1 -or [guid]$organization[0].id -ne $TenantId) { throw 'Could not resolve the expected external tenant organization.' }
    $initialDomain = @($organization[0].verifiedDomains | Where-Object { $_.isInitial -and $_.name -like '*.onmicrosoft.com' })
    if ($initialDomain.Count -ne 1) { throw 'Specify CiamDomain; the initial external tenant domain was ambiguous.' }
    $CiamDomain = $initialDomain[0].name.Replace('.onmicrosoft.com', '.ciamlogin.com')
}
$metadata = Get-PocOidcMetadata -TenantId $TenantId -TenantKind $TenantKind -CiamDomain $CiamDomain
$manifestPath = Get-PocManifestPath -StateDirectory $stateRoot -TenantKind $TenantKind -TenantId $TenantId
$manifest = Read-PocJson $manifestPath
if ($manifest -and ($manifest.tenantId -ne $TenantId.ToString() -or $manifest.tenantKind -ne $TenantKind -or $manifest.ownerTag -ne 'multiidp-net48-poc-v1')) { throw 'Existing state manifest is not owned by this script and tenant.' }
if (-not $manifest) { $manifest = [pscustomobject]@{ ownerTag = 'multiidp-net48-poc-v1'; tenantId = $TenantId.ToString(); tenantKind = $TenantKind; issuer = $metadata.Issuer; ciamDomain = $CiamDomain; apps = @() } }
$manifest.issuer = $metadata.Issuer
$manifest.ciamDomain = $CiamDomain
$kind = $TenantKind.ToLowerInvariant()
$callback = if ($TenantKind -eq 'Workforce') { '/signin-workforce' } else { '/signin-external' }
$graphAppId = '00000003-0000-0000-c000-000000000000'
$oidcScopes = @(
    @{ id = '37f7f235-527c-4136-accd-4a02d197296e'; type = 'Scope' },
    @{ id = '14dad69e-099b-42c9-810b-d002981feec1'; type = 'Scope' },
    @{ id = '64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0'; type = 'Scope' },
    @{ id = '7427e0e9-d8d5-4f63-9bd6-7da6b56289c1'; type = 'Scope' }
)
$graphPrincipals = @(Get-PocGraphCollection -Context $context -Path ('/servicePrincipals?$filter=' + [uri]::EscapeDataString("appId eq '$graphAppId'") + '&$select=id'))
if ($graphPrincipals.Count -ne 1) { throw 'The Microsoft Graph service principal could not be uniquely resolved.' }

for ($index = 0; $index -lt 2; $index++) {
    $appId = 'sampleapp{0:d2}' -f ($index + 1)
    $displayName = $appId + '-net48-' + $kind
    $tags = @('multiidp-net48-poc-v1', $appId, $kind)
    $apps = @(Get-PocGraphCollection -Context $context -Path ('/applications?$filter=' + [uri]::EscapeDataString("displayName eq '$displayName'") + '&$select=id,appId,displayName,tags,appRoles,passwordCredentials'))
    if ($apps.Count -gt 1) { throw "Multiple registrations have the owned display name $displayName; no changes were made to those registrations." }
    $application = if ($apps.Count -eq 1) { $apps[0] } else { $null }
    if ($application -and (@($tags | Where-Object { $_ -notin $application.tags }).Count -ne 0)) { throw "Registration $displayName exists without all ownership tags; it will not be adopted." }
    $savedApp = @($manifest.apps | Where-Object { $_.appId -eq $appId })
    if ($savedApp.Count -gt 1) { throw "Duplicate state entries for $appId." }
    if ($savedApp.Count -eq 1 -and (-not $application -or $savedApp[0].applicationObjectId -ne $application.id -or $savedApp[0].clientId -ne $application.appId)) { throw "Live registration no longer matches saved state for $appId; refusing replacement." }
    $roleValues = if ($TenantKind -eq 'External') { @('Retiree', 'Dependent', 'External') } elseif ($appId -eq 'sampleapp02') { @('Employee', 'Partner', 'admin', 'dependentRegistrant') } else { @('Employee') }
    $roles = @()
    foreach ($value in $roleValues) {
        $existingRole = @(if ($application) { $application.appRoles | Where-Object { $_.value -eq $value } })
        if ($existingRole.Count -gt 1) { throw "Duplicate live role value $value in $displayName." }
        $roleId = if ($existingRole.Count -eq 1) { $existingRole[0].id } else { [guid]::NewGuid().ToString() }
        $roles += @{ id = $roleId; allowedMemberTypes = @('User'); description = "Approved $value access to $appId"; displayName = $value; isEnabled = $true; value = $value }
    }
    if ($application -and @($application.appRoles | Where-Object { $_.value -notin $roleValues }).Count -gt 0) { throw "Unexpected roles exist in $displayName; refusing to remove or overwrite them." }
    $redirectUris = @(($roots[$index] + $callback), ($localRoots[$index] + $callback)) | Select-Object -Unique
    $definition = @{ displayName = $displayName; tags = $tags; signInAudience = 'AzureADMyOrg'; appRoles = $roles; requiredResourceAccess = @(@{ resourceAppId = $graphAppId; resourceAccess = $oidcScopes }); web = @{ redirectUris = @($redirectUris); implicitGrantSettings = @{ enableAccessTokenIssuance = $false; enableIdTokenIssuance = $false } } }
    if ($TenantKind -eq 'Workforce') { $definition.optionalClaims = @{ idToken = @(@{ name = 'idp'; source = $null; essential = $false; additionalProperties = @() }) } }
    if ($application) { $null = Invoke-PocGraph -Context $context -Method PATCH -Path ('/applications/' + $application.id) -Body $definition }
    else { $application = Invoke-PocGraph -Context $context -Method POST -Path '/applications' -Body $definition }
    $principals = @(Get-PocGraphCollection -Context $context -Path ('/servicePrincipals?$filter=' + [uri]::EscapeDataString("appId eq '$($application.appId)'") + '&$select=id,appId,tags'))
    if ($principals.Count -gt 1) { throw "Multiple service principals exist for $displayName." }
    if ($principals.Count -eq 1) {
        $principal = $principals[0]
        if (@($tags | Where-Object { $_ -notin $principal.tags }).Count -ne 0) { throw "Existing service principal for $displayName is not tagged as owned." }
        $null = Invoke-PocGraph -Context $context -Method PATCH -Path ('/servicePrincipals/' + $principal.id) -Body @{ accountEnabled = $true; appRoleAssignmentRequired = $true }
    } else {
        $principal = Invoke-PocGraph -Context $context -Method POST -Path '/servicePrincipals' -Body @{ appId = $application.appId; tags = $tags; accountEnabled = $true; appRoleAssignmentRequired = $true }
    }
    $secretEnvironmentVariable = 'MULTIIDP_{0}_{1}_SECRET' -f $appId.ToUpperInvariant(), $TenantKind.ToUpperInvariant()
    $secretPath = Join-Path $stateRoot ('secrets\' + $secretEnvironmentVariable + '.clixml')
    if ($savedApp.Count -eq 1) {
        $record = $savedApp[0]
        if ($record.secretFile -ne $secretPath -or -not (Test-Path -LiteralPath $secretPath) -or $record.secretEnvironmentVariable -ne $secretEnvironmentVariable) { throw "Credential state is incomplete for $displayName; no credential will be rotated automatically." }
        $secureSecret = Import-Clixml -LiteralPath $secretPath
        if ($secureSecret -isnot [Security.SecureString]) { throw "DPAPI credential file has an unexpected type for $displayName." }
        if ([DateTimeOffset]$record.credentialExpiresUtc -le [DateTimeOffset]::UtcNow) { throw "Saved seven-day credential has expired for $displayName; rotate through an explicitly reviewed operation." }
        if (@($application.passwordCredentials | Where-Object { $_.keyId -eq $record.credentialId }).Count -ne 1) { throw "Saved credential is missing from $displayName; no replacement will be created automatically." }
    } else {
        if ((Test-Path -LiteralPath $secretPath) -or @($application.passwordCredentials).Count -gt 0) { throw "Existing credential material has no matching saved manifest for $displayName; refusing automatic rotation." }
        $expiresUtc = [DateTimeOffset]::UtcNow.AddDays(7)
        $credential = Invoke-PocGraph -Context $context -Method POST -Path ('/applications/' + $application.id + '/addPassword') -Body @{ passwordCredential = @{ displayName = 'multiidp-net48-poc-7day'; endDateTime = $expiresUtc.ToString('o') } }
        $secureSecret = ConvertTo-SecureString -String $credential.secretText -AsPlainText -Force
        $secureSecret | Export-Clixml -LiteralPath $secretPath
        $record = [pscustomobject]@{ appId = $appId; displayName = $displayName; applicationObjectId = $application.id; clientId = $application.appId; servicePrincipalId = $principal.id; secretEnvironmentVariable = $secretEnvironmentVariable; secretFile = $secretPath; credentialId = $credential.keyId; credentialExpiresUtc = $credential.endDateTime; redirectUri = ''; localRedirectUri = ''; roles = @() }
        $credential = $null
    }
    $record.servicePrincipalId = $principal.id
    $record.redirectUri = $roots[$index] + $callback
    $record.localRedirectUri = $localRoots[$index] + $callback
    $record.roles = @($roles | ForEach-Object { @{ id = $_.id; value = $_.value } })
    $manifest.apps = @($manifest.apps | Where-Object { $_.appId -ne $appId }) + @($record)
    Write-PocJson -Path $manifestPath -Value $manifest
    $grants = @(Get-PocGraphCollection -Context $context -Path ('/oauth2PermissionGrants?$filter=' + [uri]::EscapeDataString("clientId eq '$($principal.id)' and consentType eq 'AllPrincipals'") + '&$select=id,resourceId,scope'))
    $matchingGrant = @($grants | Where-Object { $_.resourceId -eq $graphPrincipals[0].id })
    if ($matchingGrant.Count -gt 1) { throw "Multiple baseline consent grants exist for $displayName." }
    $scopeText = 'openid profile email offline_access'
    if ($matchingGrant.Count -eq 1) {
        if (@($matchingGrant[0].scope.Split(' ') | Where-Object { $_ -and $_ -notin $scopeText.Split(' ') }).Count -gt 0) { throw "Unexpected delegated Graph privileges exist for $displayName; refusing to silently alter them." }
        $null = Invoke-PocGraph -Context $context -Method PATCH -Path ('/oauth2PermissionGrants/' + $matchingGrant[0].id) -Body @{ scope = $scopeText }
    } else {
        $null = Invoke-PocGraph -Context $context -Method POST -Path '/oauth2PermissionGrants' -Body @{ clientId = $principal.id; consentType = 'AllPrincipals'; resourceId = $graphPrincipals[0].id; scope = $scopeText }
    }
    Write-Host ("Configured {0}; assignment required; credential expires {1}." -f $displayName, $record.credentialExpiresUtc)
}
Write-Host ("Nonsecret manifest: {0}" -f $manifestPath)
