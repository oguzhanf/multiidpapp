[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [Parameter(Mandatory)][guid]$WorkforceTenantId,
    [Parameter(Mandatory)][guid]$AllowedUserObjectId,
    [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9-]*pocdriver[a-zA-Z0-9-]*$')][string]$SiteName,
    [string]$ResourceGroup = 'rg-caldova-multiidp-poc',
    [string]$StateDirectory = (Join-Path $env:LOCALAPPDATA 'MultiIdpPoC')
)
. (Join-Path $PSScriptRoot 'Poc.Common.ps1')
if ($SubscriptionId -eq [guid]::Empty -or $WorkforceTenantId -eq [guid]::Empty -or $AllowedUserObjectId -eq [guid]::Empty) { throw 'Nonempty subscription, workforce tenant and allowed user GUIDs are required.' }
if ($SiteName.Length -gt 60 -or $ResourceGroup -notmatch '^[a-zA-Z0-9_.()-]{1,90}$') { throw 'Invalid driver site or resource group name.' }
if (-not $PSCmdlet.ShouldProcess($SiteName, 'Configure driver-only authentication with one explicit workforce user')) { return }
$stateRoot = Get-PocStateDirectory $StateDirectory
$context = Get-PocGraphContext -TenantId $WorkforceTenantId -TenantKind Workforce
$account = (& az account show --subscription $SubscriptionId.ToString() --output json --only-show-errors) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or [guid]$account.id -ne $SubscriptionId -or [guid]$account.tenantId -ne $WorkforceTenantId -or $account.state -ne 'Enabled') { throw 'Hosting subscription is not enabled in the expected workforce tenant.' }
$armToken = (& az account get-access-token --subscription $SubscriptionId.ToString() --resource-type arm --query accessToken --output tsv --only-show-errors 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not $armToken) { throw 'Could not acquire an ARM token for the explicit subscription.' }
$armClaims = ConvertFrom-PocJwtPayload $armToken
if ([guid]$armClaims.tid -ne $WorkforceTenantId -or [guid]$armClaims.oid -ne $context.UserObjectId -or -not $armClaims.PSObject.Properties['scp']) { throw 'ARM token must belong to the same delegated administrator and workforce tenant.' }
$armHeaders = @{ Authorization = 'Bearer ' + $armToken }
$armToken = $null
$siteResourcePath = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Web/sites/{2}' -f $SubscriptionId, $ResourceGroup, $SiteName
function Invoke-DriverArm {
    param([string]$Suffix, [ValidateSet('GET','PUT')][string]$Method = 'GET', [object]$Body)
    $arguments = @{ Uri = 'https://management.azure.com' + $siteResourcePath + $Suffix + '?api-version=2024-11-01'; Method = $Method; Headers = $armHeaders; ErrorAction = 'Stop' }
    if ($null -ne $Body) { $arguments.ContentType = 'application/json'; $arguments.Body = ConvertTo-Json -InputObject $Body -Depth 30 -Compress }
    try { Invoke-RestMethod @arguments }
    catch { $status = 'unknown'; if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }; throw "Driver ARM $Method failed with HTTP $status. Request bodies and credentials are not logged." }
}
$site = Invoke-DriverArm -Suffix ''
if ($site.id -ne $siteResourcePath -or -not $site.tags.PSObject.Properties['purpose'] -or $site.tags.purpose -ne 'multiidp-poc') { throw 'The explicit driver site is not tagged as this PoC; refusing to adopt it.' }
$baseUrl = Get-PocHttpsRoot ('https://' + $site.properties.defaultHostName)
if (([uri]$baseUrl).Host -notlike '*.azurewebsites.net') { throw 'Unexpected App Service default hostname.' }
$redirectUri = $baseUrl + '/.auth/login/aad/callback'
$allowedUser = Invoke-PocGraph -Context $context -Path ('/users/' + $AllowedUserObjectId + '?$select=id,userType,accountEnabled')
if ([guid]$allowedUser.id -ne $AllowedUserObjectId -or $allowedUser.userType -ne 'Member' -or -not $allowedUser.accountEnabled) { throw 'Driver access requires the explicitly supplied enabled workforce Member; guests are refused.' }

$ownerTag = 'multiidp-net48-poc-v1'
$tags = @($ownerTag, 'pocdriver', 'workforce', ('site:' + $SiteName))
$displayName = $SiteName + '-easyauth-workforce'
$manifestPath = Join-Path $stateRoot ('manifests\driver-auth-' + $WorkforceTenantId + '-' + $SiteName + '.json')
$manifest = Read-PocJson $manifestPath
if ($manifest -and ($manifest.ownerTag -ne $ownerTag -or $manifest.tenantId -ne $WorkforceTenantId.ToString() -or $manifest.subscriptionId -ne $SubscriptionId.ToString() -or $manifest.siteName -ne $SiteName -or $manifest.resourceGroup -ne $ResourceGroup -or $manifest.allowedUserObjectId -ne $AllowedUserObjectId.ToString())) { throw 'Saved driver state has a different owner, tenant, site or allowed identity; refusing implicit changes.' }
$apps = @(Get-PocGraphCollection -Context $context -Path ('/applications?$filter=' + [uri]::EscapeDataString("displayName eq '$displayName'") + '&$select=id,appId,tags,appRoles,passwordCredentials,requiredResourceAccess'))
if ($apps.Count -gt 1) { throw 'Driver app registration display name is ambiguous.' }
$application = if ($apps.Count -eq 1) { $apps[0] } else { $null }
if ($application -and @($tags | Where-Object { $_ -notin @($application.tags) }).Count -gt 0) { throw 'An unowned driver registration will not be adopted.' }
if ($manifest -and (-not $application -or $manifest.applicationObjectId -ne $application.id -or $manifest.clientId -ne $application.appId)) { throw 'Saved registration no longer matches the live driver app.' }
$graphAppId = '00000003-0000-0000-c000-000000000000'
$scopeIds = @('37f7f235-527c-4136-accd-4a02d197296e','14dad69e-099b-42c9-810b-d002981feec1','64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0')
if ($application) {
    foreach ($resource in @($application.requiredResourceAccess)) {
        if ($resource.resourceAppId -ne $graphAppId -or @($resource.resourceAccess | Where-Object { $_.type -ne 'Scope' -or $_.id -notin $scopeIds }).Count -gt 0) { throw 'Unexpected API privileges exist on the owned driver registration.' }
    }
}
$existingRoles = @(if ($application) { $application.appRoles | Where-Object { $_.value -eq 'DriverAccess' } })
if ($existingRoles.Count -gt 1 -or ($application -and @($application.appRoles | Where-Object { $_.value -ne 'DriverAccess' }).Count -gt 0)) { throw 'Unexpected app roles exist on the driver registration.' }
$roleId = if ($existingRoles.Count -eq 1) { [string]$existingRoles[0].id } else { [guid]::NewGuid().ToString() }
$definition = @{
    displayName = $displayName; tags = $tags; signInAudience = 'AzureADMyOrg'
    appRoles = @(@{ id = $roleId; allowedMemberTypes = @('User'); description = 'Approved operator access to the PoC driver'; displayName = 'DriverAccess'; isEnabled = $true; value = 'DriverAccess' })
    requiredResourceAccess = @(@{ resourceAppId = $graphAppId; resourceAccess = @($scopeIds | ForEach-Object { @{ id = $_; type = 'Scope' } }) })
    # Easy Auth's confidential browser sign-in uses code + id_token (hybrid).
    # This applies only to the driver; the separate MSAL samples use pure code flow.
    web = @{ redirectUris = @($redirectUri); implicitGrantSettings = @{ enableAccessTokenIssuance = $false; enableIdTokenIssuance = $true } }
}
if ($application) { $null = Invoke-PocGraph -Context $context -Method PATCH -Path ('/applications/' + $application.id) -Body $definition }
else { $application = Invoke-PocGraph -Context $context -Method POST -Path '/applications' -Body $definition }
$owners = @(Get-PocGraphCollection -Context $context -Path ('/applications/' + $application.id + '/owners?$select=id'))
if ($context.UserObjectId.ToString() -notin @($owners | ForEach-Object { $_.id })) { $null = Invoke-PocGraph -Context $context -Method POST -Path ('/applications/' + $application.id + '/owners/$ref') -Body @{ '@odata.id' = ('https://graph.microsoft.com/v1.0/directoryObjects/' + $context.UserObjectId) } }
$principals = @(Get-PocGraphCollection -Context $context -Path ('/servicePrincipals?$filter=' + [uri]::EscapeDataString("appId eq '$($application.appId)'") + '&$select=id,appId,tags'))
if ($principals.Count -gt 1) { throw 'Driver service principal is ambiguous.' }
if ($principals.Count -eq 1) {
    $principal = $principals[0]
    if (@($tags | Where-Object { $_ -notin @($principal.tags) }).Count -gt 0) { throw 'An unowned driver service principal will not be adopted.' }
    if ($manifest -and $manifest.servicePrincipalId -ne $principal.id) { throw 'Saved driver service principal does not match the live object.' }
    $null = Invoke-PocGraph -Context $context -Method PATCH -Path ('/servicePrincipals/' + $principal.id) -Body @{ accountEnabled = $true; appRoleAssignmentRequired = $true }
} else { $principal = Invoke-PocGraph -Context $context -Method POST -Path '/servicePrincipals' -Body @{ appId = $application.appId; tags = $tags; accountEnabled = $true; appRoleAssignmentRequired = $true } }
$secretSettingName = 'MULTIIDP_POC_DRIVER_SECRET'
$secretPath = Join-Path $stateRoot ('secrets\driver-' + $WorkforceTenantId + '-' + $SiteName + '.clixml')
if ($manifest) {
    if ($manifest.secretFile -ne $secretPath -or $manifest.secretSettingName -ne $secretSettingName -or -not (Test-Path -LiteralPath $secretPath)) { throw 'Saved driver credential state is incomplete; no automatic rotation.' }
    $secureSecret = Import-Clixml -LiteralPath $secretPath
    if ($secureSecret -isnot [Security.SecureString] -or [DateTimeOffset]$manifest.credentialExpiresUtc -le [DateTimeOffset]::UtcNow -or @($application.passwordCredentials | Where-Object { $_.keyId -eq $manifest.credentialId }).Count -ne 1) { throw 'Saved driver credential is missing, expired or invalid; no automatic replacement.' }
} else {
    if ((Test-Path -LiteralPath $secretPath) -or @($application.passwordCredentials | Where-Object { $_ }).Count -gt 0) { throw 'Untracked driver credentials exist; no automatic adoption or rotation.' }
    $credential = Invoke-PocGraph -Context $context -Method POST -Path ('/applications/' + $application.id + '/addPassword') -Body @{ passwordCredential = @{ displayName = 'multiidp-poc-driver-7day'; endDateTime = [DateTimeOffset]::UtcNow.AddDays(7).ToString('o') } }
    $secureSecret = ConvertTo-SecureString -String $credential.secretText -AsPlainText -Force
    $secureSecret | Export-Clixml -LiteralPath $secretPath
    $manifest = [pscustomobject]@{ ownerTag = $ownerTag; tenantId = $WorkforceTenantId.ToString(); subscriptionId = $SubscriptionId.ToString(); resourceGroup = $ResourceGroup; siteName = $SiteName; allowedUserObjectId = $AllowedUserObjectId.ToString(); applicationObjectId = $application.id; clientId = $application.appId; servicePrincipalId = $principal.id; roleId = $roleId; secretFile = $secretPath; secretSettingName = $secretSettingName; credentialId = $credential.keyId; credentialExpiresUtc = $credential.endDateTime; redirectUri = $redirectUri; originalAuthSettingsFile = ''; authSettingsFile = ''; verificationFile = ''; status = 'Prepared' }
    $credential = $null
    Write-PocJson -Path $manifestPath -Value $manifest
}
$assignments = @(Get-PocGraphCollection -Context $context -Path ('/servicePrincipals/' + $principal.id + '/appRoleAssignedTo'))
if (@($assignments | Where-Object { $_.principalId -ne $AllowedUserObjectId.ToString() -or $_.appRoleId -ne $roleId }).Count -gt 0) { throw 'Unexpected driver assignments exist; refusing to silently broaden or remove them.' }
$matchingAssignment = @($assignments | Where-Object { $_.principalId -eq $AllowedUserObjectId.ToString() -and $_.appRoleId -eq $roleId })
if ($matchingAssignment.Count -gt 1) { throw 'Driver role assignment is ambiguous.' }
if ($matchingAssignment.Count -eq 0) { $null = Invoke-PocGraph -Context $context -Method POST -Path ('/servicePrincipals/' + $principal.id + '/appRoleAssignedTo') -Body @{ principalId = $AllowedUserObjectId.ToString(); resourceId = $principal.id; appRoleId = $roleId } }
$graphPrincipals = @(Get-PocGraphCollection -Context $context -Path ('/servicePrincipals?$filter=' + [uri]::EscapeDataString("appId eq '$graphAppId'") + '&$select=id'))
if ($graphPrincipals.Count -ne 1) { throw 'Microsoft Graph service principal is ambiguous.' }
$grants = @(Get-PocGraphCollection -Context $context -Path ('/oauth2PermissionGrants?$filter=' + [uri]::EscapeDataString("clientId eq '$($principal.id)' and consentType eq 'AllPrincipals'") + '&$select=id,resourceId,scope'))
if (@($grants | Where-Object { $_.resourceId -ne $graphPrincipals[0].id -or @(([string]$_.scope).Split(' ') | Where-Object { $_ -and $_ -notin @('openid','profile','email') }).Count -gt 0 }).Count -gt 0 -or $grants.Count -gt 1) { throw 'Unexpected delegated consent exists on the driver service principal.' }
if ($grants.Count -eq 1) { $null = Invoke-PocGraph -Context $context -Method PATCH -Path ('/oauth2PermissionGrants/' + $grants[0].id) -Body @{ scope = 'openid profile email' } }
else { $null = Invoke-PocGraph -Context $context -Method POST -Path '/oauth2PermissionGrants' -Body @{ clientId = $principal.id; consentType = 'AllPrincipals'; resourceId = $graphPrincipals[0].id; scope = 'openid profile email' } }

$diagnosticsRoot = Join-Path $stateRoot 'diagnostics'
$null = New-Item -ItemType Directory -Path $diagnosticsRoot -Force
$originalPath = Join-Path $diagnosticsRoot ('driver-' + $SiteName + '-authsettings-original.json')
if (-not (Test-Path -LiteralPath $originalPath)) { Write-PocJson -Path $originalPath -Value (Invoke-DriverArm -Suffix '/config/authsettingsV2') }
$authSettings = @{ properties = @{
    platform = @{ enabled = $true; runtimeVersion = '~1' }
    globalValidation = @{ requireAuthentication = $true; unauthenticatedClientAction = 'RedirectToLoginPage'; redirectToProvider = 'azureActiveDirectory'; excludedPaths = @() }
    identityProviders = @{ azureActiveDirectory = @{
        enabled = $true
        registration = @{ clientId = $application.appId; clientSecretSettingName = $secretSettingName; openIdIssuer = ('https://login.microsoftonline.com/' + $WorkforceTenantId + '/v2.0') }
        login = @{ loginParameters = @('scope=openid profile email') }
        validation = @{ allowedAudiences = @($application.appId); defaultAuthorizationPolicy = @{ allowedApplications = @($application.appId); allowedPrincipals = @{ identities = @($AllowedUserObjectId.ToString()) } } }
    }
        apple = @{ enabled = $false }
        facebook = @{ enabled = $false }
        gitHub = @{ enabled = $false }
        google = @{ enabled = $false }
        legacyMicrosoftAccount = @{ enabled = $false }
        twitter = @{ enabled = $false }
        customOpenIdConnectProviders = @{}
    }
    login = @{ tokenStore = @{ enabled = $false } }
    httpSettings = @{ requireHttps = $true }
} }
$authSettingsPath = Join-Path $diagnosticsRoot ('driver-' + $SiteName + '-authsettings-request.json')
Write-PocJson -Path $authSettingsPath -Value $authSettings
$temporarySettingsPath = Join-Path $stateRoot ('driver-' + $SiteName + '-appsettings.tmp.json')
if (Test-Path -LiteralPath $temporarySettingsPath) { throw 'A previous private appsettings temporary file exists; inspect it before retrying.' }
try {
    $settings = @{ $secretSettingName = [Net.NetworkCredential]::new('', $secureSecret).Password; WEBSITE_AUTH_AAD_ALLOWED_TENANTS = $WorkforceTenantId.ToString() }
    Write-PocJson -Path $temporarySettingsPath -Value $settings
    & az webapp config appsettings set --subscription $SubscriptionId.ToString() --resource-group $ResourceGroup --name $SiteName --slot-settings "@$temporarySettingsPath" --output none --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw 'Driver secret appsetting update failed; values are not logged.' }
} finally {
    $settings = $null
    if (Test-Path -LiteralPath $temporarySettingsPath) { Remove-Item -LiteralPath $temporarySettingsPath -Force }
}
$null = Invoke-DriverArm -Suffix '/config/authsettingsV2' -Method PUT -Body $authSettings
$readback = Invoke-DriverArm -Suffix '/config/authsettingsV2'
$verificationPath = Join-Path $diagnosticsRoot ('driver-' + $SiteName + '-authsettings-readback.json')
Write-PocJson -Path $verificationPath -Value $readback
$properties = $readback.properties
$aad = $properties.identityProviders.azureActiveDirectory
$authorization = $aad.validation.defaultAuthorizationPolicy
$allowedGroups = @(if ($authorization.allowedPrincipals.PSObject.Properties['groups']) { $authorization.allowedPrincipals.groups | Where-Object { $_ } })
$otherEnabledProviders = @($properties.identityProviders.PSObject.Properties | Where-Object { $_.Name -notin @('azureActiveDirectory','customOpenIdConnectProviders') -and $_.Value -and $_.Value.PSObject.Properties['enabled'] -and $_.Value.enabled })
if ($properties.identityProviders.PSObject.Properties['customOpenIdConnectProviders'] -and $properties.identityProviders.customOpenIdConnectProviders) {
    $otherEnabledProviders += @($properties.identityProviders.customOpenIdConnectProviders.PSObject.Properties | Where-Object { $_.Value -and $_.Value.PSObject.Properties['enabled'] -and $_.Value.enabled })
}
if ($otherEnabledProviders.Count -gt 0 -or ($properties.platform.PSObject.Properties['configFilePath'] -and $properties.platform.configFilePath)) { throw 'Unexpected enabled identity provider or file-based authentication override remains; inspect private readback before claiming the driver is protected.' }
if (-not $properties.platform.enabled -or -not $properties.globalValidation.requireAuthentication -or $properties.globalValidation.unauthenticatedClientAction -ne 'RedirectToLoginPage' -or $properties.globalValidation.redirectToProvider -ne 'azureActiveDirectory' -or @($properties.globalValidation.excludedPaths | Where-Object { $_ }).Count -ne 0 -or -not $properties.httpSettings.requireHttps -or -not $aad.enabled -or $aad.registration.clientId -ne $application.appId -or $aad.registration.openIdIssuer -ne $authSettings.properties.identityProviders.azureActiveDirectory.registration.openIdIssuer -or $aad.registration.clientSecretSettingName -ne $secretSettingName -or @($authorization.allowedPrincipals.identities).Count -ne 1 -or $authorization.allowedPrincipals.identities[0] -ne $AllowedUserObjectId.ToString() -or $allowedGroups.Count -ne 0 -or @($authorization.allowedApplications).Count -ne 1 -or $authorization.allowedApplications[0] -ne $application.appId -or @($aad.validation.allowedAudiences).Count -ne 1 -or $aad.validation.allowedAudiences[0] -ne $application.appId) { throw 'Driver authentication readback did not preserve the exact all-path, tenant-bound single-identity policy. Inspect private diagnostics; no anonymous exceptions will be added.' }
$liveApp = Invoke-PocGraph -Context $context -Path ('/applications/' + $application.id + '?$select=id,appId,signInAudience,web,requiredResourceAccess')
$livePrincipal = Invoke-PocGraph -Context $context -Path ('/servicePrincipals/' + $principal.id + '?$select=id,accountEnabled,appRoleAssignmentRequired')
$liveAssignments = @(Get-PocGraphCollection -Context $context -Path ('/servicePrincipals/' + $principal.id + '/appRoleAssignedTo'))
if ($liveApp.signInAudience -ne 'AzureADMyOrg' -or -not $liveApp.web.implicitGrantSettings.enableIdTokenIssuance -or $liveApp.web.implicitGrantSettings.enableAccessTokenIssuance -or @($liveApp.web.redirectUris).Count -ne 1 -or $liveApp.web.redirectUris[0] -ne $redirectUri -or -not $livePrincipal.accountEnabled -or -not $livePrincipal.appRoleAssignmentRequired -or $liveAssignments.Count -ne 1 -or $liveAssignments[0].principalId -ne $AllowedUserObjectId.ToString() -or $liveAssignments[0].appRoleId -ne $roleId) { throw 'Driver app or assignment readback failed.' }
$manifest.originalAuthSettingsFile = $originalPath; $manifest.authSettingsFile = $authSettingsPath; $manifest.verificationFile = $verificationPath; $manifest.status = 'Configured'
Write-PocJson -Path $manifestPath -Value $manifest
$secureSecret = $null; $armHeaders = $null
Write-Output 'Driver gate configured and control-plane readback verified. Run anonymous/spoofed-header checks and operator sign-in before claiming access tests passed.'
