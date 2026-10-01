[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [Parameter(Mandatory)][guid]$WorkforceTenantId,
    [Parameter(Mandatory)][guid]$ExternalTenantId,
    [string]$ResourceGroup = 'rg-caldova-multiidp-poc',
    [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9-]{1,24}$')][string]$NameSuffix,
    [string]$App01SiteName,
    [string]$App02SiteName,
    [guid]$AllowedOperatorObjectId = [guid]::Empty,
    [guid[]]$DependentRegistrantObjectIds = @(),
    [DateTimeOffset]$ApprovalLimitUtc = [DateTimeOffset]::MinValue,
    [switch]$EnableExternalEmailPasswordReset,
    [switch]$UseMicrosoftGraphPolicyContext,
    [string]$StateDirectory = (Join-Path $env:LOCALAPPDATA 'MultiIdpPoC')
)
. (Join-Path $PSScriptRoot 'Poc.Common.ps1')
if ($SubscriptionId -eq [guid]::Empty -or $WorkforceTenantId -eq [guid]::Empty -or $ExternalTenantId -eq [guid]::Empty -or $WorkforceTenantId -eq $ExternalTenantId) { throw 'Distinct nonempty workforce/external tenant IDs and a subscription are required.' }
if ($ResourceGroup -notmatch '^[a-zA-Z0-9_.()-]{1,90}$') { throw 'Invalid resource group.' }
if (-not $App01SiteName) { $App01SiteName = 'caldova-sampleapp01-' + $NameSuffix }
if (-not $App02SiteName) { $App02SiteName = 'caldova-sampleapp02-' + $NameSuffix }
if ($App01SiteName -notmatch '^[a-zA-Z0-9-]{1,60}$' -or $App02SiteName -notmatch '^[a-zA-Z0-9-]{1,60}$' -or $App01SiteName -eq $App02SiteName) { throw 'Distinct valid sample site names are required.' }
if (-not $PSCmdlet.ShouldProcess($ResourceGroup, 'Configure owned registration services, sample managed identities, mail scope and selected member capabilities')) { return }
$stateRoot = Get-PocStateDirectory $StateDirectory
$ownerTag = 'multiidp-net48-poc-v1'
$workforce = Get-PocGraphContext -TenantId $WorkforceTenantId -TenantKind Workforce
$external = Get-PocGraphContext -TenantId $ExternalTenantId -TenantKind External
function Assert-RegistrationPolicyContext {
    param([hashtable]$ExpectedContext)
    if (-not (Get-Command Get-MgContext -ErrorAction SilentlyContinue) -or -not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) { throw 'Microsoft.Graph.Authentication is required for the delegated policy session.' }
    $session = Get-MgContext
    if (-not $session -or $session.AuthType -ne 'Delegated' -or [guid]$session.TenantId -ne [guid]$ExpectedContext.TenantId -or 'Policy.ReadWrite.AuthenticationMethod' -notin @($session.Scopes) -or $session.ContextScope -ne 'Process') { throw 'Connect-MgGraph to the External tenant with delegated Policy.ReadWrite.AuthenticationMethod,User.Read and ContextScope Process before using the policy session.' }
    try { $operator = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/me?$select=id' -OutputType PSObject -ErrorAction Stop }
    catch { throw 'The delegated Microsoft Graph policy session cannot identify its operator. Reconnect with User.Read; response details are not logged.' }
    if (-not $operator -or [guid]$operator.id -ne [guid]$ExpectedContext.UserObjectId) { throw 'Policy session operator differs from the delegated External setup administrator.' }
}
if ($UseMicrosoftGraphPolicyContext) { Assert-RegistrationPolicyContext $external }
function Invoke-RegistrationEmailPolicy {
    param([ValidateSet('GET','PATCH')][string]$Method = 'GET', [object]$Body)
    $path = '/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/Email'
    if ($UseMicrosoftGraphPolicyContext) {
        Assert-RegistrationPolicyContext $external
        $arguments = @{ Method = $Method; Uri = ('https://graph.microsoft.com/v1.0' + $path); OutputType = 'PSObject'; ErrorAction = 'Stop' }
        if ($null -ne $Body) { $arguments.Body = ConvertTo-Json -InputObject $Body -Depth 20 -Compress; $arguments.ContentType = 'application/json' }
        try { Invoke-MgGraphRequest @arguments }
        catch { throw 'External Email OTP policy request failed in the bound delegated Microsoft Graph session. Verify the authentication-policy scope and administrator role; response details are not logged.' }
    } else {
        try { Invoke-PocGraph -Context $external -Method $Method -Path $path -Body $Body }
        catch { throw 'External Email OTP policy request failed. Azure CLI may lack Policy.ReadWrite.AuthenticationMethod. Connect-MgGraph in this process with the External tenant and Policy.ReadWrite.AuthenticationMethod,User.Read, then rerun with -UseMicrosoftGraphPolicyContext. No runtime policy permission is needed.' }
    }
}
$wfPath = Get-PocManifestPath $stateRoot Workforce $WorkforceTenantId
$wfManifest = Read-PocJson $wfPath
$extManifest = Read-PocJson (Get-PocManifestPath $stateRoot External $ExternalTenantId)
foreach ($pair in @(@{ manifest = $wfManifest; tenant = $WorkforceTenantId }, @{ manifest = $extManifest; tenant = $ExternalTenantId })) {
    if (-not $pair.manifest -or $pair.manifest.ownerTag -ne $ownerTag -or $pair.manifest.tenantId -ne $pair.tenant.ToString() -or @($pair.manifest.apps).Count -ne 2) { throw 'Both owned application manifests are required.' }
}
$account = (& az account show --subscription $SubscriptionId.ToString() --output json --only-show-errors) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or [guid]$account.id -ne $SubscriptionId -or [guid]$account.tenantId -ne $WorkforceTenantId -or $account.state -ne 'Enabled') { throw 'Expected hosting subscription/workforce tenant is unavailable.' }
$armToken = (& az account get-access-token --subscription $SubscriptionId.ToString() --resource-type arm --query accessToken --output tsv --only-show-errors 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or -not $armToken) { throw 'ARM token unavailable.' }
$claims = ConvertFrom-PocJwtPayload $armToken
if ([guid]$claims.tid -ne $WorkforceTenantId -or [guid]$claims.oid -ne $workforce.UserObjectId -or -not $claims.PSObject.Properties['scp']) { throw 'ARM identity differs from delegated workforce administrator.' }
$armHeaders = @{ Authorization = 'Bearer ' + $armToken }; $armToken = $null
$subscriptionPath = '/subscriptions/' + $SubscriptionId
$rgPath = $subscriptionPath + '/resourceGroups/' + $ResourceGroup
function Invoke-RegistrationArm {
    param([string]$Path, [ValidateSet('GET','PUT','POST','PATCH')][string]$Method = 'GET', [object]$Body, [string]$ApiVersion = '2023-04-01', [switch]$AllowNotFound, [string]$Filter)
    if (-not $Path.StartsWith($subscriptionPath + '/', [StringComparison]::OrdinalIgnoreCase)) { throw 'ARM path is outside the explicit subscription.' }
    $uri = 'https://management.azure.com' + $Path + '?api-version=' + $ApiVersion
    if ($Filter) { $uri += '&$filter=' + [uri]::EscapeDataString($Filter) }
    $arguments = @{ Uri = $uri; Method = $Method; Headers = $armHeaders; ErrorAction = 'Stop' }
    if ($null -ne $Body) { $arguments.ContentType = 'application/json'; $arguments.Body = ConvertTo-Json -InputObject $Body -Depth 30 -Compress }
    try { Invoke-RestMethod @arguments }
    catch {
        $status = 'unknown'; if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        if ($AllowNotFound -and $status -eq 404) { return $null }
        throw "Registration ARM $Method failed with HTTP $status. Service responses and request bodies are not logged."
    }
}
function Assert-OwnedArmResource {
    param([object]$Resource)
    if ($Resource -and (-not $Resource.PSObject.Properties['tags'] -or -not $Resource.tags -or -not $Resource.tags.PSObject.Properties['purpose'] -or $Resource.tags.purpose -ne 'multiidp-poc')) { throw 'Unowned Azure resource will not be adopted.' }
}
function Wait-RegistrationResource {
    param([string]$Path, [string]$ApiVersion = '2023-04-01')
    for ($attempt = 0; $attempt -lt 12; $attempt++) {
        $resource = Invoke-RegistrationArm -Path $Path -ApiVersion $ApiVersion
        if (-not $resource.properties.PSObject.Properties['provisioningState'] -or $resource.properties.provisioningState -eq 'Succeeded') { return $resource }
        if ($resource.properties.provisioningState -in @('Failed','Canceled')) { throw 'Resource provisioning failed; inspect private Azure state.' }
        Start-Sleep -Seconds 3
    }
    throw 'Resource provisioning remains pending after bounded polling. Rerun when it is ready.'
}
function Get-RegistrationGraphPrincipal {
    param([hashtable]$Context)
    $principals = @(Get-PocGraphCollection -Context $Context -Path ('/servicePrincipals?$filter=' + [uri]::EscapeDataString("appId eq '00000003-0000-0000-c000-000000000000'") + '&$select=id,appRoles'))
    if ($principals.Count -ne 1) { throw 'Graph service principal is ambiguous.' }
    return $principals[0]
}
function Grant-RegistrationGraphRoles {
    param([hashtable]$Context, [object]$Graph, [string]$PrincipalId, [string[]]$Values)
    $existing = @(Get-PocGraphCollection -Context $Context -Path ('/servicePrincipals/' + $PrincipalId + '/appRoleAssignments'))
    $expectedIds = @($Graph.appRoles | Where-Object { $_.value -cin $Values } | ForEach-Object { $_.id })
    if (@($existing | Where-Object { $_.resourceId -ne $Graph.id -or $_.appRoleId -notin $expectedIds }).Count -gt 0) { throw 'Unexpected runtime application grants exist; refusing implicit privilege changes.' }
    foreach ($value in $Values) {
        $roles = @($Graph.appRoles | Where-Object { $_.value -ceq $value -and $_.isEnabled -and 'Application' -in $_.allowedMemberTypes })
        if ($roles.Count -ne 1) { throw 'Required Graph application permission is missing or ambiguous.' }
        $matches = @($existing | Where-Object { $_.resourceId -eq $Graph.id -and $_.appRoleId -eq $roles[0].id })
        if ($matches.Count -gt 1) { throw 'Duplicate Graph application grants exist.' }
        if ($matches.Count -eq 0) { $null = Invoke-PocGraph -Context $Context -Method POST -Path ('/servicePrincipals/' + $Graph.id + '/appRoleAssignedTo') -Body @{ principalId = $PrincipalId; resourceId = $Graph.id; appRoleId = $roles[0].id } }
    }
    $after = @(Get-PocGraphCollection -Context $Context -Path ('/servicePrincipals/' + $PrincipalId + '/appRoleAssignments'))
    if (@($after | Where-Object { $_.resourceId -ne $Graph.id -or $_.appRoleId -notin $expectedIds }).Count -gt 0 -or @($after | Where-Object { $_.resourceId -eq $Graph.id }).Count -ne $Values.Count) { throw 'Unexpected runtime application grants exist; no grants are silently removed.' }
}
$group = Invoke-RegistrationArm -Path $rgPath -ApiVersion '2022-09-01'
Assert-OwnedArmResource $group
$providerPath = $subscriptionPath + '/providers/Microsoft.Communication'
$provider = Invoke-RegistrationArm -Path $providerPath -ApiVersion '2021-04-01'
if ($provider.registrationState -ne 'Registered') {
    $null = Invoke-RegistrationArm -Path ($providerPath + '/register') -Method POST -ApiVersion '2021-04-01'
    for ($attempt = 0; $attempt -lt 12; $attempt++) {
        $provider = Invoke-RegistrationArm -Path $providerPath -ApiVersion '2021-04-01'
        if ($provider.registrationState -eq 'Registered') { break }
        Start-Sleep -Seconds 3
    }
    if ($provider.registrationState -ne 'Registered') { throw 'Communication provider registration remains pending. Rerun after it completes.' }
}
$entitlements = @(Read-PocJson (Join-Path $stateRoot 'configuration\entitlements.json') | Where-Object { $_ })
if ($ApprovalLimitUtc -eq [DateTimeOffset]::MinValue) {
    $limits = @($entitlements | Where-Object { $_.status -eq 'approved' -and [DateTimeOffset]$_.expiresUtc -gt [DateTimeOffset]::UtcNow } | ForEach-Object { [DateTimeOffset]$_.expiresUtc } | Sort-Object)
    if ($limits.Count -eq 0) { throw 'Supply the explicit future PoC approval deadline.' }
    $ApprovalLimitUtc = $limits[0]
}
if ($ApprovalLimitUtc -le [DateTimeOffset]::UtcNow) { throw 'PoC approval deadline must be in the future.' }
$wfGraph = Get-RegistrationGraphPrincipal $workforce
$extGraph = Get-RegistrationGraphPrincipal $external
$app02 = @($wfManifest.apps | Where-Object { $_.appId -eq 'sampleapp02' })
if ($app02.Count -ne 1) { throw 'Workforce app02 manifest is ambiguous.' }
$liveApp = Invoke-PocGraph -Context $workforce -Path ('/applications/' + $app02[0].applicationObjectId + '?$select=id,appId,tags,appRoles')
if ($liveApp.appId -ne $app02[0].clientId -or $ownerTag -notin $liveApp.tags -or 'sampleapp02' -notin $liveApp.tags) { throw 'Workforce app02 ownership mismatch.' }
$expectedValues = @('Employee','Partner','admin','dependentRegistrant')
if (@($liveApp.appRoles | Where-Object { $_.value -cnotin $expectedValues }).Count -gt 0) { throw 'Unexpected workforce app02 roles will not be overwritten.' }
$roles = @($liveApp.appRoles)
foreach ($value in @('admin','dependentRegistrant')) {
    $matching = @($roles | Where-Object { $_.value -ceq $value })
    if ($matching.Count -gt 1) { throw 'Duplicate workforce capability role.' }
    if ($matching.Count -eq 0) { $roles += @{ id = [guid]::NewGuid().ToString(); allowedMemberTypes = @('User'); description = ('Approved employee registration capability: ' + $value); displayName = $value; isEnabled = $true; value = $value } }
}
$null = Invoke-PocGraph -Context $workforce -Method PATCH -Path ('/applications/' + $liveApp.id) -Body @{ appRoles = $roles }
$app02[0].roles = @($roles | ForEach-Object { @{ id = $_.id; value = $_.value } })
Write-PocJson -Path $wfPath -Value $wfManifest
function Grant-EmployeeCapability {
    param([guid]$ObjectId, [string[]]$Capabilities)
    if ($ObjectId -eq [guid]::Empty) { throw 'Capability target ID must be nonempty.' }
    $user = Invoke-PocGraph -Context $workforce -Path ('/users/' + $ObjectId + '?$select=id,userType,accountEnabled')
    $approval = @($entitlements | Where-Object { $_.appId -eq 'sampleapp02' -and $_.tenantId -eq $WorkforceTenantId.ToString() -and $_.objectId -eq $ObjectId.ToString() -and $_.source -eq 'workforce' -and $_.persona -eq 'employee' -and $_.status -eq 'approved' -and [DateTimeOffset]$_.expiresUtc -gt [DateTimeOffset]::UtcNow })
    $assignments = @(Get-PocGraphCollection -Context $workforce -Path ('/servicePrincipals/' + $app02[0].servicePrincipalId + '/appRoleAssignedTo'))
    $employee = @($roles | Where-Object { $_.value -ceq 'Employee' })
    if ($user.userType -ne 'Member' -or -not $user.accountEnabled -or $approval.Count -ne 1 -or $employee.Count -ne 1 -or @($assignments | Where-Object { $_.principalId -eq $ObjectId.ToString() -and $_.appRoleId -eq $employee[0].id }).Count -ne 1) { throw 'Registration capability requires an enabled Member with current app02 employee approval and Employee role. Guests are refused.' }
    foreach ($value in $Capabilities) {
        $role = @($roles | Where-Object { $_.value -ceq $value })
        $matching = @($assignments | Where-Object { $_.principalId -eq $ObjectId.ToString() -and $_.appRoleId -eq $role[0].id })
        if ($matching.Count -gt 1) { throw 'Duplicate capability assignment.' }
        if ($matching.Count -eq 0) { $null = Invoke-PocGraph -Context $workforce -Method POST -Path ('/servicePrincipals/' + $app02[0].servicePrincipalId + '/appRoleAssignedTo') -Body @{ principalId = $ObjectId.ToString(); resourceId = $app02[0].servicePrincipalId; appRoleId = $role[0].id } }
    }
}
if ($AllowedOperatorObjectId -ne [guid]::Empty) { Grant-EmployeeCapability $AllowedOperatorObjectId @('admin','dependentRegistrant') }
foreach ($id in @($DependentRegistrantObjectIds | Select-Object -Unique)) { Grant-EmployeeCapability $id @('dependentRegistrant') }

# A separate client-credential provisioner in the customer directory; auth apps keep OIDC scopes only.
$provisionerName = 'multiidp-net48-registration-external'
$provisionerTags = @($ownerTag,'registration-provisioner','external')
$provisionerPath = Join-Path $stateRoot ('manifests\registration-external-' + $ExternalTenantId + '.json')
$saved = Read-PocJson $provisionerPath
if ($saved -and ($saved.ownerTag -ne $ownerTag -or $saved.tenantId -ne $ExternalTenantId.ToString())) { throw 'External provisioner state ownership mismatch.' }
$apps = @(Get-PocGraphCollection -Context $external -Path ('/applications?$filter=' + [uri]::EscapeDataString("displayName eq '$provisionerName'") + '&$select=id,appId,tags,passwordCredentials,requiredResourceAccess'))
if ($apps.Count -gt 1) { throw 'External provisioner registration is ambiguous.' }
$application = if ($apps.Count -eq 1) { $apps[0] } else { $null }
if ($application -and @($provisionerTags | Where-Object { $_ -notin $application.tags }).Count -gt 0) { throw 'Unowned provisioner registration will not be adopted.' }
if ($saved -and (-not $application -or $saved.applicationObjectId -ne $application.id -or $saved.clientId -ne $application.appId)) { throw 'Saved external provisioner no longer matches directory.' }
$provisionerPermissions = @('User.ReadWrite.All','Application.Read.All','AppRoleAssignment.ReadWrite.All')
$apiRoles = @($extGraph.appRoles | Where-Object { $_.value -cin $provisionerPermissions -and $_.isEnabled -and 'Application' -in $_.allowedMemberTypes })
if ($apiRoles.Count -ne $provisionerPermissions.Count) { throw 'External provisioner Graph role catalog mismatch.' }
if ($application -and @($application.requiredResourceAccess | Where-Object { $_.resourceAppId -ne '00000003-0000-0000-c000-000000000000' -or @($_.resourceAccess | Where-Object { $_.type -ne 'Role' -or $_.id -notin @($apiRoles | ForEach-Object { $_.id }) }).Count -gt 0 }).Count -gt 0) { throw 'Unexpected external provisioner API privileges exist.' }
$definition = @{ displayName = $provisionerName; tags = $provisionerTags; signInAudience = 'AzureADMyOrg'; requiredResourceAccess = @(@{ resourceAppId = '00000003-0000-0000-c000-000000000000'; resourceAccess = @($apiRoles | ForEach-Object { @{ id = $_.id; type = 'Role' } }) }); web = @{ redirectUris = @(); implicitGrantSettings = @{ enableIdTokenIssuance = $false; enableAccessTokenIssuance = $false } } }
if ($application) { $null = Invoke-PocGraph -Context $external -Method PATCH -Path ('/applications/' + $application.id) -Body $definition }
else { $application = Invoke-PocGraph -Context $external -Method POST -Path '/applications' -Body $definition }
$owners = @(Get-PocGraphCollection -Context $external -Path ('/applications/' + $application.id + '/owners?$select=id'))
if ($external.UserObjectId.ToString() -notin @($owners | ForEach-Object { $_.id })) { $null = Invoke-PocGraph -Context $external -Method POST -Path ('/applications/' + $application.id + '/owners/$ref') -Body @{ '@odata.id' = ('https://graph.microsoft.com/v1.0/directoryObjects/' + $external.UserObjectId) } }
$principals = @(Get-PocGraphCollection -Context $external -Path ('/servicePrincipals?$filter=' + [uri]::EscapeDataString("appId eq '$($application.appId)'") + '&$select=id,appId,tags'))
if ($principals.Count -gt 1) { throw 'External provisioner service principal is ambiguous.' }
if ($principals.Count -eq 1) {
    $principal = $principals[0]
    if (@($provisionerTags | Where-Object { $_ -notin $principal.tags }).Count -gt 0 -or ($saved -and $saved.servicePrincipalId -ne $principal.id)) { throw 'Provisioner principal ownership mismatch.' }
    $null = Invoke-PocGraph -Context $external -Method PATCH -Path ('/servicePrincipals/' + $principal.id) -Body @{ accountEnabled = $true }
} else { $principal = Invoke-PocGraph -Context $external -Method POST -Path '/servicePrincipals' -Body @{ appId = $application.appId; tags = $provisionerTags; accountEnabled = $true } }
$secretVariable = 'MULTIIDP_REGISTRATION_EXTERNAL_SECRET'
$secretPath = Join-Path $stateRoot ('secrets\' + $secretVariable + '.clixml')
if ($saved) {
    if ($saved.secretFile -ne $secretPath -or $saved.secretEnvironmentVariable -ne $secretVariable -or -not (Test-Path -LiteralPath $secretPath) -or [DateTimeOffset]$saved.credentialExpiresUtc -le [DateTimeOffset]::UtcNow -or @($application.passwordCredentials | Where-Object { $_.keyId -eq $saved.credentialId }).Count -ne 1) { throw 'Provisioner credential state is missing, expired or mismatched; no automatic rotation.' }
    $secureSecret = Import-Clixml -LiteralPath $secretPath
    if ($secureSecret -isnot [Security.SecureString]) { throw 'Unexpected provisioner DPAPI file type.' }
} else {
    if ((Test-Path -LiteralPath $secretPath) -or @($application.passwordCredentials | Where-Object { $_ }).Count -gt 0) { throw 'Untracked provisioner credential exists; refusing adoption or rotation.' }
    $credential = Invoke-PocGraph -Context $external -Method POST -Path ('/applications/' + $application.id + '/addPassword') -Body @{ passwordCredential = @{ displayName = 'multiidp-registration-7day'; endDateTime = [DateTimeOffset]::UtcNow.AddDays(7).ToString('o') } }
    $secureSecret = ConvertTo-SecureString -String $credential.secretText -AsPlainText -Force
    $secureSecret | Export-Clixml -LiteralPath $secretPath
    $saved = @{ ownerTag = $ownerTag; tenantId = $ExternalTenantId.ToString(); applicationObjectId = $application.id; clientId = $application.appId; servicePrincipalId = $principal.id; secretFile = $secretPath; secretEnvironmentVariable = $secretVariable; credentialId = $credential.keyId; credentialExpiresUtc = $credential.endDateTime }
    $credential = $null
    Write-PocJson -Path $provisionerPath -Value $saved
}
Grant-RegistrationGraphRoles $external $extGraph $principal.id $provisionerPermissions
$organization = @(Get-PocGraphCollection -Context $external -Path '/organization?$select=id,verifiedDomains')
$initialDomain = @(if ($organization.Count -eq 1 -and $organization[0].id -eq $ExternalTenantId.ToString()) { $organization[0].verifiedDomains | Where-Object { $_.isInitial -and $_.name -like '*.onmicrosoft.com' } })
if ($initialDomain.Count -ne 1) { throw 'External initial domain is ambiguous.' }
$emailPolicy = Invoke-RegistrationEmailPolicy
if ($EnableExternalEmailPasswordReset) {
    # Setup-only, on the explicit customer tenant: no runtime policy permission is granted.
    $null = Invoke-RegistrationEmailPolicy -Method PATCH -Body @{ '@odata.type' = '#microsoft.graph.emailAuthenticationMethodConfiguration'; state = 'enabled'; includeTargets = @(@{ targetType = 'group'; id = 'all_users'; isRegistrationRequired = $false }) }
    $emailPolicy = Invoke-RegistrationEmailPolicy
}
$emailExclusions = @(if ($emailPolicy.PSObject.Properties['excludeTargets']) { $emailPolicy.excludeTargets | Where-Object { $_ } })
if ($emailPolicy.state -ne 'enabled' -or @($emailPolicy.includeTargets | Where-Object { $_.id -eq 'all_users' }).Count -ne 1 -or $emailExclusions.Count -gt 0) { throw 'Email OTP password reset is not enabled for the intended customer accounts. Configure it explicitly in the new External tenant before runtime setup.' }
$flowState = Read-PocJson (Join-Path $stateRoot 'external-flow.json')
if (-not $flowState -or $flowState.tenantId -ne $ExternalTenantId.ToString()) { throw 'Owned controlled customer flow state is required.' }
$flow = Invoke-PocGraph -Context $external -Path ('/identity/authenticationEventsFlows/' + $flowState.flowId)
if ($flow.onInteractiveAuthFlowStart.isSignUpAllowed -ne $false -or 'EmailPassword-OAUTH' -notin @($flow.onAuthenticationMethodLoadStart.identityProviders | ForEach-Object { $_.id })) { throw 'Customer flow must use email/password with public sign-up disabled.' }

$emailServicePath = $rgPath + '/providers/Microsoft.Communication/emailServices/ecs-multiidp-poc-' + $NameSuffix
$domainPath = $emailServicePath + '/domains/AzureManagedDomain'
$communicationPath = $rgPath + '/providers/Microsoft.Communication/communicationServices/acs-multiidp-poc-' + $NameSuffix
foreach ($path in @($emailServicePath,$domainPath,$communicationPath)) { Assert-OwnedArmResource (Invoke-RegistrationArm -Path $path -AllowNotFound) }
$tags = @{ purpose = 'multiidp-poc'; component = 'registration-email' }
$null = Invoke-RegistrationArm -Path $emailServicePath -Method PUT -Body @{ location = 'global'; tags = $tags; properties = @{ dataLocation = 'Europe' } }
$null = Wait-RegistrationResource $emailServicePath
$null = Invoke-RegistrationArm -Path $domainPath -Method PUT -Body @{ location = 'global'; tags = $tags; properties = @{ domainManagement = 'AzureManaged'; userEngagementTracking = 'Disabled' } }
$domain = Wait-RegistrationResource $domainPath
if ($domain.properties.domainManagement -ne 'AzureManaged' -or $domain.properties.userEngagementTracking -ne 'Disabled' -or $domain.properties.fromSenderDomain -notmatch '^[a-zA-Z0-9-]+\.azurecomm\.net$') { throw 'Azure-managed sender domain was not generated as expected.' }
if (-not $domain.properties.PSObject.Properties['verificationStates'] -or -not $domain.properties.verificationStates -or @($domain.properties.verificationStates.PSObject.Properties | Where-Object { $_.Value -and $_.Value.status -ne 'Verified' }).Count -gt 0) { throw 'Managed domain verification is not yet complete. Rerun after it is ready.' }
$senders = Invoke-RegistrationArm -Path ($domainPath + '/senderUsernames')
$sender = @($senders.value | Where-Object { $_.properties.username -ieq 'donotreply' })
if ($sender.Count -ne 1) { throw 'Default Azure-managed sender is missing or ambiguous.' }
$senderAddress = $sender[0].properties.username + '@' + $domain.properties.fromSenderDomain
$null = Invoke-RegistrationArm -Path $communicationPath -Method PUT -Body @{ location = 'global'; tags = $tags; properties = @{ dataLocation = 'Europe'; linkedDomains = @($domainPath) } }
$communication = Wait-RegistrationResource $communicationPath
if ($communication.properties.dataLocation -ne 'Europe' -or @($communication.properties.linkedDomains).Count -ne 1 -or $communication.properties.linkedDomains[0] -ne $domainPath) { throw 'ACS resource domain/data-location readback differs from the requested dedicated mail scope.' }
$endpoint = [uri]$communication.properties.hostName
if (-not $endpoint.IsAbsoluteUri) { $endpoint = [uri]('https://' + $communication.properties.hostName) }
if ($endpoint.Scheme -ne 'https' -or $endpoint.Host -notlike '*.communication.azure.com' -or $endpoint.Query -or $endpoint.UserInfo -or $endpoint.Fragment) { throw 'Unexpected ACS service endpoint.' }

# The role deliberately contains only the two documented REST/SDK mail permissions.
$roleName = 'MultiIdp PoC ACS Mail Runtime ' + $NameSuffix
$description = $ownerTag + ': resource-scoped ACS read/write for sample application identities only'
$roleList = Invoke-RegistrationArm -Path ($rgPath + '/providers/Microsoft.Authorization/roleDefinitions') -ApiVersion '2022-04-01' -Filter ("roleName eq '$roleName'")
$mailRoles = @($roleList.value | Where-Object { $_.properties.roleName -ceq $roleName })
if ($mailRoles.Count -gt 1) { throw 'ACS custom role is ambiguous.' }
$actions = @('Microsoft.Communication/CommunicationServices/read','Microsoft.Communication/CommunicationServices/write')
if ($mailRoles.Count -eq 1) {
    $mailRole = $mailRoles[0]
    if ($mailRole.properties.type -ne 'CustomRole' -or $mailRole.properties.description -ne $description -or @($mailRole.properties.assignableScopes).Count -ne 1 -or $mailRole.properties.assignableScopes[0] -ne $rgPath -or @($mailRole.properties.permissions).Count -ne 1 -or @(Compare-Object @($mailRole.properties.permissions[0].actions) $actions).Count -gt 0 -or @($mailRole.properties.permissions[0].notActions).Count -gt 0 -or @($mailRole.properties.permissions[0].dataActions).Count -gt 0 -or @($mailRole.properties.permissions[0].notDataActions).Count -gt 0) { throw 'Existing custom mail role is not the exact owned two-action role.' }
} else {
    $rolePath = $rgPath + '/providers/Microsoft.Authorization/roleDefinitions/' + [guid]::NewGuid()
    $mailRole = Invoke-RegistrationArm -Path $rolePath -Method PUT -ApiVersion '2022-04-01' -Body @{ properties = @{ roleName = $roleName; description = $description; type = 'CustomRole'; assignableScopes = @($rgPath); permissions = @(@{ actions = $actions; notActions = @(); dataActions = @(); notDataActions = @() }) } }
}
$siteRecords = @()
for ($index = 0; $index -lt 2; $index++) {
    $appId = 'sampleapp{0:d2}' -f ($index + 1)
    $siteName = @($App01SiteName,$App02SiteName)[$index]
    $sitePath = $rgPath + '/providers/Microsoft.Web/sites/' + $siteName
    $site = Invoke-RegistrationArm -Path $sitePath -ApiVersion '2024-11-01'
    Assert-OwnedArmResource $site
    if (-not $site.PSObject.Properties['identity'] -or -not $site.identity -or $site.identity.type -notlike '*SystemAssigned*') {
        $identity = @{ type = 'SystemAssigned' }
        if ($site.PSObject.Properties['identity'] -and $site.identity -and $site.identity.PSObject.Properties['userAssignedIdentities'] -and $site.identity.userAssignedIdentities) { $identity.type = 'SystemAssigned, UserAssigned'; $identity.userAssignedIdentities = $site.identity.userAssignedIdentities }
        $null = Invoke-RegistrationArm -Path $sitePath -Method PATCH -ApiVersion '2024-11-01' -Body @{ identity = $identity }
        $site = Invoke-RegistrationArm -Path $sitePath -ApiVersion '2024-11-01'
    }
    if ([guid]$site.identity.tenantId -ne $WorkforceTenantId -or [guid]$site.identity.principalId -eq [guid]::Empty) { throw 'Sample managed identity is not bound to the workforce directory.' }
    $miId = [string]$site.identity.principalId
    $mi = $null
    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        try { $mi = Invoke-PocGraph -Context $workforce -Path ('/servicePrincipals/' + $miId + '?$select=id,servicePrincipalType'); break }
        catch { if ($attempt -eq 9) { throw 'Managed identity is not yet visible in Graph. Rerun after propagation.' }; Start-Sleep -Seconds 3 }
    }
    if ($mi.servicePrincipalType -ne 'ManagedIdentity') { throw 'Runtime principal is not a managed identity.' }
    $permissions = @('Application.Read.All','User.Read.All')
    if ($appId -eq 'sampleapp02') { $permissions += @('AppRoleAssignment.ReadWrite.All','User.Invite.All') }
    Grant-RegistrationGraphRoles $workforce $wfGraph $miId $permissions
    $assignmentList = Invoke-RegistrationArm -Path ($communicationPath + '/providers/Microsoft.Authorization/roleAssignments') -ApiVersion '2022-04-01' -Filter ("principalId eq '$miId'")
    $matching = @($assignmentList.value | Where-Object { $_.properties.principalId -eq $miId -and $_.properties.roleDefinitionId -eq $mailRole.id -and $_.properties.scope -eq $communicationPath })
    if ($matching.Count -gt 1) { throw 'Duplicate mail runtime role assignment.' }
    if ($matching.Count -eq 0) { $null = Invoke-RegistrationArm -Path ($communicationPath + '/providers/Microsoft.Authorization/roleAssignments/' + [guid]::NewGuid()) -Method PUT -ApiVersion '2022-04-01' -Body @{ properties = @{ principalId = $miId; principalType = 'ServicePrincipal'; roleDefinitionId = $mailRole.id } } }
    $wfApp = @($wfManifest.apps | Where-Object { $_.appId -eq $appId }); $extApp = @($extManifest.apps | Where-Object { $_.appId -eq $appId })
    if ($wfApp.Count -ne 1 -or $extApp.Count -ne 1) { throw 'Per-app target service principal is ambiguous.' }
    $baseUrl = Get-PocHttpsRoot ('https://' + $site.properties.defaultHostName)
    if ($wfApp[0].redirectUri -ne ($baseUrl + '/signin-workforce') -or $extApp[0].redirectUri -ne ($baseUrl + '/signin-external')) { throw 'Sample hosting origin differs from tenant registration manifests.' }
    $wfRoleMap = @{}; foreach ($role in $wfApp[0].roles) { $wfRoleMap[$role.value] = $role.id }
    $extRoleMap = @{}; foreach ($role in $extApp[0].roles) { $extRoleMap[$role.value] = $role.id }
    $configurationPath = Join-Path $stateRoot ('configuration\' + $appId + '.registration.json')
    $configuration = @{ appId = $appId; appBaseUrl = $baseUrl; stateFile = "D:\home\data\multiidp\$appId\registration-state.json"; approvalLimitUtc = $ApprovalLimitUtc.ToUniversalTime().ToString('o'); workforce = @{ tenantId = $WorkforceTenantId.ToString(); graphAuthentication = 'managedIdentity'; servicePrincipalId = $wfApp[0].servicePrincipalId; roleIds = $wfRoleMap }; external = @{ tenantId = $ExternalTenantId.ToString(); initialDomain = $initialDomain[0].name; clientId = $application.appId; clientSecretEnvironmentVariable = $secretVariable; servicePrincipalId = $extApp[0].servicePrincipalId; roleIds = $extRoleMap }; email = @{ endpoint = $endpoint.AbsoluteUri.TrimEnd('/'); senderAddress = $senderAddress } }
    $setupState = Read-PocJson (Join-Path $stateRoot 'password-setup.json')
    if ($setupState -and $setupState.tenantId -eq "$ExternalTenantId" -and $setupState.ownerTag -eq 'multiidp-net48-password-setup-v1') { $configuration.external.passwordSetupClientId = $setupState.clientId }
    Write-PocJson -Path $configurationPath -Value $configuration
    $temporarySettingsPath = Join-Path $stateRoot ($appId + '-registration-appsettings.tmp.json')
    if (Test-Path -LiteralPath $temporarySettingsPath) { throw 'A previous temporary registration appsettings file exists; inspect privately before retrying.' }
    try {
        $settingName = 'MULTIIDP_' + $appId.ToUpperInvariant() + '_REGISTRATION_CONFIG'
        $settings = @{ $settingName = 'D:\home\site\wwwroot\App_Data\registration.json'; $secretVariable = [Net.NetworkCredential]::new('', $secureSecret).Password }
        Write-PocJson -Path $temporarySettingsPath -Value $settings
        & az webapp config appsettings set --subscription $SubscriptionId.ToString() --resource-group $ResourceGroup --name $siteName --slot-settings "@$temporarySettingsPath" --output none --only-show-errors 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'Registration appsettings update failed; values are not logged.' }
    } finally { $settings = $null; if (Test-Path -LiteralPath $temporarySettingsPath) { Remove-Item -LiteralPath $temporarySettingsPath -Force } }
    $siteRecords += @{ appId = $appId; siteName = $siteName; managedIdentityObjectId = $miId; graphPermissions = $permissions; configurationFile = $configurationPath; mailRoleDefinitionId = $mailRole.id }
}
$setupManifest = @{ ownerTag = $ownerTag; subscriptionId = $SubscriptionId.ToString(); workforceTenantId = $WorkforceTenantId.ToString(); externalTenantId = $ExternalTenantId.ToString(); resourceGroup = $ResourceGroup; emailServiceId = $emailServicePath; domainId = $domainPath; communicationServiceId = $communicationPath; externalProvisionerManifest = $provisionerPath; sites = $siteRecords; approvalLimitUtc = $ApprovalLimitUtc.ToUniversalTime().ToString('o'); status = 'Configured'; contentDeployed = $false; passwordsEverExported = $false }
Write-PocJson -Path (Join-Path $stateRoot 'manifests\registration-setup.json') -Value $setupManifest
$secureSecret = $null; $armHeaders = $null
Write-Output 'Registration infrastructure and private configuration prepared. Deploy protected configuration without overwriting registration-state.json; verify SSPR reset-link visibility and live invitation delivery separately.'
