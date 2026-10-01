[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Poc.Common.ps1')
$testRoot = Join-Path $PSScriptRoot ('.verification-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $testRoot
foreach ($directory in @('manifests', 'configuration', 'secrets')) { $null = New-Item -ItemType Directory -Path (Join-Path $testRoot $directory) }
$script:directory = @{ apps = @(); principals = @(); grants = @(); assignments = @(); credentialsCreated = 0; calls = 0 }
$script:graphId = [guid]::NewGuid().ToString()

function Get-PocStateDirectory { param([string]$Path) return $testRoot }
function Get-PocGraphContext { param([guid]$TenantId, [string]$TenantKind) return @{ TenantId = $TenantId.ToString() } }
function Get-PocOidcMetadata {
    param([guid]$TenantId, [string]$TenantKind, [string]$CiamDomain)
    $hostName = if ($TenantKind -eq 'External') { $TenantId.ToString() + '.ciamlogin.com' } else { 'login.microsoftonline.com' }
    return @{ Issuer = 'https://' + $hostName + '/' + $TenantId + '/v2.0'; CiamDomain = $CiamDomain }
}
function Get-PocGraphCollection {
    param([hashtable]$Context, [string]$Path)
    $script:directory.calls++
    $decoded = [uri]::UnescapeDataString($Path)
    if ($decoded -match "^/applications.*displayName eq '([^']+)'") { $script:directory.apps | Where-Object { $_.displayName -eq $Matches[1] -and $_.tenantId -eq $Context.TenantId }; return }
    if ($decoded -match "^/servicePrincipals.*appId eq '([^']+)'") {
        if ($Matches[1] -eq '00000003-0000-0000-c000-000000000000') { [pscustomobject]@{ id = $script:graphId }; return }
        $script:directory.principals | Where-Object { $_.appId -eq $Matches[1] -and $_.tenantId -eq $Context.TenantId }; return
    }
    if ($decoded -match "^/oauth2PermissionGrants.*clientId eq '([^']+)'") { $script:directory.grants | Where-Object { $_.clientId -eq $Matches[1] }; return }
    if ($decoded -match '^/servicePrincipals/([^/]+)/appRoleAssignedTo') { $script:directory.assignments | Where-Object { $_.resourceId -eq $Matches[1] }; return }
    throw ('Unexpected mocked Graph collection path: ' + $Path)
}
function Invoke-PocGraph {
    param([hashtable]$Context, [string]$Path, [string]$Method = 'GET', [object]$Body)
    $script:directory.calls++
    if ($Method -eq 'POST' -and $Path -eq '/applications') {
        $application = [pscustomobject]@{ id = [guid]::NewGuid().ToString(); appId = [guid]::NewGuid().ToString(); tenantId = $Context.TenantId; displayName = $Body.displayName; tags = $Body.tags; appRoles = $Body.appRoles; passwordCredentials = @(); web = $Body.web; signInAudience = $Body.signInAudience; requiredResourceAccess = $Body.requiredResourceAccess; optionalClaims = if ($Body.ContainsKey('optionalClaims')) { $Body.optionalClaims } else { $null } }
        $script:directory.apps += $application
        return $application
    }
    if ($Method -eq 'PATCH' -and $Path -match '^/applications/([^/]+)$') {
        $application = $script:directory.apps | Where-Object { $_.id -eq $Matches[1] }
        foreach ($name in $Body.Keys) { $application.$name = $Body[$name] }
        return
    }
    if ($Method -eq 'POST' -and $Path -eq '/servicePrincipals') {
        $principal = [pscustomobject]@{ id = [guid]::NewGuid().ToString(); tenantId = $Context.TenantId; appId = $Body.appId; tags = $Body.tags; appRoleAssignmentRequired = $Body.appRoleAssignmentRequired; accountEnabled = $Body.accountEnabled }
        $script:directory.principals += $principal
        return $principal
    }
    if ($Path -match '^/servicePrincipals/([^/?]+)\??') {
        $principal = $script:directory.principals | Where-Object { $_.id -eq $Matches[1] }
        if ($Method -eq 'GET') { return $principal }
        if ($Method -eq 'PATCH') { foreach ($name in $Body.Keys) { $principal.$name = $Body[$name] }; return }
        if ($Method -eq 'POST' -and $Path -like '*/appRoleAssignedTo') { $script:directory.assignments += [pscustomobject]$Body; return [pscustomobject]$Body }
    }
    if ($Method -eq 'POST' -and $Path -match '^/applications/([^/]+)/addPassword$') {
        $application = $script:directory.apps | Where-Object { $_.id -eq $Matches[1] }
        $credential = [pscustomobject]@{ keyId = [guid]::NewGuid().ToString(); endDateTime = $Body.passwordCredential.endDateTime; secretText = 'mock-secret-do-not-use' }
        $application.passwordCredentials += [pscustomobject]@{ keyId = $credential.keyId; endDateTime = $credential.endDateTime }
        $script:directory.credentialsCreated++
        return $credential
    }
    if ($Method -eq 'POST' -and $Path -eq '/oauth2PermissionGrants') {
        $grant = [pscustomobject]@{ id = [guid]::NewGuid().ToString(); clientId = $Body.clientId; resourceId = $Body.resourceId; scope = $Body.scope }
        $script:directory.grants += $grant
        return $grant
    }
    if ($Method -eq 'PATCH' -and $Path -match '^/oauth2PermissionGrants/(.+)$') { ($script:directory.grants | Where-Object { $_.id -eq $Matches[1] }).scope = $Body.scope; return }
    if ($Method -eq 'GET' -and $Path -match '^/users/([^?]+)') { return [pscustomobject]@{ id = $Matches[1]; userType = 'Member'; accountEnabled = $true } }
    throw ('Unexpected mocked Graph operation: ' + $Method + ' ' + $Path)
}
function Invoke-TestScript {
    param([string]$Name, [hashtable]$Arguments)
    $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot $Name) -Raw
    $source = $source.Replace('. (Join-Path $PSScriptRoot ''Poc.Common.ps1'')', '')
    & ([scriptblock]::Create($source)) @Arguments
}
function Assert-PocTest { param([bool]$Condition, [string]$Message) if (-not $Condition) { throw $Message } }

try {
    $tenantWorkforce = [guid]::NewGuid()
    $tenantExternal = [guid]::NewGuid()
    $arguments = @{ TenantId = $tenantWorkforce; TenantKind = 'Workforce'; App01BaseUrl = 'https://app01.example.com'; App02BaseUrl = 'https://app02.example.com'; StateDirectory = $testRoot }
    Invoke-TestScript 'Configure-PocApplications.ps1' $arguments
    Invoke-TestScript 'Configure-PocApplications.ps1' $arguments
    Assert-PocTest ($script:directory.apps.Count -eq 2 -and $script:directory.credentialsCreated -eq 2) 'Workforce rerun created additional apps or credentials.'
    Assert-PocTest (@($script:directory.apps | Where-Object { $_.web.implicitGrantSettings.enableIdTokenIssuance -or $_.signInAudience -ne 'AzureADMyOrg' }).Count -eq 0) 'Unsafe application flow/audience configuration.'
    Assert-PocTest (@($script:directory.apps | Where-Object { $_.optionalClaims.idToken[0].name -ne 'idp' }).Count -eq 0) 'Workforce signed idp optional claim missing.'
    $arguments.TenantId = $tenantExternal; $arguments.TenantKind = 'External'; $arguments.CiamDomain = 'mock.ciamlogin.com'
    Invoke-TestScript 'Configure-PocApplications.ps1' $arguments
    Invoke-TestScript 'Configure-PocApplications.ps1' $arguments
    Assert-PocTest ($script:directory.apps.Count -eq 4 -and $script:directory.credentialsCreated -eq 4) 'External rerun created additional apps or credentials.'
    Assert-PocTest (@($script:directory.principals | Where-Object { -not $_.appRoleAssignmentRequired -or -not $_.accountEnabled }).Count -eq 0) 'Assignment-required service principal missing.'
    Assert-PocTest (@($script:directory.apps.requiredResourceAccess.resourceAccess | Where-Object { $_.type -ne 'Scope' }).Count -eq 0) 'Graph application privileges were requested.'
    $workforceManifest = Read-PocJson (Get-PocManifestPath $testRoot 'Workforce' $tenantWorkforce)
    $originalCredentials = @($workforceManifest.apps.credentialId)
    Assert-PocTest ($workforceManifest.apps[0].roles[0].value -eq 'Employee' -and @($workforceManifest.apps[0].roles).Count -eq 1) 'sampleapp01 Workforce role contract failed.'
    $jsonPath = Join-Path $testRoot 'configuration\entitlements.json'
    Write-PocJson -Path $jsonPath -Value @()
    Assert-PocTest ((Get-Content -LiteralPath $jsonPath -Raw).Trim().StartsWith('[') -and @(Read-PocJson $jsonPath).Count -eq 0) 'Empty entitlement JSON array failed.'
    Invoke-TestScript 'Export-PocConfiguration.ps1' @{ WorkforceTenantId = $tenantWorkforce; ExternalTenantId = $tenantExternal; StateDirectory = $testRoot; Local = $true; EmployeeDomains = @('Contoso.example'); ApprovedPartnerDomains = @('Partner.example') }
    $config = Read-PocJson (Join-Path $testRoot 'configuration\sampleapp01.local.json')
    Assert-PocTest ($config.workforce.redirectUri -eq 'https://localhost:44371/signin-workforce' -and $config.external.redirectUri -eq 'https://localhost:44371/signin-external') 'Local callback contract failed.'
    Assert-PocTest (@($config.approvedPartnerDomains).Count -eq 0 -and $config.employeeDomains[0] -eq 'contoso.example') 'Exact domain routing contract failed.'
    Assert-PocTest ($config.approvedPartnerDomains -is [array]) 'sampleapp01 approvedPartnerDomains was not serialized as a JSON array.'
    $employeeUser = [guid]::NewGuid()
    Invoke-TestScript 'Add-PocAssignment.ps1' @{ TenantId = $tenantWorkforce; TenantKind = 'Workforce'; AppId = 'sampleapp01'; UserId = $employeeUser; Persona = 'Employee'; ExpiresUtc = [DateTimeOffset]::UtcNow.AddDays(2); BenefitEligible = $true; StateDirectory = $testRoot }
    $user = [guid]::NewGuid()
    $assignmentArguments = @{ TenantId = $tenantExternal; TenantKind = 'External'; AppId = 'sampleapp01'; UserId = $user; Persona = 'Dependent'; ExpiresUtc = [DateTimeOffset]::UtcNow.AddDays(1); Sponsor = 'poc-sponsor'; RelationshipVerified = $true; BenefitEligible = $true; LinkedEmployeeTenantId = $tenantWorkforce; LinkedEmployeeObjectId = $employeeUser; StateDirectory = $testRoot }
    Invoke-TestScript 'Add-PocAssignment.ps1' $assignmentArguments
    Invoke-TestScript 'Add-PocAssignment.ps1' $assignmentArguments
    Assert-PocTest ($script:directory.assignments.Count -eq 2 -and @(Read-PocJson $jsonPath).Count -eq 2 -and (Get-Content -LiteralPath $jsonPath -Raw).Trim().StartsWith('[')) 'Assignment/entitlement rerun was not idempotent.'
    $before = $script:directory.calls
    $assignmentArguments.BenefitEligible = $false
    $rejected = $false
    try { Invoke-TestScript 'Add-PocAssignment.ps1' $assignmentArguments } catch { $rejected = $true }
    Assert-PocTest ($rejected -and $script:directory.calls -eq $before) 'Unverified dependent caused a Graph operation.'
    $assignmentArguments.BenefitEligible = $true
    $assignmentArguments.LinkedEmployeeObjectId = [guid]::NewGuid()
    $rejected = $false
    try { Invoke-TestScript 'Add-PocAssignment.ps1' $assignmentArguments } catch { $rejected = $true }
    Assert-PocTest ($rejected -and $script:directory.calls -eq $before) 'Unapproved employee link caused a Graph operation.'
    $application = $script:directory.apps | Where-Object { $_.tenantId -eq $tenantExternal.ToString() -and $_.displayName -eq 'sampleapp01-net48-external' }
    $application.tags = @('unowned')
    $rejected = $false
    try { Invoke-TestScript 'Configure-PocApplications.ps1' $arguments } catch { $rejected = $true }
    Assert-PocTest ($rejected -and $script:directory.credentialsCreated -eq 4) 'An unowned app was adopted or its credentials rotated.'
    Write-Host 'PASS: mocked lifecycle, rerun credentials, app ownership, role contract, callbacks, configuration arrays, entitlement assignment and preflight denial.'
} finally {
    $resolved = [IO.Path]::GetFullPath($testRoot)
    if (-not $resolved.StartsWith([IO.Path]::GetFullPath($PSScriptRoot) + '\', [StringComparison]::OrdinalIgnoreCase) -or -not (Split-Path $resolved -Leaf).StartsWith('.verification-')) { throw 'Refusing test directory cleanup outside scripts/poc.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
    foreach ($name in @('MULTIIDP_SAMPLEAPP01_CONFIG', 'MULTIIDP_SAMPLEAPP02_CONFIG')) { [Environment]::SetEnvironmentVariable($name, $null, 'Process') }
}
