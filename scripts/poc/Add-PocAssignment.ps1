[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][guid]$TenantId,
    [Parameter(Mandatory = $true)][ValidateSet('Workforce', 'External')][string]$TenantKind,
    [Parameter(Mandatory = $true)][ValidateSet('sampleapp01', 'sampleapp02')][string]$AppId,
    [Parameter(Mandatory = $true)][guid]$UserId,
    [Parameter(Mandatory = $true)][ValidateSet('Employee', 'Partner', 'Retiree', 'Dependent', 'External')][string]$Persona,
    [Parameter(Mandatory = $true)][DateTimeOffset]$ExpiresUtc,
    [string]$Sponsor,
    [switch]$RelationshipVerified,
    [switch]$BenefitEligible,
    [guid]$LinkedEmployeeTenantId = [guid]::Empty,
    [guid]$LinkedEmployeeObjectId = [guid]::Empty,
    [guid]$HomeTenantId = [guid]::Empty,
    [Nullable[DateTimeOffset]]$OrganizationVerifiedUtc,
    [string]$EntitlementFile,
    [string]$StateDirectory = (Join-Path $env:LOCALAPPDATA 'MultiIdpPoC')
)
. (Join-Path $PSScriptRoot 'Poc.Common.ps1')
if ($UserId -eq [guid]::Empty -or $ExpiresUtc -le [DateTimeOffset]::UtcNow) { throw 'A real user object ID and a future entitlement expiry are required.' }
if (($Persona -in @('Employee', 'Partner') -and $TenantKind -ne 'Workforce') -or ($Persona -in @('Retiree', 'Dependent', 'External') -and $TenantKind -ne 'External')) { throw 'Employee/Partner use Workforce; Retiree/Dependent/External use External.' }
if ($Persona -ne 'Employee' -and -not $Sponsor) { throw 'External benefits and partners require an accountable sponsor.' }
if ($Persona -eq 'Dependent' -and (-not $RelationshipVerified -or -not $BenefitEligible -or $LinkedEmployeeTenantId -eq [guid]::Empty -or $LinkedEmployeeObjectId -eq [guid]::Empty)) { throw 'Dependent access requires verified relationship, benefit eligibility and the stable linked employee tenant/object IDs.' }
if ($Persona -eq 'Partner' -and ($AppId -ne 'sampleapp02' -or $HomeTenantId -eq [guid]::Empty -or -not $OrganizationVerifiedUtc -or $OrganizationVerifiedUtc -gt [DateTimeOffset]::UtcNow)) { throw 'Partner access requires sampleapp02, an approved home tenant and completed organization verification.' }
if (-not $PSCmdlet.ShouldProcess(($AppId + ':' + $UserId.ToString()), ('Assign directory role ' + $Persona + ' and save the explicit entitlement'))) { return }
$stateRoot = Get-PocStateDirectory $StateDirectory
if (-not $EntitlementFile) { $EntitlementFile = Join-Path $stateRoot 'configuration\entitlements.json' }
$path = [IO.Path]::GetFullPath($EntitlementFile)
$entries = @(Read-PocJson $path | Where-Object { $null -ne $_ })
if ($Persona -eq 'Dependent') {
    $linked = @($entries | Where-Object { $_.appId -eq $AppId -and $_.tenantId -eq $LinkedEmployeeTenantId.ToString() -and $_.objectId -eq $LinkedEmployeeObjectId.ToString() -and $_.source -eq 'workforce' -and $_.persona -eq 'employee' -and $_.status -eq 'approved' -and $_.benefitEligible -and [DateTimeOffset]$_.expiresUtc -gt [DateTimeOffset]::UtcNow })
    if ($linked.Count -ne 1) { throw 'Dependent access requires one approved, unexpired and benefit-eligible linked employee entitlement in the same application.' }
}
$manifest = Read-PocJson (Get-PocManifestPath $stateRoot $TenantKind $TenantId)
if (-not $manifest -or $manifest.ownerTag -ne 'multiidp-net48-poc-v1' -or $manifest.tenantId -ne $TenantId.ToString()) { throw 'The owned manifest for this tenant is required.' }
$apps = @($manifest.apps | Where-Object { $_.appId -eq $AppId })
if ($apps.Count -ne 1) { throw 'The application registration is missing or ambiguous in the manifest.' }
$app = $apps[0]
$roles = @($app.roles | Where-Object { $_.value -ceq $Persona })
if ($roles.Count -ne 1) { throw 'The requested persona role is missing or ambiguous.' }
$context = Get-PocGraphContext $TenantId $TenantKind
$user = Invoke-PocGraph $context ('/users/' + $UserId.ToString() + '?$select=id,userType,accountEnabled')
if ([guid]$user.id -ne $UserId -or -not $user.accountEnabled) { throw 'The explicit user is missing or disabled in this tenant.' }
if ($Persona -eq 'Partner' -and $user.userType -ne 'Guest') { throw 'Partner access requires a Workforce B2B guest object; no guest or customer users are created by this script.' }
$principal = Invoke-PocGraph $context ('/servicePrincipals/' + $app.servicePrincipalId + '?$select=id,appId,tags')
if ($principal.appId -ne $app.clientId -or 'multiidp-net48-poc-v1' -notin $principal.tags -or $AppId -notin $principal.tags) { throw 'Live service principal ownership no longer matches saved state.' }
$assignments = @(Get-PocGraphCollection $context ('/servicePrincipals/' + $app.servicePrincipalId + '/appRoleAssignedTo'))
$matching = @($assignments | Where-Object { $_.principalId -eq $UserId.ToString() -and $_.appRoleId -eq $roles[0].id })
if ($matching.Count -gt 1) { throw 'Duplicate role assignments exist; review them before continuing.' }
if ($matching.Count -eq 0) {
    $null = Invoke-PocGraph -Context $context -Method POST -Path ('/servicePrincipals/' + $app.servicePrincipalId + '/appRoleAssignedTo') -Body @{ principalId = $UserId.ToString(); resourceId = $app.servicePrincipalId; appRoleId = $roles[0].id }
}
$entry = @{ appId = $AppId; tenantId = $TenantId.ToString(); objectId = $UserId.ToString(); source = $TenantKind.ToLowerInvariant(); persona = $Persona.ToLowerInvariant(); sponsor = $Sponsor; status = 'approved'; expiresUtc = $ExpiresUtc.ToUniversalTime().ToString('o'); relationshipVerified = [bool]$RelationshipVerified; benefitEligible = [bool]$BenefitEligible; linkedEmployeeTenantId = if ($LinkedEmployeeTenantId -ne [guid]::Empty) { $LinkedEmployeeTenantId.ToString() } else { $null }; linkedEmployeeObjectId = if ($LinkedEmployeeObjectId -ne [guid]::Empty) { $LinkedEmployeeObjectId.ToString() } else { $null }; homeTenantId = if ($HomeTenantId -ne [guid]::Empty) { $HomeTenantId.ToString() } else { $null }; organizationVerifiedUtc = if ($OrganizationVerifiedUtc) { ([DateTimeOffset]$OrganizationVerifiedUtc).ToUniversalTime().ToString('o') } else { $null } }
$entries = @($entries | Where-Object { -not ($_.appId -eq $AppId -and $_.tenantId -eq $TenantId.ToString() -and $_.objectId -eq $UserId.ToString()) }) + @($entry)
Write-PocJson $path $entries
$verified = @(Get-PocGraphCollection $context ('/servicePrincipals/' + $app.servicePrincipalId + '/appRoleAssignedTo') | Where-Object { $_.principalId -eq $UserId.ToString() -and $_.appRoleId -eq $roles[0].id })
if ($verified.Count -ne 1) { throw 'Assignment persistence could not be verified.' }
Write-Host ("Verified {0} assignment for explicit user {1}; entitlement expires {2}." -f $Persona, $UserId, $ExpiresUtc.ToUniversalTime().ToString('o'))
