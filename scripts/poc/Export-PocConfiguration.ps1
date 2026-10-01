[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][guid]$WorkforceTenantId,
    [Parameter(Mandatory = $true)][guid]$ExternalTenantId,
    [string[]]$EmployeeDomains = @(),
    [string[]]$ApprovedPartnerDomains = @(),
    [string]$EntitlementFile,
    [switch]$Local,
    [string]$StateDirectory = (Join-Path $env:LOCALAPPDATA 'MultiIdpPoC')
)
. (Join-Path $PSScriptRoot 'Poc.Common.ps1')
if ($EmployeeDomains.Count -eq 0) { throw 'Provide at least one approved employee domain; the classic ASP.NET applications require an explicit workforce route.' }
if (-not $PSCmdlet.ShouldProcess($StateDirectory, 'Export two nonsecret app configuration files and set their process environment references')) { return }
$stateRoot = Get-PocStateDirectory $StateDirectory
$workforce = Read-PocJson (Get-PocManifestPath $stateRoot 'Workforce' $WorkforceTenantId)
$external = Read-PocJson (Get-PocManifestPath $stateRoot 'External' $ExternalTenantId)
foreach ($manifest in @($workforce, $external)) {
    if (-not $manifest -or $manifest.ownerTag -ne 'multiidp-net48-poc-v1') { throw 'Both owned tenant manifests are required. Run Configure-PocApplications for each tenant first.' }
}
if ($workforce.tenantId -ne $WorkforceTenantId.ToString() -or $external.tenantId -ne $ExternalTenantId.ToString()) { throw 'Manifest tenant binding does not match the requested tenants.' }
$workforceMetadata = Get-PocOidcMetadata $WorkforceTenantId 'Workforce'
$externalMetadata = Get-PocOidcMetadata $ExternalTenantId 'External' $external.ciamDomain
foreach ($domain in @($EmployeeDomains) + @($ApprovedPartnerDomains)) {
    if ($domain -notmatch '^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$') { throw 'Routing lists require explicit DNS domain names, without wildcards or email addresses.' }
}
if (-not $EntitlementFile) { $EntitlementFile = Join-Path $stateRoot 'configuration\entitlements.json' }
$entitlementPath = [IO.Path]::GetFullPath($EntitlementFile)
if (-not (Test-Path -LiteralPath $entitlementPath)) { Write-PocJson $entitlementPath @() }
$mode = if ($Local) { 'local' } else { 'cloud' }
foreach ($appId in @('sampleapp01', 'sampleapp02')) {
    $workforceApp = @($workforce.apps | Where-Object { $_.appId -eq $appId })
    $externalApp = @($external.apps | Where-Object { $_.appId -eq $appId })
    if ($workforceApp.Count -ne 1 -or $externalApp.Count -ne 1) { throw "One registration per tenant is required for $appId." }
    $wf = $workforceApp[0]; $ext = $externalApp[0]
    $configuration = [ordered]@{
        appId = $appId
        employeeDomains = @($EmployeeDomains | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
        approvedPartnerDomains = @(if ($appId -eq 'sampleapp02') { $ApprovedPartnerDomains | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique })
        entitlementFile = $entitlementPath
        workforce = @{ tenantId = $WorkforceTenantId.ToString(); clientId = $wf.clientId; clientSecretEnvironmentVariable = $wf.secretEnvironmentVariable; redirectUri = if ($Local) { $wf.localRedirectUri } else { $wf.redirectUri }; issuer = $workforceMetadata.Issuer }
        external = @{ tenantId = $ExternalTenantId.ToString(); clientId = $ext.clientId; clientSecretEnvironmentVariable = $ext.secretEnvironmentVariable; redirectUri = if ($Local) { $ext.localRedirectUri } else { $ext.redirectUri }; issuer = $externalMetadata.Issuer; ciamDomain = $external.ciamDomain }
    }
    $path = Join-Path $stateRoot ('configuration\' + $appId + '.' + $mode + '.json')
    Write-PocJson $path $configuration
    $name = 'MULTIIDP_' + $appId.ToUpperInvariant() + '_CONFIG'
    [Environment]::SetEnvironmentVariable($name, $path, 'Process')
    Write-Host ("{0}={1}" -f $name, $path)
}
Write-Host 'Configuration contains environment variable names, never secret values. Cloud deployment must provide its own absolute entitlement/configuration paths.'
