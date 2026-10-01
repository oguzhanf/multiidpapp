[CmdletBinding()]
param(
    [Parameter(Mandatory)][Guid]$SubscriptionId,
    [Parameter(Mandatory)][Guid]$WorkforceTenantId,
    [Parameter(Mandatory)][Guid]$ExternalTenantId,
    [string]$ResourceGroup='rg-caldova-multiidp-poc',
    [string]$NameSuffix='07279263',
    [string]$StateDirectory=(Join-Path $env:LOCALAPPDATA 'MultiIdpPoC'),
    [ValidateSet('sampleapp01','sampleapp02')][string[]]$ApplicationIds=@('sampleapp01','sampleapp02'),
    [switch]$DriverOnly
)
. (Join-Path $PSScriptRoot 'Poc.Common.ps1')
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$stateRoot = Get-PocStateDirectory $StateDirectory
$account = (& az account show --subscription "$SubscriptionId" -o json) | ConvertFrom-Json
if ($LASTEXITCODE -or $account.tenantId -ne "$WorkforceTenantId") { throw 'Wrong hosting subscription tenant.' }
& (Join-Path $PSScriptRoot 'Export-PocCodeSamples.ps1')
$stageRoot = Join-Path $repoRoot ('artifacts\deploy-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null
$lab = @{apps=@{}}
foreach ($appId in @('sampleapp01','sampleapp02')) {
    $config = Read-PocJson (Join-Path $stateRoot "configuration\$appId.cloud.json")
    if (-not $config -or $config.appId -ne $appId -or $config.workforce.tenantId -ne "$WorkforceTenantId" -or $config.external.tenantId -ne "$ExternalTenantId") { throw 'Both tenant-bound cloud configurations are required.' }
    $lab.apps[$appId] = @{baseUrl=([Uri]$config.workforce.redirectUri).GetLeftPart([UriPartial]::Authority);workforceTenantId=$config.workforce.tenantId;workforceClientId=$config.workforce.clientId;workforceIssuer=$config.workforce.issuer;employeeDomains=($config.employeeDomains -join ',');approvedPartnerDomains=($config.approvedPartnerDomains -join ',');externalTenantId=$config.external.tenantId;externalClientId=$config.external.clientId;ciamDomain=$config.external.ciamDomain;externalIssuer=$config.external.issuer}
    if ($DriverOnly -or $appId -notin $ApplicationIds) { continue }
    $logs = (& az webapp log show --subscription "$SubscriptionId" -g $ResourceGroup -n "caldova-$appId-$NameSuffix" -o json) | ConvertFrom-Json
    if ($LASTEXITCODE -or $logs.httpLogs.fileSystem.enabled -or $logs.httpLogs.azureBlobStorage.enabled -or $logs.failedRequestsTracing.enabled -or $logs.detailedErrorMessages.enabled) { throw 'Invitation sites require URL request logging, request tracing and detailed errors to remain disabled so bearer links are not retained in application request logs.' }
    $projectRoot = Join-Path $repoRoot "samples\net48\$appId"
    & dotnet build (Join-Path $projectRoot "$appId.csproj") -c Release --no-restore
    if ($LASTEXITCODE) { throw "$appId build failed." }
    $stage = Join-Path $stageRoot $appId
    New-Item -ItemType Directory -Path "$stage\bin","$stage\App_Data" -Force | Out-Null
    Copy-Item -LiteralPath "$projectRoot\web.config","$projectRoot\Global.asax" -Destination $stage
    Copy-Item -LiteralPath "$repoRoot\driver\code-samples.js" -Destination $stage
    Copy-Item -Path "$projectRoot\bin\*.dll" -Destination "$stage\bin"
    $sourceEntitlementFile=$config.entitlementFile
    if (-not $sourceEntitlementFile -or -not (Test-Path -LiteralPath $sourceEntitlementFile)) { throw 'The configured governance file is missing.' }
    $config.entitlementFile='D:\home\site\wwwroot\App_Data\entitlements.json'
    Write-PocJson "$stage\App_Data\identity.json" $config
    Copy-Item -LiteralPath $sourceEntitlementFile -Destination "$stage\App_Data\entitlements.json"
    $registration = Read-PocJson (Join-Path $stateRoot "configuration\$appId.registration.json")
    if ($registration) {
        if ($registration.appId -ne $appId -or $registration.workforce.tenantId -ne "$WorkforceTenantId" -or $registration.external.tenantId -ne "$ExternalTenantId" -or $registration.appBaseUrl -ne $lab.apps[$appId].baseUrl) { throw 'Registration configuration does not match this application and tenant pair.' }
        $registration.stateFile="D:\home\data\multiidp\$appId\registration-state.json"
        Write-PocJson "$stage\App_Data\registration.json" $registration
        # Runtime state lives outside wwwroot, which ZIP deployment can replace.
        # Never package or replace registration-state.json or its lock file.
    }
    $settings = @{}
    $settings['MULTIIDP_' + $appId.ToUpperInvariant() + '_CONFIG']='D:\home\site\wwwroot\App_Data\identity.json'
    if ($registration) { $settings['MULTIIDP_' + $appId.ToUpperInvariant() + '_REGISTRATION_CONFIG']='D:\home\site\wwwroot\App_Data\registration.json' }
    foreach ($tenant in @($config.workforce,$config.external)) {
        $name=$tenant.clientSecretEnvironmentVariable
        if ($name -notmatch '^MULTIIDP_SAMPLEAPP0[12]_(WORKFORCE|EXTERNAL)_SECRET$') { throw 'Unexpected secret setting name.' }
        $secure=Import-Clixml -LiteralPath (Join-Path $stateRoot "secrets\$name.clixml")
        $settings[$name]=[Net.NetworkCredential]::new('', $secure).Password
    }
    $settingFile = Join-Path $stateRoot "$appId-appsettings.json"
    try {
        Write-PocJson $settingFile $settings
        & az webapp config appsettings set --subscription "$SubscriptionId" -g $ResourceGroup -n "caldova-$appId-$NameSuffix" --settings "@$settingFile" -o none
        if ($LASTEXITCODE) { throw 'App Service settings failed.' }
    } finally { $settings=$null; if (Test-Path -LiteralPath $settingFile) { Remove-Item -LiteralPath $settingFile -Force } }
    $zip="$stage.zip"
    Compress-Archive -Path "$stage\*" -DestinationPath $zip
    & az webapp deploy --subscription "$SubscriptionId" -g $ResourceGroup -n "caldova-$appId-$NameSuffix" --src-path $zip --type zip --async true -o none
    if ($LASTEXITCODE) { throw 'Application deployment failed.' }
}
$driver = Join-Path $stageRoot 'driver'
New-Item -ItemType Directory -Path "$driver\source" -Force | Out-Null
Copy-Item -LiteralPath "$repoRoot\driver\index.html","$repoRoot\driver\site.css","$repoRoot\driver\site.js","$repoRoot\driver\code-samples.js","$repoRoot\driver\web.config" -Destination $driver
$driverHtml = [IO.File]::ReadAllText((Join-Path $driver 'index.html'))
foreach ($asset in @('site.css','site.js','code-samples.js')) {
    $version = (Get-FileHash -LiteralPath (Join-Path $driver $asset) -Algorithm SHA256).Hash.ToLowerInvariant().Substring(0,16)
    $driverHtml = $driverHtml.Replace('"' + $asset + '"', '"' + $asset + '?v=' + $version + '"')
}
[IO.File]::WriteAllText((Join-Path $driver 'index.html'), $driverHtml, [Text.UTF8Encoding]::new($false))
Write-PocJson "$driver\lab-settings.json" $lab
$sourceStage=Join-Path $stageRoot 'source'
New-Item -ItemType Directory -Path "$sourceStage\samples\net48","$sourceStage\scripts\poc","$sourceStage\tests\Net48" -Force | Out-Null
foreach ($relative in @('samples\net48','scripts\poc','tests\Net48','docs\poc','driver')) {
    foreach ($file in Get-ChildItem -LiteralPath (Join-Path $repoRoot $relative) -Recurse -File | Where-Object {$_.FullName -notmatch '\\(bin|obj)\\' -and $_.Extension -notin @('.dll','.exe','.pdb','.clixml')}) {
        $destination=Join-Path $sourceStage $file.FullName.Substring($repoRoot.Length+1)
        New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($destination)) -Force | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $destination
    }
}
Copy-Item -LiteralPath "$repoRoot\NuGet.Config","$repoRoot\global.json" -Destination $sourceStage
Compress-Archive -Path "$sourceStage\*" -DestinationPath "$driver\source\net48-source.zip"
Compress-Archive -Path "$driver\*" -DestinationPath "$stageRoot\driver.zip"
& az webapp deploy --subscription "$SubscriptionId" -g $ResourceGroup -n "caldova-pocdriver-$NameSuffix" --src-path "$stageRoot\driver.zip" --type zip --async true -o none
if ($LASTEXITCODE) { throw 'Driver deployment failed.' }
Write-Output "Deployment submitted. Verify all three HTTPS sites and protected App_Data before claiming completion. Staging: $stageRoot"
