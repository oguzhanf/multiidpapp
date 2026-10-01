[CmdletBinding()]
param(
    [Parameter(Mandatory)][Guid]$SubscriptionId,
    [Parameter(Mandatory)][Guid]$WorkforceTenantId,
    [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9]{1,26}$')][string]$ExternalSubdomain,
    [string]$ResourceGroup = 'rg-caldova-multiidp-poc',
    [string]$ResourceGroupLocation = 'westeurope',
    [string]$HostingRegion = 'swedencentral',
    [string]$TenantCountry = 'AE',
    [ValidateSet('Europe','United States','Asia Pacific','Australia')][string]$TenantLocation = 'Europe',
    [string]$NameSuffix = '07279263'
)
$ErrorActionPreference = 'Stop'
function Invoke-AzChecked([string[]]$Arguments) {
    $result = & az @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'Azure CLI operation failed. Review the preceding service error.' }
    return $result
}
$account = (Invoke-AzChecked @('account','show','--subscription',"$SubscriptionId",'-o','json')) | ConvertFrom-Json
if ($account.tenantId -ne "$WorkforceTenantId") { throw 'Subscription belongs to a different workforce tenant.' }
$groupExists = (Invoke-AzChecked @('group','exists','--subscription',"$SubscriptionId",'-n',$ResourceGroup,'-o','tsv')).Trim()
if ($groupExists -eq 'true') {
    $existingGroup = (Invoke-AzChecked @('group','show','--subscription',"$SubscriptionId",'-n',$ResourceGroup,'-o','json')) | ConvertFrom-Json
    if ($existingGroup.tags.purpose -ne 'multiidp-poc') { throw 'The existing resource group is not tagged as this PoC. Refusing to adopt it.' }
    $ResourceGroupLocation = $existingGroup.location
} else {
    Invoke-AzChecked @('group','create','--subscription',"$SubscriptionId",'-n',$ResourceGroup,'-l',$ResourceGroupLocation,'--tags','purpose=multiidp-poc','-o','none') | Out-Null
}
$resourceUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.AzureActiveDirectory/ciamDirectories/${ExternalSubdomain}?api-version=2023-05-17-preview"
$stateDir = Join-Path $env:LOCALAPPDATA 'MultiIdpPoC'
New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
$directoryFile = Join-Path $stateDir 'create-directory.json'
@{ location=$TenantLocation; sku=@{name='Base';tier='A0'}; properties=@{createTenantProperties=@{displayName='Caldova Multi IDP PoC';countryCode=$TenantCountry}}; tags=@{purpose='multiidp-poc'} } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $directoryFile -Encoding UTF8
Invoke-AzChecked @('rest','--subscription',"$SubscriptionId",'--method','put','--url',$resourceUri,'--body',"@$directoryFile",'-o','none') | Out-Null
$planName = 'asp-caldova-multiidp-poc'
Invoke-AzChecked @('appservice','plan','create','--subscription',"$SubscriptionId",'-g',$ResourceGroup,'-n',$planName,'-l',$HostingRegion,'--sku','B1','--tags','purpose=multiidp-poc','-o','none') | Out-Null
$sites = @()
foreach ($app in @('sampleapp01','sampleapp02','pocdriver')) {
    $name = "caldova-$app-$NameSuffix"
    $site = (Invoke-AzChecked @('webapp','create','--subscription',"$SubscriptionId",'-g',$ResourceGroup,'-p',$planName,'-n',$name,'--runtime','ASPNET:V4.8','--https-only','true','--tags','purpose=multiidp-poc','-o','json')) | ConvertFrom-Json
    Invoke-AzChecked @('webapp','config','set','--subscription',"$SubscriptionId",'-g',$ResourceGroup,'-n',$name,'--always-on','true','--min-tls-version','1.2','--ftps-state','Disabled','-o','none') | Out-Null
    $sites += @{appId=$app;name=$name;baseUrl="https://$($site.defaultHostName)"}
}
$directory = (Invoke-AzChecked @('rest','--subscription',"$SubscriptionId",'--method','get','--url',$resourceUri,'-o','json')) | ConvertFrom-Json
$manifest = @{subscriptionId="$SubscriptionId";resourceGroup=$ResourceGroup;resourceGroupLocation=$ResourceGroupLocation;hostingRegion=$HostingRegion;plan=$planName;externalTenantId=$directory.properties.tenantId;externalSubdomain=$ExternalSubdomain;sites=$sites}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $stateDir 'infrastructure.json') -Encoding UTF8
Write-Output "Infrastructure saved in $stateDir\infrastructure.json. Tenant provisioning state: $($directory.properties.provisioningState). Wait for an allocated tenant ID before directory setup."
