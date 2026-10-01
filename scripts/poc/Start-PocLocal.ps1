[CmdletBinding()]
param(
    [string]$StateDirectory = (Join-Path $env:LOCALAPPDATA 'MultiIdpPoC'),
    [string]$IisExpressPath,
    [string]$ApplicationHostConfig,
    [string]$Site01 = 'sampleapp01',
    [string]$Site02 = 'sampleapp02'
)
. (Join-Path $PSScriptRoot 'Poc.Common.ps1')
if (-not $IisExpressPath) {
    foreach ($candidate in @((Join-Path $env:ProgramFiles 'IIS Express\iisexpress.exe'), (Join-Path ${env:ProgramFiles(x86)} 'IIS Express\iisexpress.exe'))) {
        if (Test-Path -LiteralPath $candidate) { $IisExpressPath = $candidate; break }
    }
}
if (-not $IisExpressPath -or -not (Test-Path -LiteralPath $IisExpressPath)) { throw 'Official Microsoft IIS Express is not installed. Install it, configure HTTPS bindings on 44371/44372, then rerun this script.' }
$stateRoot = Get-PocStateDirectory $StateDirectory
if (-not $ApplicationHostConfig -or -not (Test-Path -LiteralPath $ApplicationHostConfig)) { throw 'Provide an IIS Express applicationhost.config with the two HTTPS sites and trusted certificates. This script does not install certificates or rewrite IIS configuration.' }
foreach ($appId in @('sampleapp01', 'sampleapp02')) {
    $configPath = Join-Path $stateRoot ('configuration\' + $appId + '.local.json')
    $configuration = Read-PocJson $configPath
    if (-not $configuration -or $configuration.appId -ne $appId) { throw 'Export local configurations before launching IIS Express.' }
    [Environment]::SetEnvironmentVariable(('MULTIIDP_' + $appId.ToUpperInvariant() + '_CONFIG'), $configPath, 'Process')
    foreach ($tenant in @($configuration.workforce, $configuration.external)) {
        $name = $tenant.clientSecretEnvironmentVariable
        if ($name -notmatch '^MULTIIDP_SAMPLEAPP0[12]_(WORKFORCE|EXTERNAL)_SECRET$') { throw 'An unexpected secret environment name was found in local configuration.' }
        $protectedPath = Join-Path $stateRoot ('secrets\' + $name + '.clixml')
        $secureValue = Import-Clixml -LiteralPath $protectedPath
        if ($secureValue -isnot [Security.SecureString]) { throw 'A protected credential file did not contain a SecureString.' }
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureValue)
        try { [Environment]::SetEnvironmentVariable($name, [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer), 'Process') }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    }
}
$arguments = @('/config:"' + [IO.Path]::GetFullPath($ApplicationHostConfig) + '"', '/site:' + $Site01, '/systray:false')
$first = Start-Process -FilePath $IisExpressPath -ArgumentList $arguments -WindowStyle Hidden -PassThru
$second = Start-Process -FilePath $IisExpressPath -ArgumentList @('/config:"' + [IO.Path]::GetFullPath($ApplicationHostConfig) + '"', '/site:' + $Site02, '/systray:false') -WindowStyle Hidden -PassThru
Write-Host ("Started IIS Express processes {0}, {1}. Verify https://localhost:44371 and https://localhost:44372 before demonstrating sign-in." -f $first.Id, $second.Id)
