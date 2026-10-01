Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PocStateDirectory {
    param([string]$Path = (Join-Path $env:LOCALAPPDATA 'MultiIdpPoC'))
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'These scripts require Windows and DPAPI CurrentUser protection.' }
    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..')).TrimEnd('\')
    if ($fullPath -eq $repoRoot -or $fullPath.StartsWith($repoRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'StateDirectory must be outside the repository.'
    }
    if (-not (Test-Path -LiteralPath $fullPath)) { $null = New-Item -ItemType Directory -Path $fullPath }
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = [IO.Directory]::GetAccessControl($fullPath, [Security.AccessControl.AccessControlSections]::Access)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($entry in @($acl.Access)) { $acl.RemoveAccessRuleSpecific($entry) }
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
    [IO.Directory]::SetAccessControl($fullPath, $acl)
    foreach ($name in @('manifests', 'secrets', 'configuration')) {
        $directory = Join-Path $fullPath $name
        if (-not (Test-Path -LiteralPath $directory)) { $null = New-Item -ItemType Directory -Path $directory }
    }
    return $fullPath
}

function Get-PocManifestPath {
    param([string]$StateDirectory, [string]$TenantKind, [guid]$TenantId)
    Join-Path $StateDirectory ('manifests\{0}-{1}.json' -f $TenantKind.ToLowerInvariant(), $TenantId.ToString())
}

function Read-PocJson {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $document = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    return $document
}

function Write-PocJson {
    param([string]$Path, [object]$Value)
    $temporaryPath = $Path + '.tmp'
    [IO.File]::WriteAllText($temporaryPath, (ConvertTo-Json -InputObject $Value -Depth 20), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
}

function ConvertFrom-PocJwtPayload {
    param([string]$Token)
    $parts = $Token.Split('.')
    if ($parts.Length -ne 3) { throw 'Azure CLI returned a token that cannot be inspected for tenant/user binding.' }
    $payload = $parts[1].Replace('-', '+').Replace('_', '/')
    $payload = $payload.PadRight($payload.Length + ((4 - $payload.Length % 4) % 4), '=')
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
}

function Get-PocGraphContext {
    param([guid]$TenantId, [ValidateSet('Workforce', 'External')][string]$TenantKind)
    if ($TenantId -eq [guid]::Empty) { throw 'A nonempty tenant ID is required.' }
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) { throw 'Azure CLI is required. Sign in to the expected tenant with an administrator account first.' }
    $token = (& az account get-access-token --tenant $TenantId.ToString() --resource-type ms-graph --query accessToken --output tsv 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $token) { throw 'Could not obtain a delegated Microsoft Graph token for the requested tenant. Run az login --tenant <tenant-id> --allow-no-subscriptions.' }
    $claims = ConvertFrom-PocJwtPayload $token
    if ([guid]$claims.tid -ne $TenantId) { throw 'Microsoft Graph token tenant does not match TenantId.' }
    if (-not $claims.PSObject.Properties['scp'] -or -not $claims.scp -or -not $claims.PSObject.Properties['oid']) {
        throw 'An administrator USER account with a delegated Graph token is required; application tokens are refused.'
    }
    if ($claims.PSObject.Properties['idtyp'] -and $claims.idtyp -eq 'app') { throw 'Application-only tokens are refused.' }
    $context = @{ TenantId = $TenantId.ToString(); Headers = @{ Authorization = 'Bearer ' + $token }; UserObjectId = [guid]$claims.oid }
    $me = Invoke-PocGraph -Context $context -Path '/me?$select=id,userType'
    if ([guid]$me.id -ne $context.UserObjectId) { throw 'Graph /me does not match the delegated token user.' }
    $adminRoles = @('62e90394-69f5-4237-9190-012177145e10', '158c047a-c907-4556-b7ef-446551a6b5f7')
    if ($TenantKind -eq 'Workforce') { $adminRoles += '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' }
    $roles = @()
    if ($claims.PSObject.Properties['wids']) { $roles += @($claims.wids) }
    if (-not ($roles | Where-Object { $_ -in $adminRoles })) {
        $memberships = @(Get-PocGraphCollection -Context $context -Path '/me/transitiveMemberOf/microsoft.graph.directoryRole?$select=id,roleTemplateId')
        $roles += @($memberships | ForEach-Object { $_.roleTemplateId })
    }
    if (-not ($roles | Where-Object { $_ -in $adminRoles })) { throw 'Activate Global Administrator or Cloud Application Administrator for this tenant. Workforce also permits Application Administrator.' }
    return $context
}

function Invoke-PocGraph {
    param([hashtable]$Context, [string]$Path, [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')][string]$Method = 'GET', [object]$Body)
    $uri = if ($Path.StartsWith('https://graph.microsoft.com/')) { $Path } else { 'https://graph.microsoft.com/v1.0' + $Path }
    if (-not $uri.StartsWith('https://graph.microsoft.com/', [StringComparison]::Ordinal)) { throw 'Graph requests are restricted to graph.microsoft.com.' }
    $arguments = @{ Uri = $uri; Method = $Method; Headers = $Context.Headers; ErrorAction = 'Stop' }
    if ($null -ne $Body) { $arguments.ContentType = 'application/json'; $arguments.Body = $Body | ConvertTo-Json -Depth 20 -Compress }
    try { Invoke-RestMethod @arguments }
    catch {
        $status = 'unknown'
        if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        $errorCode = 'unknown'
        try { $errorCode = ($_.ErrorDetails.Message | ConvertFrom-Json).error.code } catch { }
        throw ('Microsoft Graph {0} {1} failed with HTTP {2} ({3}). Verify tenant roles, consent and the operation; no request body or credentials are logged.' -f $Method, $Path.Split('?')[0], $status, $errorCode)
    }
}

function Get-PocGraphCollection {
    param([hashtable]$Context, [string]$Path)
    do {
        $response = Invoke-PocGraph -Context $Context -Path $Path
        foreach ($item in @($response.value)) { $item }
        $Path = if ($response.PSObject.Properties['@odata.nextLink']) { $response.'@odata.nextLink' } else { $null }
    } while ($Path)
}

function Get-PocHttpsRoot {
    param([string]$Value)
    $uri = [uri]$Value
    if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or $uri.Query -or $uri.Fragment -or $uri.UserInfo -or $uri.AbsolutePath -ne '/') {
        throw 'App base URLs must be absolute HTTPS roots, without a path, query, fragment or user information.'
    }
    $uri.AbsoluteUri.TrimEnd('/')
}

function Get-PocOidcMetadata {
    param([guid]$TenantId, [ValidateSet('Workforce', 'External')][string]$TenantKind, [string]$CiamDomain)
    $hostName = 'login.microsoftonline.com'
    if ($TenantKind -eq 'External') {
        if ($CiamDomain -notmatch '^[a-zA-Z0-9-]+\.ciamlogin\.com$') { throw 'CiamDomain must be the external tenant subdomain.ciamlogin.com hostname.' }
        $hostName = $CiamDomain.ToLowerInvariant()
    }
    $metadataUrl = 'https://{0}/{1}/v2.0/.well-known/openid-configuration' -f $hostName, $TenantId.ToString()
    $metadata = Invoke-RestMethod -Uri $metadataUrl -Method GET -ErrorAction Stop
    $issuer = [uri]$metadata.issuer
    if ($issuer.Scheme -ne 'https' -or $issuer.Query -or $issuer.Fragment -or $issuer.UserInfo -or $issuer.AbsolutePath.TrimEnd('/') -ne ('/{0}/v2.0' -f $TenantId.ToString())) {
        throw 'Live OIDC discovery issuer does not bind to the expected tenant.'
    }
    if (($TenantKind -eq 'Workforce' -and $issuer.Host -ne 'login.microsoftonline.com') -or ($TenantKind -eq 'External' -and $issuer.Host -notmatch '^[a-zA-Z0-9-]+\.ciamlogin\.com$')) {
        throw 'Live discovery returned an unexpected issuer host.'
    }
    return @{ Issuer = [string]$metadata.issuer; MetadataUrl = $metadataUrl; CiamDomain = $CiamDomain }
}
