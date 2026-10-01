[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][Guid]$WorkforceTenantId,
    [Parameter(Mandatory)][Guid]$ExternalTenantId,
    [Parameter(Mandatory)][string]$WorkforceDomain,
    [Parameter(Mandatory)][string]$ExternalDomain,
    [string]$StateDirectory = (Join-Path $env:LOCALAPPDATA 'MultiIdpPoC')
)
. (Join-Path $PSScriptRoot 'Poc.Common.ps1')
if (-not $PSCmdlet.ShouldProcess('The two PoC directories', 'Create three non-admin synthetic test accounts and protect their temporary passwords with Windows DPAPI')) { return }
$stateRoot = Get-PocStateDirectory $StateDirectory
$recordPath = Join-Path $stateRoot 'test-users.json'
$records = @(Read-PocJson $recordPath | Where-Object {$null -ne $_})
$workforce = Get-PocGraphContext $WorkforceTenantId Workforce
$external = Get-PocGraphContext $ExternalTenantId External
foreach ($item in @(
    @{persona='Employee';kind='Workforce';tenantId="$WorkforceTenantId";email="poc.employee@$WorkforceDomain";name='PoC employee (synthetic)';context=$workforce},
    @{persona='Retiree';kind='External';tenantId="$ExternalTenantId";email="poc.retiree@$ExternalDomain";name='PoC retiree (synthetic)';context=$external},
    @{persona='Dependent';kind='External';tenantId="$ExternalTenantId";email="poc.dependent@$ExternalDomain";name='PoC dependent (synthetic)';context=$external}
)) {
    $previous = @($records | Where-Object {$_.tenantId -eq $item.tenantId -and $_.persona -eq $item.persona})
    if ($previous.Count -gt 1) { throw 'Duplicate saved test accounts.' }
    if ($previous.Count -eq 1) {
        $live = Invoke-PocGraph $item.context ('/users/' + $previous[0].objectId + '?$select=id,accountEnabled')
        if (-not $live.accountEnabled) { throw 'An existing test account is disabled. Do not silently reactivate it.' }
        continue
    }
    $email = $item.email
    $filter = if ($item.kind -eq 'Workforce') { "userPrincipalName eq '$email'" } else { "identities/any(i:i/issuerAssignedId eq '$email' and i/issuer eq '$ExternalDomain')" }
    $collision = @(Get-PocGraphCollection $item.context ('/users?$filter=' + [uri]::EscapeDataString($filter) + '&$select=id'))
    if ($collision.Count -gt 0) { throw "A test account already exists for $email without a saved record. Refusing to change its password." }
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {$rng.GetBytes($bytes)} finally {$rng.Dispose()}
    $password = [Convert]::ToBase64String($bytes) + '!aA3'
    $body = @{accountEnabled=$true;displayName=$item.name;passwordProfile=@{password=$password;forceChangePasswordNextSignIn=$false}}
    if ($item.kind -eq 'Workforce') { $body.userPrincipalName=$email; $body.mailNickname='poc.employee' }
    else { $body.identities=@(@{signInType='emailAddress';issuer=$ExternalDomain;issuerAssignedId=$email}); $body.passwordPolicies='DisablePasswordExpiration' }
    $user = Invoke-PocGraph -Context $item.context -Method POST -Path '/users' -Body $body
    $credentialFile = Join-Path $stateRoot ('secrets\test-' + $item.persona.ToLowerInvariant() + '.clixml')
    $credential = [Management.Automation.PSCredential]::new($email, (ConvertTo-SecureString $password -AsPlainText -Force))
    $credential | Export-Clixml -LiteralPath $credentialFile
    $password=$null; $body=$null; $credential=$null
    $records += @{tenantId=$item.tenantId;tenantKind=$item.kind;persona=$item.persona;objectId=$user.id;signInEmail=$email;credentialFile=$credentialFile;synthetic=$true}
    Write-PocJson $recordPath $records
    Write-Output "Created non-admin synthetic $($item.persona) account; password saved as DPAPI in $credentialFile."
}
Write-Output "Test account inventory: $recordPath. These accounts have no mailbox; do not use them to claim email delivery or recovery works."
