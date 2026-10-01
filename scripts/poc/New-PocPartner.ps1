[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][Guid]$WorkforceTenantId,
    [Parameter(Mandatory)][string]$PartnerEmail,
    [Parameter(Mandatory)][Guid]$HomeTenantId,
    [Parameter(Mandatory)][string]$App02BaseUrl,
    [string]$StateDirectory=(Join-Path $env:LOCALAPPDATA 'MultiIdpPoC')
)
. (Join-Path $PSScriptRoot 'Poc.Common.ps1')
$email=[Net.Mail.MailAddress]::new($PartnerEmail)
if ($email.Address -ne $PartnerEmail) { throw 'Enter an exact partner email address.' }
$root=Get-PocHttpsRoot $App02BaseUrl
$metadata=Invoke-RestMethod -Uri ('https://login.microsoftonline.com/'+$email.Host+'/v2.0/.well-known/openid-configuration')
if ($metadata.issuer -ne "https://login.microsoftonline.com/$HomeTenantId/v2.0") { throw 'The partner domain does not resolve to the explicitly approved home tenant.' }
if ($HomeTenantId -eq $WorkforceTenantId) { throw 'Partners must have a separate approved organizational home tenant.' }
if (-not $PSCmdlet.ShouldProcess($PartnerEmail, 'Create a workforce B2B guest invitation without sending email; the home organizational authentication must still be redeemed and validated')) { return }
$stateRoot=Get-PocStateDirectory $StateDirectory
$context=Get-PocGraphContext $WorkforceTenantId Workforce
$path=Join-Path $stateRoot 'partner.json'
$record=Read-PocJson $path
if ($record) {
    if ($record.email -ne $PartnerEmail -or $record.homeTenantId -ne "$HomeTenantId" -or $record.workforceTenantId -ne "$WorkforceTenantId") { throw 'Another saved partner exists. Use a separate state directory.' }
    $live=Invoke-PocGraph $context ('/users/'+$record.objectId+'?$select=id,userType,accountEnabled,externalUserState')
    if ($live.userType -ne 'Guest' -or -not $live.accountEnabled) { throw 'Saved partner guest is missing or disabled.' }
    Write-Output "Existing partner guest verified. Redemption state: $($live.externalUserState)."
    return
}
$invitation=Invoke-PocGraph -Context $context -Method POST -Path '/invitations' -Body @{invitedUserEmailAddress=$PartnerEmail;invitedUserDisplayName='PoC organizational partner';inviteRedirectUrl=$root;sendInvitationMessage=$false}
$record=@{workforceTenantId="$WorkforceTenantId";homeTenantId="$HomeTenantId";email=$PartnerEmail;objectId=$invitation.invitedUser.id;inviteRedeemUrl=$invitation.inviteRedeemUrl;organizationVerifiedUtc=[DateTimeOffset]::UtcNow.ToString('o');verification='Home tenant discovery validated; signed idp and guest object checked at application admission.'}
Write-PocJson $path $record
Write-Output "Partner guest created without email. Private redemption link and object ID are saved in $path. Invitation is not proof of successful organizational authentication."
