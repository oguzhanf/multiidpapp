[CmdletBinding()]
param(
    [string]$OutputPath
)
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
if (-not $OutputPath) { $OutputPath = Join-Path $repoRoot 'driver\code-samples.js' }

# Publish source only. Runtime configuration, identities, entitlements and credentials
# are deliberately outside this fixed whitelist.
$shared = @(
    @{ path='samples/net48/Directory.Build.props'; title='Framework and NuGet references'; description='Targets net48 and pins MVC, OWIN, MSAL and token-validation libraries.'; language='xml' },
    @{ path='samples/net48/Shared/Configuration.cs'; title='Two tenant configurations'; description='Loads separate authorities, client IDs, callbacks and server-side credential variable names.'; language='csharp' },
    @{ path='samples/net48/Shared/Startup.cs'; title='Workforce and External ID authentication'; description='Registers both OIDC providers, PKCE, token validation and the application cookie.'; language='csharp' },
    @{ path='samples/net48/Shared/MsalOpenIdConnect.cs'; title='MSAL authorization-code redemption'; description='Redeems the code with its protected PKCE verifier and returns the ID token to Katana validation.'; language='csharp' },
    @{ path='samples/net48/Shared/StrictJwtSecurityTokenHandler.cs'; title='Require signed tokens'; description='Keeps signature validation mandatory in the OWIN code-flow handler.'; language='csharp' },
    @{ path='samples/net48/Shared/Policy.cs'; title='Routing and application access'; description='Routes identities and checks roles, approval, expiry, dependent relationships and partner home organization.'; language='csharp' },
    @{ path='samples/net48/Shared/Controllers.cs'; title='Sign-in and protected application actions'; description='Challenges the selected provider and checks current entitlement before showing application access.'; language='csharp' },
    @{ path='samples/net48/Shared/Registration.cs'; title='Invitation policy and governance'; description='Checks employee capabilities, creates single-use links and atomically records account-bound approvals.'; language='csharp' },
    @{ path='samples/net48/Shared/RegistrationControllers.cs'; title='Invite and complete registration'; description='Shows role-gated forms and completes registration through protected OIDC state and CSRF-checked confirmation.'; language='csharp' },
    @{ path='samples/net48/Shared/RegistrationServices.cs'; title='Directory provisioning and email'; description='Resolves Microsoft organizations, provisions External ID or B2B accounts and sends links through Azure Communication Services.'; language='csharp' },
    @{ path='samples/net48/Shared/PasswordSetupController.cs'; title='Invitation email verification and password creation'; description='Validates the invitation, checks the sponsor, and runs CSRF-protected email verification and password creation screens.'; language='csharp' },
    @{ path='samples/net48/Shared/PasswordSetup.cs'; title='Microsoft native password setup protocol'; description='Calls start, challenge, continue, submit and poll_completion; keeps continuation tokens in a short-lived server session and never uses them for app sign-in.'; language='csharp' }
)
$files = @($shared)
$apps = [ordered]@{}
foreach ($appId in @('sampleapp01','sampleapp02')) {
    $specific = @(
        @{ path="samples/net48/$appId/$appId.csproj"; title="$appId project"; description='Sets this application assembly and compile-time identity; imports the shared net48 build settings.'; language='xml' },
        @{ path="samples/net48/$appId/web.config"; title="$appId IIS configuration"; description='Configures ASP.NET 4.8, OWIN startup, secure cookies, protected App_Data and assembly bindings.'; language='xml' }
    )
    $files += $specific
    $apps[$appId] = @($specific[0].path) + @($shared | ForEach-Object { $_.path }) + @($specific[1].path)
}
$published = foreach ($file in $files) {
    $sourcePath = Join-Path $repoRoot $file.path
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) { throw "Missing public source file: $($file.path)" }
    [ordered]@{
        path = $file.path
        title = $file.title
        description = $file.description
        language = $file.language
        content = [IO.File]::ReadAllText($sourcePath)
    }
}
$catalog = [ordered]@{ files=@($published); apps=$apps }
$json = (ConvertTo-Json -InputObject $catalog -Depth 8 -Compress).Replace('<','\u003c').Replace('>','\u003e').Replace('&','\u0026')
$scriptContent = "// Generated from the public source whitelist by Export-PocCodeSamples.ps1.`nwindow.pocCodeSamples = " + $json + ";`n"
[IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath), $scriptContent, [Text.UTF8Encoding]::new($false))
Write-Output ('Published {0} non-secret source files for both applications.' -f @($published).Count)
