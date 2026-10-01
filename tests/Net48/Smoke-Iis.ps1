[CmdletBinding()]
param(
    [Parameter(Mandatory)][uri]$BaseUri,
    [Parameter(Mandatory)][string]$EmployeeEmail,
    [string]$ExternalEmail = 'poc-routing-check@example.invalid',
    [string]$PartnerEmail,
    [switch]$App02
)
$ErrorActionPreference = 'Stop'
if ($BaseUri.Scheme -ne 'https') { throw 'Smoke tests require an HTTPS IIS endpoint.' }
Add-Type -AssemblyName System.Net.Http
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$handler = New-Object Net.Http.HttpClientHandler
$handler.AllowAutoRedirect = $false
$handler.CookieContainer = New-Object Net.CookieContainer
$client = New-Object Net.Http.HttpClient($handler)
$client.BaseAddress = $BaseUri
$client.Timeout = [TimeSpan]::FromSeconds(45)
function Assert-Check([bool]$Condition, [string]$Name) {
    if (-not $Condition) { throw "FAIL $Name" }
    Write-Output "PASS $Name"
}
function Send-Form([string]$Path, [hashtable]$Fields) {
    $pairs = New-Object 'Collections.Generic.Dictionary[string,string]'
    foreach ($key in $Fields.Keys) { $pairs.Add($key, [string]$Fields[$key]) }
    $content = New-Object Net.Http.FormUrlEncodedContent($pairs)
    try { return $client.PostAsync($Path, $content).GetAwaiter().GetResult() }
    finally { $content.Dispose() }
}
function Test-Challenge([string]$Email, [string]$Provider, [string]$Token) {
    $response = Send-Form '/Account/Login' @{ email = $Email; __RequestVerificationToken = $Token }
    try {
        Assert-Check ([int]$response.StatusCode -eq 302) "$Provider challenge returns redirect"
        $location = $response.Headers.Location
        Assert-Check ($location -ne $null -and $location.Scheme -eq 'https') "$Provider challenge uses HTTPS"
        $hostMatch = if ($Provider -eq 'workforce') { $location.Host -eq 'login.microsoftonline.com' } else { $location.Host.EndsWith('.ciamlogin.com') }
        Assert-Check $hostMatch "$Provider selected authority host"
        $query = [Web.HttpUtility]::ParseQueryString($location.Query)
        Assert-Check ($query['response_type'] -eq 'code') "$Provider code-only flow"
        Assert-Check ($query['code_challenge_method'] -eq 'S256' -and -not [string]::IsNullOrWhiteSpace($query['code_challenge'])) "$Provider PKCE S256"
        Assert-Check (-not [string]::IsNullOrWhiteSpace($query['state']) -and -not [string]::IsNullOrWhiteSpace($query['nonce'])) "$Provider protected state and nonce"
        Assert-Check ($query['redirect_uri'].EndsWith('/signin-' + $Provider)) "$Provider separate callback"
        Assert-Check ($query['login_hint'] -eq $Email) "$Provider email is routing hint"
        # Do not print state, nonce, cookies or token-bearing protocol messages.
        if ($response.Headers.Contains('Set-Cookie')) {
            $cookies = $response.Headers.GetValues('Set-Cookie')
            Assert-Check (($cookies | Where-Object { $_ -match 'OpenIdConnect.nonce' -and $_ -match '(?i)secure' -and $_ -match '(?i)httponly' }).Count -gt 0) "$Provider nonce cookie secure and HttpOnly"
        }
    } finally { $response.Dispose() }
}
try {
    Add-Type -AssemblyName System.Web
    $taskHomeResponse = $client.GetAsync('/').GetAwaiter().GetResult()
    $html = $taskHomeResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    Assert-Check ([int]$taskHomeResponse.StatusCode -eq 200 -and $html -match 'ASP.NET Framework 4.8') 'public IIS Framework home'
    Assert-Check ($html -notmatch 'Configuration needed') 'application has valid configuration'
    $match = [regex]::Match($html, 'name="__RequestVerificationToken"[^>]*value="([^"]+)"')
    Assert-Check $match.Success 'login antiforgery form rendered'
    $token = [Web.HttpUtility]::HtmlDecode($match.Groups[1].Value)
    $taskHomeResponse.Dispose()
    $noToken = Send-Form '/Account/Login' @{ email = $EmployeeEmail }
    Assert-Check ([int]$noToken.StatusCode -eq 400) 'login without CSRF token rejected'
    $noToken.Dispose()
    $logout = Send-Form '/Account/Logout' @{}
    Assert-Check ([int]$logout.StatusCode -eq 400) 'logout without CSRF token rejected'
    $logout.Dispose()
    $private = $client.GetAsync('/Benefits/Index').GetAwaiter().GetResult()
    Assert-Check ([int]$private.StatusCode -eq 302 -and $private.Headers.Location.OriginalString -eq '/') 'protected page requires sign-in'
    $private.Dispose()
    foreach ($path in @('/App_Data/identity.json', '/App_Data/entitlements.json')) {
        $hidden = $client.GetAsync($path).GetAwaiter().GetResult()
        Assert-Check ([int]$hidden.StatusCode -eq 404) "IIS hides $path"
        $hidden.Dispose()
    }
    Test-Challenge $EmployeeEmail 'workforce' $token
    Test-Challenge $ExternalEmail 'external' $token
    if ($PartnerEmail) { Test-Challenge $PartnerEmail $(if ($App02) { 'workforce' } else { 'external' }) $token }
    Write-Output 'HTTPS IIS smoke complete. Interactive tenant login, code redemption and benefit admission were not exercised.'
} finally { $client.Dispose(); $handler.Dispose() }
