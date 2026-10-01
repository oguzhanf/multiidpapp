[CmdletBinding()]
param(
    [Parameter(Mandatory)][uri]$BaseUri
)
$ErrorActionPreference = 'Stop'
if ($BaseUri.Scheme -ne 'https' -or $BaseUri.AbsolutePath -ne '/') { throw 'Use the HTTPS driver origin without a path.' }
Add-Type -AssemblyName System.Net.Http
$handler = [Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $false
$handler.UseCookies = $false
$client = [Net.Http.HttpClient]::new($handler)
$client.BaseAddress = $BaseUri
$client.Timeout = [TimeSpan]::FromSeconds(45)
try {
    foreach ($path in @('/','/index.html','/entra-setup.html','/login-routing.html','/login-routing.js','/migration-sampleapp01.html','/migration.css','/site.css','/site.js','/code-samples.js','/lab-settings.json','/source/net48-source.zip','/source/SAMPLEAPP01-IMPLEMENTATION-HANDOFF.md','/unlisted-page.html')) {
        $response = $client.GetAsync($path).GetAwaiter().GetResult()
        try {
            $status = [int]$response.StatusCode
            if ($status -notin @(302,303,307,401,403)) { throw "FAIL anonymous content restriction at $path (HTTP $status)." }
            if ($status -in @(302,303,307)) {
                $location = $response.Headers.Location
                if (-not $location) { throw "FAIL missing authentication redirect at $path." }
                $target = [uri]::new($BaseUri,$location)
                if ($target.Host -ne $BaseUri.Host -or $target.AbsolutePath -notmatch '^/\.auth/login/') { throw "FAIL unexpected anonymous redirect at $path." }
            }
            Write-Output "PASS anonymous access blocked: $path"
        } finally { $response.Dispose() }
    }
    $spoof = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get,'/index.html')
    $null = $spoof.Headers.TryAddWithoutValidation('X-MS-CLIENT-PRINCIPAL-ID','11111111-1111-4111-8111-111111111111')
    $null = $spoof.Headers.TryAddWithoutValidation('X-MS-CLIENT-PRINCIPAL-NAME','spoof@example.invalid')
    $null = $spoof.Headers.TryAddWithoutValidation('X-MS-CLIENT-PRINCIPAL','eyJhdXRoX3R5cCI6ImFhZCIsImNsYWltcyI6W119')
    $response = $client.SendAsync($spoof).GetAwaiter().GetResult()
    try {
        if ([int]$response.StatusCode -notin @(302,303,307,401,403)) { throw 'FAIL spoofed identity headers bypassed authentication.' }
        Write-Output 'PASS spoofed identity headers cannot access driver content.'
    } finally { $response.Dispose(); $spoof.Dispose() }
    $response = $client.GetAsync('/.auth/me').GetAwaiter().GetResult()
    try {
        if ([int]$response.StatusCode -eq 200) {
            $identities = @($response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json)
            if ($identities.Count) { throw 'FAIL anonymous identity endpoint returned an authenticated identity.' }
        } elseif ([int]$response.StatusCode -notin @(302,303,307,401,403)) { throw 'FAIL unexpected anonymous identity endpoint status.' }
        Write-Output 'PASS anonymous identity endpoint exposes no authenticated identity.'
    } finally { $response.Dispose() }
} finally { $client.Dispose(); $handler.Dispose() }
