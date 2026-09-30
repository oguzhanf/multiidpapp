# Components and exact versions

Versions below describe the restored sample, not a claim that every version is the latest. The authoritative machine-readable graph is `src/MultiIdpApp/packages.lock.json`; the test project has its own lock file.

## Framework and tooling

| Component | Version / rule |
|---|---|
| Target framework | `net10.0` |
| SDK used for local validation | `10.0.401` |
| ASP.NET Core / .NET runtime used for local validation | `10.0.12` |
| SDK selection | `global.json`: minimum feature band `10.0.100`, roll forward to the latest installed .NET 10 feature band, no prerelease SDKs |
| Hosted runtime | A serviced .NET 10 runtime; the hosting platform controls the installed patch |
| Frontend | Razor Pages and repository-owned CSS; no JavaScript library/CDN dependency |
| Tests | .NET 10 executable harness and ASP.NET Core shared framework; no extra test-framework package |

## Direct packages

| Package | Resolved version | Use |
|---|---|---|
| Microsoft.Identity.Web | 4.15.0 | Entra web-app authentication and two named schemes. |
| Microsoft.AspNetCore.Authentication.OpenIdConnect | 10.0.10 | OIDC authorization-code/PKCE handler. |
| Microsoft.AspNetCore.Authentication.JwtBearer | 10.0.10 | Explicitly pinned dependency version; the app does not register a bearer API. |

## Transitive packages

| Package | Resolved version |
|---|---|
| Azure.Core | 1.50.0 |
| Azure.Identity | 1.17.2 |
| Azure.Security.KeyVault.Certificates | 4.6.0 |
| Azure.Security.KeyVault.Secrets | 4.6.0 |
| Microsoft.Bcl.AsyncInterfaces | 8.0.0 |
| Microsoft.Bcl.Cryptography | 10.0.2 |
| Microsoft.Identity.Abstractions | 12.7.0 |
| **Microsoft.Identity.Client (MSAL.NET)** | **4.90.0** |
| Microsoft.Identity.Client.Extensions.Msal | 4.83.1 |
| Microsoft.Identity.Web.Certificate | 4.15.0 |
| Microsoft.Identity.Web.Certificateless | 4.15.0 |
| Microsoft.Identity.Web.Diagnostics | 4.15.0 |
| Microsoft.Identity.Web.TokenAcquisition | 4.15.0 |
| Microsoft.Identity.Web.TokenCache | 4.15.0 |
| Microsoft.IdentityModel.Abstractions | 8.22.0 |
| Microsoft.IdentityModel.JsonWebTokens | 8.22.0 |
| Microsoft.IdentityModel.Logging | 8.22.0 |
| Microsoft.IdentityModel.LoggingExtensions | 8.22.0 |
| Microsoft.IdentityModel.Protocols | 8.22.0 |
| Microsoft.IdentityModel.Protocols.OpenIdConnect | 8.22.0 |
| Microsoft.IdentityModel.Tokens | 8.22.0 |
| Microsoft.IdentityModel.Validators | 8.22.0 |
| System.ClientModel | 1.8.0 |
| System.IdentityModel.Tokens.Jwt | 8.22.0 |
| System.Memory.Data | 8.0.1 |
| System.Security.Cryptography.Pkcs | 10.0.10 |
| System.Security.Cryptography.ProtectedData | 4.5.0 |

The page models do not instantiate MSAL directly. Microsoft.Identity.Web brings the MSAL libraries into the dependency graph. Merely resolving cache, certificate, or Azure SDK packages does not mean this sample configures those capabilities. In particular, it does not add a downstream Graph/API client or a distributed token cache, and App Service resolves the deployment guide's Key Vault references outside application code.

`Microsoft.Identity.Web.UI` is not needed: the sample owns its sign-in, session, and sign-out Razor Pages.

## Reproduce and maintain

```powershell
dotnet restore .\MultiIdpApp.slnx --configfile .\NuGet.Config --locked-mode
dotnet list .\src\MultiIdpApp\MultiIdpApp.csproj package --include-transitive
dotnet list .\src\MultiIdpApp\MultiIdpApp.csproj package `
    --vulnerable --include-transitive
```

For a deliberate dependency update, edit the package references, regenerate the lock files using the public feed, update this table to match the resolved graph, then build and run the tests. Do not change a version table independently of the actual lock file.

The runtime patch is separate from the NuGet OIDC package version. Keep the hosting runtime serviced even while package versions remain locked.
