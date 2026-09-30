# MultiIdpApp

One ASP.NET Core Razor Pages application authenticating against two independent Microsoft Entra identity providers:

- **Workforce tenant** for workforce accounts.
- **External ID external tenant (CIAM)** for customer accounts.

The app is hosted once. Each identity tenant owns a separate Web app registration, enterprise application, user population, and access assignment. External customers do not need guest accounts in the Workforce directory.

This is a generic authentication sample, not a business entitlement system or a production-ready access-governance service. No live tenant, application, credential, deployed resource, or personal account is supplied.

## The heart of the two-IDP setup

The two registrations are next to each other in [`src/MultiIdpApp/Program.cs`](src/MultiIdpApp/Program.cs):

```csharp
authentication.AddMicrosoftIdentityWebApp(
    builder.Configuration.GetSection("AzureAd"),
    WorkforceOidc,
    WorkforceCookie,
    displayName: "Workforce account");

authentication.AddMicrosoftIdentityWebApp(
    builder.Configuration.GetSection("ExternalId"),
    ExternalOidc,
    ExternalCookie,
    displayName: "External ID customer");
```

These are two named OIDC handlers, not two deployed applications. Each handler has its own configuration, callback, tenant/client validation, and cookie. The same file explicitly selects **authorization-code flow with PKCE**, chains Microsoft's token-validation event, validates the expected tenant, and creates trusted application claims.

| Code | Responsibility |
|---|---|
| [`Program.cs`](src/MultiIdpApp/Program.cs) | Register both providers, session policy, cookies, OIDC events, and authorization. |
| [`IdentityRouter.cs`](src/MultiIdpApp/Identity/IdentityRouter.cs) | Validate the entered email and choose the OIDC scheme by domain without a directory lookup. |
| [`SignIn.cshtml.cs`](src/MultiIdpApp/Pages/SignIn.cshtml.cs) | Issue a challenge to the chosen scheme and pass `login_hint`. |
| [`PrincipalNormalizer.cs`](src/MultiIdpApp/Identity/PrincipalNormalizer.cs) | After token validation, enforce tenant/subject and replace application-owned claims. |
| [`IdentityConfiguration.cs`](src/MultiIdpApp/Identity/IdentityConfiguration.cs) | Fail explicitly for missing credentials, invalid tenant configuration, or unsafe proxy trust. |
| [`SignOut.cshtml.cs`](src/MultiIdpApp/Pages/SignOut.cshtml.cs) | Antiforgery-protected POST logout, clear both cookies, and sign out from the active provider. |

## What the sample demonstrates

1. A public home page and one email-based sign-in entry point.
2. Workforce domains **and their subdomains** route to Workforce; all other valid domains route to External ID.
3. Separate `/signin-oidc` and `/signin-external-oidc` callbacks.
4. Independent issuer, audience, signature, lifetime, and expected-tenant validation.
5. Normalized `identity_source`, `app_tenant_id`, `app_subject`, and optional `app_email` claims.
6. One protected session page for either population.
7. Separate secure cookies, opposite-cookie removal, a fixed one-hour session lifetime, and active-provider logout.

The router is not proof of a person's identity or account existence. An External ID user with a Workforce-listed email domain will route to Workforce; there is no automatic fallback to the other provider.

## Prerequisites

- .NET 10 SDK; approved package access to public NuGet.
- A Workforce tenant and a separate External ID **external** tenant.
- Administrative permission to register apps, grant consent, configure assignments, manage the external user flow, and provision test users.
- Two single-tenant Web registrations with separate credentials and correct redirect/logout URLs.
- An external sign-up/sign-in user flow associated with the External registration.
- A Workforce email-domain allowlist and real, non-admin test accounts.
- HTTPS and an approved secret store. Cloud deployment also needs Azure hosting permissions and an approved subscription/budget.
- For controlled onboarding: approval to disable external self-service sign-up using the currently documented Graph beta administration operation.

See [the deployment guide](docs/DEPLOYMENT.md) for roles, billing, tenant creation, consent, MFA, exact callbacks, local configuration, Azure hosting, and acceptance checks.

## Run locally

The checked-in credentials and domains are intentionally empty. The app **fails startup until you provide your own configuration**.

```powershell
dotnet restore .\MultiIdpApp.slnx --configfile .\NuGet.Config --locked-mode
dotnet build .\MultiIdpApp.slnx -c Release --no-restore
dotnet run --project .\tests\MultiIdpApp.Tests\MultiIdpApp.Tests.csproj `
    -c Release --no-build --no-restore
dotnet dev-certs https --trust
```

Follow [local configuration](docs/DEPLOYMENT.md#4-configure-local-development) to enter credentials with protected prompts and User Secrets. Then:

```powershell
dotnet run --project .\src\MultiIdpApp\MultiIdpApp.csproj --launch-profile https
```

Open `https://localhost:7016`. Register that HTTPS listener's sign-in and post-logout callbacks in both tenants.

## Components and versions

| Component | Resolved version | Purpose |
|---|---|---|
| .NET / ASP.NET Core | Target `net10.0` | Web host, Razor Pages, cookies, authorization, antiforgery, HTTPS. |
| Microsoft.Identity.Web | 4.15.0 | Microsoft Entra integration and named web-app authentication schemes. |
| Microsoft.Identity.Client (MSAL.NET) | 4.90.0 | Transitive Microsoft authentication library used by Microsoft.Identity.Web; not called directly by the page models. |
| Microsoft.Identity.Client.Extensions.Msal | 4.83.1 | Transitive cache-persistence helpers; this sample does not configure a distributed token cache. |
| Microsoft.AspNetCore.Authentication.OpenIdConnect | 10.0.10 | OIDC handler, authorization-code flow, PKCE, correlation, and token validation. |
| Microsoft.AspNetCore.Authentication.JwtBearer | 10.0.10 | Pinned dependency compatibility; no bearer API endpoint is configured in this sample. |
| Microsoft.IdentityModel token/protocol libraries | 8.22.0 | Token, issuer, signing-key and OIDC protocol support. |

[COMPONENTS.md](docs/COMPONENTS.md) lists the complete resolved package graph, direct/transitive distinction, and validated SDK/runtime versions. Both projects commit `packages.lock.json`; the public `NuGet.Config` prevents relying on a workstation's private feeds.

## Deployment and limitations

Use [DEPLOYMENT.md](docs/DEPLOYMENT.md) for a single Linux Azure App Service deployment with Key Vault references and an explicit trusted-proxy configuration. Leave App Service platform authentication disabled when the application owns this two-provider sign-in flow.

Before production, implement business authorization/entitlements, immediate revocation or session revalidation, a supported credential strategy, protected/shared Data Protection keys as required by the hosting topology, monitoring, recovery, and load/availability validation. Default app assignment controls new admission; it does not automatically invalidate an already-issued application cookie.

The session page shows only the authenticated user's own selected claims. Do not publish real screenshots, raw tokens, cookies, passwords, secret values, or tenant/resource identifiers. Build outputs, local configuration, credentials, documents, and recordings are excluded from the source repository.

## Microsoft references

- [Multiple authentication schemes in Microsoft.Identity.Web](https://github.com/AzureAD/microsoft-identity-web/wiki/multiple-authentication-schemes)
- [Create an External ID external tenant](https://learn.microsoft.com/en-us/entra/external-id/customers/how-to-create-external-tenant-portal)
- [External user-flow configuration](https://learn.microsoft.com/en-us/entra/external-id/customers/how-to-user-flow-sign-up-sign-in-customers)
- [Authorization-code flow and PKCE](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
