# Two IIS ASP.NET Framework 4.8 demonstrations

`sampleapp01` and `sampleapp02` are **.NET Framework 4.8 / System.Web MVC applications**, built with SDK-style projects. They share source in `Shared`; they are separate IIS applications with separate cookie names, registrations, callbacks and credentials. The existing ASP.NET Core application elsewhere in this repository is a separate example.

Sampleapp01 admits workforce employees and approved External ID retirees/dependents/other external users. Sampleapp02 additionally admits approved workforce B2B partners. An email is a routing hint. Exact configured employee domains select workforce; explicitly onboarded partner domains select workforce only in sampleapp02; other valid addresses select External ID. A workforce authentication failure never changes the selected provider.

## Build and tests

On Windows with the .NET SDK and .NET Framework 4.8 runtime:

```powershell
dotnet build samples/net48/sampleapp01/sampleapp01.csproj -p:RestoreLockedMode=true
dotnet build samples/net48/sampleapp02/sampleapp02.csproj -p:RestoreLockedMode=true
dotnet build tests/Net48/Net48.Tests.csproj -p:RestoreLockedMode=true
& tests/Net48/bin/Debug/net48/Net48.Tests.exe
```

The three projects are also grouped in `samples/net48/MultiIdp.Net48.sln`.

If this machine's workload resolver is broken, append `-p:MSBuildEnableWorkloadResolver=false`. The NuGet reference-assemblies package permits compilation without Visual Studio. A Windows IIS runtime is needed to run the web apps. Output dependencies are in each application's `bin` folder. Deploy **web.config, Global.asax, and the complete bin folder**; do not use ASP.NET Core `dotnet publish` conventions or run the DLL with `dotnet`.

The executable policy suite checks exact routing, cross-app/tenant/object denial, duplicate claims/records, issuer/audience checks, signed persona roles, expiry, revocation, sponsor/relationship/benefit approval and signed B2B home organization. Its identities are synthetic test inputs, not proof that any real account was verified. Fresh IIS HTTPS challenge and completed tenant login are separate integration checks.

After IIS deployment, run `tests/Net48/Smoke-Iis.ps1 -BaseUri <https-origin> -EmployeeEmail <employee-domain-address> -ExternalEmail <external-address> -PartnerEmail <approved-domain-address>`, adding `-App02` for sampleapp02. It checks live HTTPS routing, CSRF rejection, protected-page behavior, inaccessible App_Data files, nonce cookie attributes and code/PKCE/state/nonce challenges without printing protocol secrets. It does not submit user credentials or complete tenant login.

## IIS and configuration

Create separate IIS applications/site bindings using CLR **v4.0**, integrated pipeline and .NET Framework 4.8. Enable **Anonymous Authentication** for the apps and disable IIS Windows Authentication: OWIN owns the application sign-in. HTTPS is required. This is the migration point from Kerberos/Negotiate: existing domain credentials no longer establish the web application's principal; Entra OIDC establishes it. Review a real migration's identity mapping, session behavior and downstream delegation separately.

The configuration loader reads the absolute JSON filename from `MULTIIDP_SAMPLEAPP01_CONFIG` or `MULTIIDP_SAMPLEAPP02_CONFIG` in the actual IIS process environment. Keep local configuration/credentials outside the repository. For Windows App Service, an absolute file in `D:\home\site\wwwroot\App_Data` is supported because `web.config` explicitly protects `App_Data` as an IIS hidden segment. Never place config or entitlement JSON in a public static folder. Apply filesystem permissions for the app pool identity and deployment administrators only. IIS app pool processes do not inherit variables set in an unrelated interactive shell; configure app-pool environment or App Service app settings, then recycle. A current-user IIS Express launcher can inherit environment from its launcher.

For sampleapp01, an example **without credentials** is:

```json
{
  "appId": "sampleapp01",
  "employeeDomains": ["employee.example"],
  "approvedPartnerDomains": [],
  "entitlementFile": "C:\\ProgramData\\MultiIdpPoC\\entitlements.json",
  "workforce": {
    "tenantId": "11111111-1111-1111-1111-111111111111",
    "clientId": "33333333-3333-3333-3333-333333333333",
    "clientSecretEnvironmentVariable": "MULTIIDP_SAMPLEAPP01_WORKFORCE_SECRET",
    "redirectUri": "https://localhost:44371/signin-workforce",
    "issuer": "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0"
  },
  "external": {
    "tenantId": "22222222-2222-2222-2222-222222222222",
    "clientId": "44444444-4444-4444-4444-444444444444",
    "clientSecretEnvironmentVariable": "MULTIIDP_SAMPLEAPP01_EXTERNAL_SECRET",
    "redirectUri": "https://localhost:44371/signin-external",
    "ciamDomain": "yourtenant.ciamlogin.com",
    "issuer": "https://22222222-2222-2222-2222-222222222222.ciamlogin.com/22222222-2222-2222-2222-222222222222/v2.0"
  }
}
```

Replace all values with real tenant discovery/registration values; CIAM's discovery issuer may use a GUID hostname. Do not guess the issuer from the friendly hostname. Sampleapp02 uses `appId=sampleapp02`, HTTPS port 44372, its **own two client IDs**, and the two environment variables `MULTIIDP_SAMPLEAPP02_WORKFORCE_SECRET` / `MULTIIDP_SAMPLEAPP02_EXTERNAL_SECRET`. All four registrations are single-tenant Web clients. Register each exact HTTPS `/signin-workforce` or `/signin-external` URI, including the deployed hostname. Associate each External ID registration with its sign-up/sign-in user flow. Secrets are read server-side from environment and never rendered or stored in source.

A missing/invalid configuration leaves the public home page available with an actionable configuration message. It does not permit an authentication challenge or benefit access.

## Protocol and admission

`Shared/Startup.cs` registers two passive OWIN schemes with separate callbacks and tenant-specific discovery authorities. Katana creates PKCE, protects state and verifier, handles cookies, and runs ID-token/protocol validation. `Shared/StrictJwtSecurityTokenHandler.cs` forces signed tokens and signing-key validation at the JWT validation boundary because Katana 4.2.3 relaxes `RequireSignedTokens` in its code-flow branch. Standard JWT issuer, audience and lifetime checks continue. `Shared/MsalOpenIdConnect.cs` overrides only `RedeemAuthorizationCodeAsync`: direct MSAL.NET exchanges the code with the recovered PKCE verifier, then returns the token response to Katana's normal validation pipeline. It intentionally does **not** call `HandleCodeRedemption`, which would bypass Katana's normal token-response nonce validation. MSAL is a token-acquisition library; OWIN/MVC provides the web authentication/session integration. MSAL authority omits `/v2.0`; OWIN authority includes it. Tokens are transient server input, not saved in the application cookie, logs or HTML.

Admission requires signed `tid`, `oid`, exact `iss`/`aud`, an application role matching the persona, and a server-controlled entitlement keyed by **appId + issuing tenantId + objectId**. Signed directory roles are exactly `Employee`, `Retiree`, `Dependent`, `Partner`, `External`. Email, self-declared registration fields and display names grant no rights. Configure directory app-role assignments and assignment-required enterprise applications. Role/entitlement admission is checked during callback and rechecked on every protected page request. The app cookie is Secure, HttpOnly, SameSite=Lax, host-only, separate per app, and expires after 20 minutes without sliding renewal. Login and local app logout are antiforgery-protected POSTs. Logout terminates this app's cookie; the provider's SSO session may remain.

The central entitlement JSON is an array. This **synthetic dependent example** illustrates the schema:

```json
[
  {
    "appId": "sampleapp01",
    "tenantId": "22222222-2222-2222-2222-222222222222",
    "objectId": "55555555-5555-5555-5555-555555555555",
    "source": "external",
    "persona": "dependent",
    "sponsor": "approved-employee-relationship-record-001",
    "status": "approved",
    "expiresUtc": "2027-01-01T00:00:00Z",
    "relationshipVerified": true,
    "benefitEligible": true,
    "linkedEmployeeTenantId": "11111111-1111-1111-1111-111111111111",
    "linkedEmployeeObjectId": "88888888-8888-8888-8888-888888888888"
  }
]
```

Employee records require workforce source. Retiree/dependent/external records require External ID source and sponsor; dependents additionally require verified employee relationship and benefit eligibility. A dependent must link through `linkedEmployeeTenantId` + `linkedEmployeeObjectId` to exactly one same-app workforce employee record with current approved status, unexpired approval and `benefitEligible=true`. The synthetic example above is denied until this parent record exists. Revoking the parent denies the child on its next request. Partner records require sampleapp02, workforce source, sponsor, `homeTenantId` and an already established `organizationVerifiedUtc`. Enable optional ID-token claim `idp` on workforce registrations. The signed B2B `idp` must equal `https://sts.windows.net/<homeTenantId>/` or `https://login.microsoftonline.com/<homeTenantId>/v2.0`; missing, consumer, email-OTP or a different home organization is denied. The `oid` is the workforce guest object's ID. A verified email domain alone never establishes Microsoft 365 partner identity. Other issuer forms require deliberate review and an updated policy, not a permissive fallback. The administrator must verify the organizational account and its home organization before creating the entitlement. Actual live claims must still be checked with an onboarded guest.

Disable `status` or change `expiresUtc` to revoke the next protected request; the file reloads on each check and duplicates fail closed. These fields model governance approval; they do not perform HR validation themselves. Keep real approval/relationship records server-side, update files atomically, and use the customer's governed store for production.

Microsoft documentation: [OWIN OpenID Connect](https://learn.microsoft.com/en-us/previous-versions/aspnet/dn782620(v=vs.113)), [MSAL authorization code API](https://learn.microsoft.com/en-us/dotnet/api/microsoft.identity.client.iconfidentialclientapplication.acquiretokenbyauthorizationcode), [ID-token claims and guest idp](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference), [External ID authentication endpoints](https://learn.microsoft.com/en-us/entra/external-id/customers/concept-supported-features-customers), [App roles](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps).

Pinned packages/lock files record the tested dependency graph. When upgrading, keep IdentityModel package versions aligned and regenerate matching System.Web binding redirects before deployment.
