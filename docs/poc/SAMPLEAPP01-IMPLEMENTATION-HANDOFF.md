# Sampleapp01: implementation brief for an existing ASP.NET Framework 4.8 application

Use this file as the task specification for the developer's coding agent. It is self-contained; attach the reference source ZIP or provide repository access as well. It contains no customer credentials or live identity records.

## Task for the coding agent

Modify the customer's existing IIS-hosted ASP.NET .NET Framework 4.8 application to support employees in an Entra workforce tenant and approved retirees/dependents in a separate Entra External ID **external tenant**. Preserve the existing application, business screens, user keys and successful workforce MSAL integration. Implement the Sampleapp01 model below, including employee-sponsored dependent registration. Do not replace the application with ASP.NET Core or convert its project format merely to match the sample.

Inspect the actual repository first. Identify the existing authentication, login, authorization, configuration, user lookup and registration locations. Produce a short file-by-file change map, then implement the changes, run appropriate checks and report the result. If tenant values or a production dependency are missing, use clearly marked synthetic test configuration for independent work and list the remaining inputs. Do not invent tenant settings or report unexercised sign-ins as passing.

## Reference implementation

- Repository: <https://github.com/oguzhanf/multiidpapp>
- Working branch: `poc/net48-dual-tenant`.
- Historical baseline: commit `44affa2182337c337a0756016019f37cb7166960`. It includes the tested pending-registration login correction and predates the automatic workforce-account lookup described below. Use the supplied current source ZIP or matching reviewed branch revision for that routing implementation; do not copy the historical domain router for this requirement.
- [Download the reference repository at that revision](https://github.com/oguzhanf/multiidpapp/archive/44affa2182337c337a0756016019f37cb7166960.zip), or use the source ZIP supplied by the PoC owner.
- Source directory: `samples/net48/Shared/`; app-specific project/configuration: `samples/net48/sampleapp01/`.
- Reference tests: `tests/Net48/`.
- Web guide: <https://caldova-pocdriver-07279263.azurewebsites.net/migration-sampleapp01.html>. The hosted driver requires its approved operator's sign-in; the customer agent must not depend on having that account. Use the supplied source ZIP or repository instead.

Repository paths below are reference locations, **not assumed paths in the customer's project**. Read the complete files before adapting partial examples. This PoC uses Katana OIDC with a custom MSAL code-redemption adapter; it is not a Microsoft-provided External ID Framework web quickstart. Microsoft also offers `Microsoft.Identity.Web.OWIN`; using that alternative needs separate dual-provider adaptation and verification.

## Required behavior

| Persona | Authentication source | Required signed app role | Application approval |
|---|---|---|---|
| Employee | Customer workforce tenant | `Employee` | Current same-app employee approval |
| Dependent | Dedicated External ID tenant | `Dependent` | Verified relationship, benefit eligibility and link to a current eligible same-app workforce employee |
| Retiree | Dedicated External ID tenant | `Retiree` | Approved retirement eligibility, accountable sponsor and expiry |
| Other approved personal customer, if enabled | Dedicated External ID tenant | `External` | Explicit app approval, sponsor and expiry |

This brief covers Sampleapp01's employees and approved personal customer identities. Its employee role permits dependent invitations only when the employee's approval and benefit eligibility are current. Automated retiree enrollment is a separate customer workflow; the sample demonstrates retiree admission, not a retirement-verification system.

One login entry point selects one of two passive OIDC providers. Both providers issue the application's secure cookie. Authentication proves identity; the app's governance rules decide access. A failed workforce sign-in must not automatically retry External ID.

## 1. Find the customer's change locations

Inventory MVC, Web Forms or mixed hosting, the project/NuGet format, `Global.asax`, OWIN startup, existing MSAL code, login/logout screens, protected pages/actions/endpoints, employee lookups, AD group checks and deployment settings. Search for `WindowsIdentity`, `WindowsPrincipal`, `DOMAIN\\user`, impersonation, integrated SQL authentication and file-share access.

| Existing location to identify | Required change | Reference file |
|---|---|---|
| `.csproj`, `packages.config` or PackageReference | Compatible dependencies and assembly redirects | `samples/net48/Directory.Build.props` |
| `Startup.cs` / `App_Start/Startup.Auth.cs` | Two providers, secure app cookie and validation callbacks | `Shared/Startup.cs` |
| Existing code-redemption handler | MSAL confidential client per provider; preserve PKCE/state/nonce | `Shared/MsalOpenIdConnect.cs` |
| Token validator | Mandatory signature, issuer, audience and lifetime checks | `Shared/StrictJwtSecurityTokenHandler.cs` |
| Private configuration loader | Separate tenant/client/callback/credential settings | `Shared/Configuration.cs` |
| Login controller/page event and directory adapter | Exact entered UPN lookup in the configured workforce tenant, then selected-provider challenge | `Shared/Controllers.cs`, `Shared/RegistrationServices.cs` |
| Workforce account resolver | Server-side Graph lookup; confirmed absence versus unavailable result | `Shared/WorkforceAccountResolver.cs` |
| User/employee repository and shared access guard | Stable identity mapping and current business approval | `Shared/Policy.cs`, `Shared/RegistrationControllers.cs` |
| Employee invitation/recipient pages | Role-gated invitation and confirmation | `Shared/RegistrationControllers.cs` |
| Governance/invitation repository | Bound invitation, one-use redemption and approvals | `Shared/Registration.cs` |
| Provisioning and email integration | Graph adapters, sponsor refresh and ACS sender | `Shared/RegistrationServices.cs` |
| Recipient account setup | Email verification and password creation | `Shared/PasswordSetup.cs`, `Shared/PasswordSetupController.cs` |
| `web.config`, IIS application/pool, `Application_Start` | OWIN hosting, routes, cookies, protected files and binding redirects | `sampleapp01/web.config`, `Shared/Startup.cs` |

Preserve customer routes/services in `Application_Start`. Keep **one** OWIN startup entry point. In a Web Forms application, either port the screen handlers with the same security checks or host the sample's MVC registration endpoints alongside the pages; merge MVC routes and `AntiforgeryFailureFilter` registration. Do not replace `Global.asax` with the sample wholesale.

## 2. Align dependencies

The reference build uses these versions; these are tested versions, not a claim that they are the latest:

| Package | Reference version |
|---|---|
| `Microsoft.Identity.Client` | `4.90.1` |
| `Microsoft.Owin.Host.SystemWeb` | `4.2.3` |
| `Microsoft.Owin.Security.Cookies` | `4.2.3` |
| `Microsoft.Owin.Security.OpenIdConnect` | `4.2.3` |
| `Microsoft.IdentityModel.Protocols.OpenIdConnect` | `8.23.0` |
| `Microsoft.IdentityModel.Tokens` | `8.23.0` |
| `System.IdentityModel.Tokens.Jwt` | `8.23.0` |
| `Newtonsoft.Json` | `13.0.4` |
| `Microsoft.AspNet.Mvc`, when retaining sample MVC code | `5.3.0` |

Install through the customer's existing NuGet workflow, retain target Framework 4.8, include adapted source as normal project items, and reconcile compatible versions and `web.config` binding redirects. A classic non-SDK project does not need `Directory.Build.props` or SDK conversion. If copying shared `Startup.cs` unchanged, define `SAMPLEAPP01` so conditional compilation selects this application's identity and policy. Keep `appId=sampleapp01` for the reference PoC. A different customer application identifier requires updating `RegistrationPolicy.KnownApp`, every app-specific policy/routing branch, configuration names and approval/invitation store scoping consistently, with regression checks; changing only the JSON value is insufficient.

## 3. Supply tenant and server settings

Obtain these from the customer's tenant administrator/private deployment configuration:

- Workforce tenant ID, existing or agreed workforce client ID, exact discovery issuer and the server-side Graph identity/permissions for account lookup.
- External tenant ID, CIAM hostname, separate external client ID, exact discovery issuer and controlled user-flow association.
- HTTPS application origin and separate registered **Web** callbacks `/signin-workforce` and `/signin-external`. Existing callbacks must remain consistent with the working integration during migration; update code and registration together if adopting the reference paths.
- Separate server-side credentials, app-role assignments, approval store, sponsor/relationship source, email sender and provisioning identities.
- A separate public/native setup client associated with the controlled EmailPassword flow if using the reference password-creation extension.

Both interactive registrations are tenant-specific, require assignment and use code with PKCE; leave implicit issuance disabled. Keep public signup disabled for the invitation-only model. Obtain the external issuer from discovery: it may use a GUID-based CIAM host even when the authority uses a friendly hostname. Do not construct an expected issuer from an assumption.

Define the exact role values in each app registration's **App roles**; assign users through its corresponding **Enterprise application → Users and groups**. Create role GUIDs in the customer's registrations; do not copy Caldova role or service-principal IDs. The sample expects direct sponsor-role assignments unless the group-resolution adapter is implemented.

Example **synthetic** configuration matching the reference schema:

```json
{
  "appId": "sampleapp01",
  "employeeDomains": [],
  "approvedPartnerDomains": [],
  "workforce": {
    "tenantId": "11111111-1111-4111-8111-111111111111",
    "clientId": "33333333-3333-4333-8333-333333333331",
    "issuer": "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/v2.0",
    "redirectUri": "https://trips.example/signin-workforce",
    "clientSecretEnvironmentVariable": "MULTIIDP_SAMPLEAPP01_WORKFORCE_SECRET"
  },
  "external": {
    "tenantId": "22222222-2222-4222-8222-222222222222",
    "clientId": "44444444-4444-4444-8444-444444444441",
    "ciamDomain": "customer-example.ciamlogin.com",
    "issuer": "https://22222222-2222-4222-8222-222222222222.ciamlogin.com/22222222-2222-4222-8222-222222222222/v2.0",
    "redirectUri": "https://trips.example/signin-external",
    "clientSecretEnvironmentVariable": "MULTIIDP_SAMPLEAPP01_EXTERNAL_SECRET"
  },
  "entitlementFile": "C:\\PocPrivate\\sampleapp01\\entitlements.json"
}
```

Replace every synthetic tenant/domain/client value privately before a real sign-in. `MULTIIDP_SAMPLEAPP01_CONFIG` points to an absolute protected config path. Credential values stay in the server secret mechanism; the JSON records variable names only. The IIS worker needs access to its configuration and secret settings after pool recycle.

### Automatic workforce account lookup across all UPN domains

Sampleapp01's login calls `RegistrationRuntime.RouteAsync`, backed by `WorkforceAccountResolver.ResolveAsync`, to query the configured **workforce tenant** through Microsoft Graph for the exact entered UPN. It does not maintain an employee-domain allowlist or synchronize a list of verified domains. Accounts such as `employee@company.example`, `employee@subsidiary.example` and `employee@tenant.onmicrosoft.com` use the same lookup; these synthetic suffixes are examples, not configuration entries. `employeeDomains` is retained in the shared configuration schema for compatibility and can be empty for Sampleapp01; it must not decide this first-stage account route.

An existing exact UPN selects `workforce`, including a found disabled account or Guest; finding an object grants no access. Directory sign-in, the signed app role and current application approval still apply. Only a confirmed absence selects `external`. A lookup permission/service error, timeout or invalid response must fail with an unavailable result (HTTP 503), never be treated as absence or retry External ID.

Every workforce account found across the tenant's UPN suffixes selects the same `workforce` scheme, authority, client ID and `/signin-workforce` callback. No provider, client or list entry is needed per suffix. Require the actual UPN: Graph lookup does not automatically resolve SMTP aliases. Even if the customer's Entra sign-in policy supports an alternate email, this lookup needs a separately designed, tested resolver before accepting that alternative.

A UPN change on the **same directory account** retains its `tid` and `oid`, so the existing internal-user mapping and current approval remain tied to that account; the new exact UPN is looked up without changing a domain list. Deleting/recreating an account, or using another tenant's account, produces a different stable identity and requires explicit mapping and approval; the old email or UPN must not transfer access automatically.

Registration uses separate configuration (`MULTIIDP_SAMPLEAPP01_REGISTRATION_CONFIG` in the sample). Never commit production identities, recipient addresses, invitation tokens/hashes, credentials or live governance records. Keep durable invitation/approval storage outside folders replaced by deployment.

## 4. Extend authentication and login

Register one secure application cookie before the two passive schemes `workforce` and `external`. Use separate clients, authorities and callbacks. The reference cookie is `Secure`, `HttpOnly`, `SameSite=Lax`, scoped to `/`, with a 20-minute non-sliding lifetime. Preserve Katana's protected state, nonce and PKCE handling.

Partial reference excerpts; adapt the **complete** surrounding validation and error handling:

```csharp
// Startup.AddProvider: independent settings for each provider.
var authority = external
    ? "https://" + tenant.CiamDomain + "/" + tenant.TenantId
    : "https://login.microsoftonline.com/" + tenant.TenantId;
var msal = ConfidentialClientApplicationBuilder.Create(tenant.ClientId)
    .WithClientSecret(secret).WithAuthority(authority)
    .WithRedirectUri(tenant.RedirectUri).Build();
// OWIN Authority = authority + "/v2.0".

// MsalOpenIdConnectHandler: recover verifier from protected OIDC state.
var result = await client.AcquireTokenByAuthorizationCode(new string[0], request.Code)
    .WithPkceCodeVerifier(verifier).ExecuteAsync().ConfigureAwait(false);
// Return the protocol response to Katana's normal validation pipeline.
```

Reuse/adapt the strict validator; require a signed ID token, trusted signing key, exact issuer/audience, valid lifetime, expected `tid` and stable `oid`. Keep claim names consistent (`MapInboundClaims=false`, role claim `roles`). `SecurityTokenValidated` calls `RegistrationSignInPolicy.Validate` after token validation, before issuing ordinary or registration-only access. Do not replace validation with decoded token contents or bypass nonce checking through manual code handling.

The existing asynchronous login POST/button event validates its form and awaits the exact workforce UPN lookup before selecting the provider. Only confirmed absence selects External ID; directory errors stop the request. The entered UPN selects an authentication route, not authorization. Use a fixed/local allowlisted return path.

```csharp
// Partial MVC login example; preserve HTTPS, input and anti-forgery guards.
var source = await RegistrationRuntime.RouteAsync(Startup.Config, email);
var properties = new AuthenticationProperties { RedirectUri = "/Benefits/Index" };
properties.Dictionary["login_hint"] = email.Trim();
HttpContext.GetOwinContext().Authentication.Challenge(properties,
    source == IdentitySource.Workforce ? "workforce" : "external");
return new HttpUnauthorizedResult();
```

For Web Forms, adapt the challenge/response to the page lifecycle rather than returning an MVC result. Keep the callback endpoints available to OWIN. Logout is a CSRF-protected POST that clears the application cookie; directory-wide logout is a separate behavior to define. Never render or log authentication codes, tokens or protocol exception details.

## 5. Map identities and guard business operations

Map validated `(tenant ID, object ID)` to the existing internal employee/customer key. Preserve employee numbers, bookings and existing business records. Do not match or merge privileged users automatically by email, display name or `DOMAIN\\username`. Include application ID in approval keys; tenant/object IDs identify the subject across email changes.

The approval model needs: application ID, tenant/object ID, source, persona, approved/disabled status, expiry and accountable sponsor. A dependent additionally needs verified relationship, benefit eligibility and linked workforce employee tenant/object IDs. Enforce a unique same-app approval and a unique current, benefit-eligible employee parent.

Put a common policy check at every protected action, page, business endpoint and application API. MVC can use a shared filter/service; Web Forms can use a shared base page. Guard state-changing business operations server-side as well as page rendering. Use the authenticated principal, not claims submitted by the browser.

```csharp
// Partial guard: stop/deny the operation when Allowed is false.
var decision = RegistrationSignInPolicy.EvaluateApplicationAccess(
    Startup.Config, principal,
    RegistrationRuntime.ReadEntitlements(Startup.Config), DateTimeOffset.UtcNow);
```

`[Authorize]`, menu visibility or a signed role alone is insufficient. This guard checks the correct source/tenant/audience, signed persona role, current approval and dependent rules, and denies `registration_only` sessions. Production data must come from the customer's approved employee/relationship system; PoC attestation is not that system.

Define revocation behavior precisely. The sample reloads governance on protected requests, so disabled/expired app approvals and linked-employee approvals deny the next policy check. Ordinary directory roles/account state are a signed cookie snapshot until fresh authentication or cookie expiry; directory unassignment alone does not guarantee immediate session termination. Implement the customer's required directory freshness/offboarding/session-revocation strategy and test it. Sponsor operations already refresh enabled workforce membership and app roles; the reference adapter assumes direct role assignments. If the customer uses group assignment, implement and test that resolution explicitly.

## 6. Implement dependent invitation and account setup

Port the policy and workflow from `Registration.cs`, `RegistrationControllers.cs`, `RegistrationServices.cs`, `PasswordSetupController.cs` and `PasswordSetup.cs` into the customer application/service layout:

1. An enabled workforce member with signed `Employee`, current same-app approval and benefit eligibility opens the invitation form and attests the dependent relationship. Recheck current sponsor directory roles/approval on the server; never permit an external customer to sponsor.
2. Provision or locate the External ID **customer identity**, verify the email identity/enabled state, assign this application's `Dependent` role, and bind the invitation to its exact tenant/object ID. Do not use an external-tenant administrative guest invitation as customer onboarding.
3. Create a cryptographically random, app-scoped invitation. Store its hash, recipient binding, sponsor, persona, creation/expiry, delivery audit and one-use status. Expiry is at most 24 hours and bounded by the approval deadline. Email the HTTPS link through the configured sender; a send does not create an approval.
4. Present **Verify email and create password**. The reference pre-provisions an account with a transient unknown random password and uses Microsoft's native SSPR protocol to let the recipient choose their password. This is an initial account-setup extension, not a public signup flow or a request to click **Forgot password**. Existing accounts may select existing-account sign-in.
5. Keep the separate native setup client and normal confidential MSAL web clients distinct. Native API stages are `start`, `challenge`, `continue`, `submit`, `poll_completion`; continuation tokens stay in a short-lived server session. Verify the email before accepting the password, require CSRF on mutations, and never persist/log passwords or codes. Do not redeem native continuation state for app authentication tokens. The sample session is ten minutes with a persistent five-minute verification-email cooldown.
6. After ordinary signed-token authentication, issue a **registration-only** session for the valid bound invitation. A CSRF-protected confirmation refreshes identity/sponsor checks, consumes the invitation and creates the approval in one transaction. Then clear the restricted cookie and require fresh ordinary sign-in for business access.
7. Support Home-login resumption: only one current, bound, `ready`, **sent** invitation for the exact signed `tid`, `oid`, source, issuer, audience and target-app role may resume `/Registration/Complete`. Hold its ID in protected ticket properties; deny benefits before confirmation. An invalid explicitly supplied invitation token must fail, not fall back to lookup. Reject missing, duplicate, canceled, expired and unsent invitations.

The reference native password-setup adapter requires **SSPR enabled for EmailPassword customers** and the correctly associated native client/user flow. It calls the raw native API; Microsoft prefers its native SDK where one supports the chosen client. Review this server-side PoC extension's support, policy and production suitability before adopting it. This does not change the normal confidential MSAL web-login flow.

Use transactional production storage with uniqueness and one-use redemption under concurrent requests. The reference JSON store demonstrates atomic commit/locking, not a production database design. Prevent concurrent duplicates and replay. Keep invitation URLs out of access logs/tracing/referrers; use no-store responses and masked sponsor-only inventory. Record uncertain email operations and do not automatically resend or treat a missing delivery record as proof that nothing was sent.

Retiree and other personal-customer approvals require their own approved business workflow. Do not grant those personas through the dependent invitation form.

## 7. Adapt provisioning/email to the actual host

**Host dependency:** the server's exact-UPN routing lookup and registration services obtain workforce Graph tokens through Azure App Service managed-identity endpoints. Routing requires the managed identity's `User.Read.All` Graph application permission; registration additionally needs its listed Graph permissions and ACS sender role. The external directory uses a separate provisioner. The interactive login registrations must not gain directory-write permissions.

If the customer hosts ordinary IIS on a VM or on-premises, replace the App Service token-acquisition adapter with a host-supported workload identity, certificate-backed service identity or separately secured directory/registration service. An Azure VM's managed-identity interface is not the App Service interface. Make the workforce lookup available before enabling the Home login flow; retain the same sponsor, recipient, role and approval checks. OIDC/MSAL performs authentication after this server-side route selection.

Inspect `scripts/poc/Configure-PocRegistration.ps1` and `Configure-PocPasswordSetup.ps1` for the reference service setup. Adapt resource ownership, permissions, credential lifecycle, private configuration and email sender to customer infrastructure; these PoC scripts are not customer production deployment scripts.

## 8. Update IIS and assess Kerberos dependencies

Use a separate test IIS application/pool first. Configure integrated CLR v4, Framework 4.8, trusted HTTPS, OWIN startup detection, secure cookies and required assembly redirects. The OIDC entry point requires IIS Anonymous authentication; disable Windows authentication for this test application and use ASP.NET `<authentication mode="None" />`. Remove FormsAuthentication interception if present.

Review inherited IIS/ASP.NET URL authorization so login, callbacks and recipient setup routes reach their handlers. Protected business access remains enforced by the application guard. Keep configuration inaccessible through HTTP (`App_Data` hidden or outside the web root), and keep durable governance/invitation state separate from deployments.

An OIDC claims principal does not create a Windows access token, Kerberos ticket or delegation chain. Identify downstream SQL integrated security, file shares, impersonation and AD group dependencies; implement and test the agreed service identity/API or other supported access design. Preserve the production Kerberos route until this is resolved and acceptance passes. Rollback restores the original binaries, IIS authentication settings and configuration together, while preserving durable invitation/approval audit data.

## 9. Acceptance checks and required output

| Check | Required evidence |
|---|---|
| Existing workforce login | Correct workforce client/tenant; employee business screens still work |
| Workforce account lookup | Existing exact UPN across any tenant suffix selects the same workforce tenant/client/callback; only confirmed absence selects External ID; permission/service failures stop with HTTP 503 |
| Employee UPN change / replacement account | Same-account `tid`/`oid` keeps its current mapping/approval without a domain-list update; a new object ID cannot inherit approval by email |
| External login | Exact CIAM issuer/client and signed assigned persona; same application screens use the mapped internal key |
| Invalid token/source | Wrong tenant, issuer, audience, unsigned/expired token or missing required role cannot establish permitted access |
| Workforce failure | No External ID fallback |
| App authorization | Anonymous and authenticated-unapproved direct requests to protected pages/endpoints fail |
| Dependent invitation | Authorized employee can invite; external/unapproved/ineligible sponsor cannot |
| Recipient setup | Real test inbox receives link; email verification and password creation succeed without an emailed password or Forgot password instructions |
| Pending registration | Home login resumes exact sent/bound invitation; restricted session cannot access business endpoints |
| Confirmation | CSRF-protected confirmation refreshes sponsor and writes one approval; fresh sign-in admits the approved dependent |
| Replay/concurrency | Second/concurrent redemption cannot create another approval; invalid explicit token never falls back |
| Negative invitation cases | Wrong identity/app, ambiguous/expired/canceled/unsent invitation and absent/forged CSRF fail |
| Governance isolation | App01 approval cannot authorize another app; email-only identity substitution fails |
| Revocation | Disabled/expired dependent or parent approval denies the next protected policy check; directory/session behavior matches the documented freshness strategy |
| Deployment | Private state survives deploy/restart as designed; transient setup sessions expire safely; secrets and bearer links stay out of source/logs |
| Downstream access | Required SQL/file/service paths work under the agreed identity design |

The current reference source passed 232 automated checks, including workforce lookup across 100 synthetic UPN domains. Live first-stage routing confirmed workforce and personal-dependent redirects to their respective authorities. The earlier live app01 dependent resumption/confirmation/fresh-login admission check remains separate evidence; it was not repeated for this routing change. Exercise a new recipient's complete password-creation path and the customer deployment's acceptance tests separately.

Return:

1. The actual customer file/location map and implemented patch.
2. Dependency/configuration changes and private administrator inputs still needed.
3. Tenant role, callback, flow and provisioning requirements.
4. Test commands/results, live sign-in/account-setup evidence and every `NOT RUN` check.
5. Known limitations, offboarding/downstream identity decisions and rollout/rollback instructions.

Reference build commands (these apply to the supplied sample, not automatically to the customer's solution):

```powershell
dotnet build samples/net48/MultiIdp.Net48.sln -c Release
& .\tests\Net48\bin\Release\net48\Net48.Tests.exe
```

For the customer solution, use its actual MSBuild/NuGet/build and test workflow. Do not mark implementation complete merely because the reference sample builds.

## Microsoft references

- [MSAL.NET source and platform support](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet)
- [ASP.NET Framework OWIN integration](https://learn.microsoft.com/en-us/entra/msidweb/frameworks/owin)
- [MSAL authorization-code redemption](https://learn.microsoft.com/en-us/entra/msal/dotnet/acquiring-tokens/web-apps-apis/authorization-codes)
- [External ID application registration](https://learn.microsoft.com/en-us/entra/external-id/customers/how-to-register-ciam-app)
- [External ID application roles](https://learn.microsoft.com/en-us/entra/external-id/customers/how-to-use-app-roles-customers)
- [Native authentication API](https://learn.microsoft.com/en-us/entra/identity-platform/reference-native-authentication-api)
- [OWIN hosting in an existing Web Forms application](https://learn.microsoft.com/en-us/aspnet/identity/overview/getting-started/adding-aspnet-identity-to-an-empty-or-existing-web-forms-project)

These references support the platform/protocol choices. The customer's dual-provider implementation, governance model and pre-provisioned password-setup extension must be validated against the adapted code and actual tenant configuration.
