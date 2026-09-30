# Architecture and code walkthrough

```text
Workforce account                    External ID customer
       |                                      |
Workforce tenant                     External ID external tenant
Web registration + enterprise app    Web registration + enterprise app + flow
       |                                      |
/signin-oidc                         /signin-external-oidc
       +-------------------+------------------+
                           |
                  One ASP.NET Core app
                Two OIDC handlers / cookies
                  Normalized claims policy
                           |
                    Protected /Profile
```

## 1. A single authentication pipeline

`Program.cs` sets `AppSession` as the authenticate scheme and `ChooserCookie` as the challenge scheme. The policy scheme reads which named session cookie is present and forwards authentication to the matching cookie handler. Anonymous protected-page requests go to `/SignIn`.

This cookie selector does not choose a token issuer and does not validate tokens itself. The named OIDC handlers do that work.

## 2. Two registrations

The adjacent `AddMicrosoftIdentityWebApp` calls in `Program.cs` bind:

| Section | OIDC scheme | Cookie scheme | Population |
|---|---|---|---|
| `AzureAd` | `WorkforceOidc` | `WorkforceCookie` | Workforce tenant |
| `ExternalId` | `ExternalOidc` | `ExternalCookie` | External tenant |

Each registration is local to its identity tenant. Each enterprise app can require assignment. Hosting in an Azure subscription attached to Workforce does not create External ID customer users in Workforce.

## 3. Email-based authority routing

`IdentityRouter.TryNormalize` rejects empty, overlength, malformed, and display-name-formatted input. It trims outer whitespace and normalizes the domain's case.

`SelectScheme` routes exact Workforce domains and their subdomains to `WorkforceOidc`. Everything else goes to `ExternalOidc`. The sign-in page passes the normalized address as `login_hint`, and the challenge's eventual return page is `/Profile`.

There is no directory search, account-existence probing, account migration, or automatic second-provider retry. If personas can share a listed domain, agree a different routing design rather than relying on this domain-only selector.

## 4. OIDC and token validation

`ConfigureOidc` explicitly sets `ResponseType=code`, `UsePkce=true`, and `MapInboundClaims=false`. Microsoft.Identity.Web and the OIDC handler retain the normal authority/discovery-based issuer, audience, signature, and lifetime checks.

The sample chains the existing Microsoft validation handler instead of replacing it. Only after that handler succeeds does `PrincipalNormalizer`:

1. Require an authenticated claims identity.
2. Match `tid` to the expected tenant for the selected OIDC scheme.
3. Require a stable `oid`, mapped object identifier, `sub`, or mapped name identifier.
4. Replace any token-supplied application-owned claims.
5. Add the scheme-controlled identity source, tenant, subject, and optional email.

Do not call the normalizer on an unvalidated JWT. Reading claims is not signature validation.

## 5. Application authorization

The default policy requires authentication and an `identity_source` of `Workforce` or `ExternalId`. `/Profile` uses `[Authorize]`.

This is intentionally only an admission demonstration. Mapping `RoleClaimType` to `roles` does not require a business role. Add explicit policy/role/entitlement checks for real protected resources and keep authoritative eligibility outside self-declared registration attributes.

Use a tenant/subject tuple for durable account linking; email can change and is not an authorization key.

## 6. Cookies and logout

The two cookies use distinct generic names, `HttpOnly`, `Secure=Always`, and `SameSite=Lax`. Signing in removes the opposite population's cookie. Sessions expire after one hour without sliding renewal.

The layout submits an antiforgery-protected POST to `/auth/signout`. The handler clears both local cookies and, when a session exists, logs out from the active provider with the saved ID-token hint. A GET only presents a confirmation form.

Directory disable/unassign affects new sign-in. It does not continuously revalidate the app's existing cookie. A production revocation requirement needs additional implementation.

## 7. Reverse proxy boundary

Forwarded-header processing is disabled by default. For TLS-terminating hosting, enable it only after providing approved IPs/CIDR ranges in `ReverseProxy`. Startup rejects an enabled but empty trust list and wildcard `/0` networks.

The application retains the framework's default loopback trust; it never clears the proxy lists to trust every source. Configure `AllowedHosts` to actual approved hostnames.

## Tests

`tests/MultiIdpApp.Tests` is an executable, dependency-light test harness. It tests routing edge cases, normalized claims, spoofed application claims, tenant/subject rejection, required configuration, and proxy boundaries. No real tenant or account is used.

CI restores the committed lock files from public NuGet, builds both projects, and runs that harness. Complete tenant-backed authentication, MFA, logout, and denial acceptance checks are separate deployment tests.
