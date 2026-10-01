# Caldova .NET Framework 4.8 PoC handoff

Status on 1 October 2026: the two IIS/System.Web applications and onsite driver are running in the isolated PoC resource group. The driver now requires the approved Caldova admin operator's sign-in on every URL. Sponsored registration is implemented and server/email setup is configured; one authorized personal-email invitation reached ACS `Succeeded` and the live app confirmed sent status. Inbox receipt, SSPR account setup and invitation redemption remain pending owner verification. Completed earlier sign-in checks are listed below. Synthetic employee MFA enrollment remains pending. The approved partner completed organizational sign-in, consent and workforce B2B redemption; a user-authorized exception now excludes only this guest from the security-information registration restriction. Other policy fields were verified preserved and MFA remains required. Enrollment and protected app02 admission are still PENDING. The earlier candidate's PoC access was removed.

## Start here

| Site | Link |
|---|---|
| Onsite driver | [Open driver](https://caldova-pocdriver-07279263.azurewebsites.net) |
| Sampleapp01 | [Employees and approved external users](https://caldova-sampleapp01-07279263.azurewebsites.net) |
| Sampleapp02 | [Supports approved organizational partners](https://caldova-sampleapp02-07279263.azurewebsites.net) |
| Downloadable source | [Source ZIP](https://caldova-pocdriver-07279263.azurewebsites.net/source/net48-source.zip) |

The driver opens with synthetic defaults. Expand **Application values → Load hosted lab setup**, then open the selected demo. Values/checkpoints stay in that browser's localStorage. The driver runs no tenant or IIS operations. Print includes all 12 steps for the selected application. An offline copy is in `driver/`; follow [its README](../../driver/README.md).

The hosted driver uses a separate workforce registration and App Service EasyAuth with an admin-only object-ID allowlist. Every page, asset, `code-samples.js`, `lab-settings.json` and source ZIP requires that operator authentication. Demo application roles do not grant driver access. Anonymous gate checks and real operator sign-in passed; an offline copy needs no authentication or network. The earlier HTTP/source privacy audit preceded this gate and the new registration source; it is historical evidence, not anonymous access to the current driver.

The lab manifest contains non-secret per-app values and correct demo origins; the configured partner domain `diax16026166.onmicrosoft.com` belongs only in app02, with app01 partner routing empty. No individual partner identity is exposed. IIS JSON/ZIP MIME settings are in `driver/web.config`. The driver starts with Architecture, preserves progress when opening Runbook, and reads actual application/shared source from the offline catalog.

## Resources and non-secret identity configuration

| Item | Value |
|---|---|
| Subscription | Oguzhan — `25947d5c-0462-4b16-a85e-b29ff6b0dd19` |
| Resource group | `rg-caldova-multiidp-poc` — resource-group location West Europe |
| Hosting plan | `asp-caldova-multiidp-poc` — Windows **B1**, Sweden Central |
| Web apps | `caldova-sampleapp01-07279263`, `caldova-sampleapp02-07279263`, `caldova-pocdriver-07279263` |
| Workforce tenant | Caldova — `8a97b0ce-7bdf-4928-bff5-41b8697d81b7` |
| New External ID tenant | `516de683-24d0-4674-bb56-3fe3ed4e935e` |
| External directory resource | `caldovapoc100107279263` in the same resource group; tenant location Europe, country AE |
| External login hostname | `caldovapoc100107279263.ciamlogin.com` |
| External discovery issuer | `https://516de683-24d0-4674-bb56-3fe3ed4e935e.ciamlogin.com/516de683-24d0-4674-bb56-3fe3ed4e935e/v2.0` |
| External user flow | `MultiIdpNet48ControlledSignIn` — `fbe78404-2468-4e28-8c1f-77878ff8c461` |

All three web apps were verified **Running** with HTTPS-only enabled. The **B1 plan remains running and billable** until the owner scales down or removes the PoC resources. Stopping a web app alone does not remove the plan.

| Registration | Client ID | Callback |
|---|---|---|
| sampleapp01-net48-workforce | `3e9dec76-0967-4769-b73d-592cfa8e51c6` | App01 origin + `/signin-workforce` |
| sampleapp01-net48-external | `17a183c7-925e-4d16-be3c-6b422025b0aa` | App01 origin + `/signin-external` |
| sampleapp02-net48-workforce | `dbc73d8b-8871-4aa9-8743-7b04724d054f` | App02 origin + `/signin-workforce` |
| sampleapp02-net48-external | `64320be4-c3ad-4704-947f-5ae606195c38` | App02 origin + `/signin-external` |

The four demo registrations are tenant-specific Web clients with assignment required, code/PKCE authentication and separate credentials. The controlled external email/password flow serves both external clients with `isSignUpAllowed=false`. The separately registered driver uses EasyAuth; its configuration does not change the four demo clients.

| Directory application | Exact role values |
|---|---|
| App01 workforce | `Employee` |
| App02 workforce | `Employee`, `Partner`, `admin`, `dependentRegistrant` |
| App01 and app02 external | `Retiree`, `Dependent`, `External` |

**All four application secrets expire on 7 October 2026**, between 12:17:07 and 12:18:36 UTC. The current approved test entitlements also expire that day; consult the private governance file for each exact timestamp. Arrange rotation or teardown before expiry; rerun scripts do not silently rotate missing or expired credentials.

## Verified and pending results

| Check | Result |
|---|---|
| Net48 build and policy/MSAL/token-validation/registration tests | Latest build reports zero warnings/errors and 165/165 tests passed. These are synthetic implementation checks, not new invitation delivery or admission. |
| Both Azure application HTTPS home pages | HTTP 200; configured sign-in forms present. |
| Real retiree sign-in | Passed in both apps. |
| Real dependent sign-in | Passed in app01, with a current same-app employee link. |
| Same dependent in app02 | Denied by Entra with `AADSTS50105` because the user is unassigned. This is the intended app-specific denial. |
| Workforce operator/admin, approved as Employee | Cached interactive sign-in passed in both apps. An administrator is unsuitable for a directory-assignment denial test. |
| Synthetic non-admin employee | MFA/security-information enrollment pending. Do not record this identity's login as passed yet. |
| Approved organizational partner, app02 | Home-organization SSO, organizational consent and B2B invitation redemption completed; Graph confirms the guest is Accepted and its app02 Partner assignment exists. A current sponsored entitlement is configured. Resource-tenant MFA registration previously returned `AADSTS53003`. On 1 October, the user-authorized exception excluded only this guest from that registration restriction, preserving all other policy fields and the MFA requirement. Enrollment and actual protected admission remain PENDING, without a PASS claim. Its username, object ID and governance record stay private. The approved routing domain is `diax16026166.onmicrosoft.com` for app02 only. The withdrawn candidate must not be reused. |
| Real retiree app01 logout | Authenticated CSRF-protected logout passed; the next protected request returned the home page. |
| Fresh Graph state | Four single-tenant clients, exact callbacks, implicit issuance disabled and assignment required. Controlled flow has public sign-up disabled. The approved partner's guest is Accepted and its app02 Partner assignment is confirmed. |
| Withdrawn partner cleanup | Its PoC role assignment, entitlement and routing were removed; only its newly created resource-tenant guest copy was soft-deleted. The home-organization account was unchanged and private candidate state was archived. |
| Driver authentication and UI | Anonymous gate checks and approved operator sign-in passed. Live Chrome confirms Architecture default, 12 Code selections per app, actual MSAL source and no menu/tracker overlap. Content-hash asset queries and no-store headers resolve stale post-deployment CSS/JS. Offline/mobile/large-font/print checks also pass. |
| Source privacy audits | The 30 September baseline excluded private configuration, credentials and recipient inventory. Root confirmed the initial 1 October 57-file package privacy audit passed after the three-site deployment. Hosted source downloads require authentication; later packaging must retain the same exclusions. |
| New sponsored registration | Implemented; infrastructure/configuration complete. One authorized personal-email send has ACS `Succeeded` and live sent-status confirmation. Inbox receipt, customer SSPR setup, invitation confirmation and protected admission remain PENDING owner verification. |
| Employee/admin registration forms | Live approved Employee pages passed in both apps; app02 admin Employee sees both dependent and business forms. The prepared customer is enabled and provisioner role-assignment diagnostics pass. A later ZIP deployment erased the old App_Data unsent pending record, with zero registration approvals and no email sent. Runtime state now has a separate data path and survived several later ZIP deployments in the live UI; complete recipient registration remains pending. |
| MFA/recovery/mail delivery | One personal-email send reached ACS `Succeeded`; inbox receipt and account setup are not yet verified. Earlier synthetic identities have no working mailboxes. |

The synthetic employee still needs approved enrollment and confirmed protected application admission. The approved partner still needs resource-tenant MFA registration and protected app02 admission; do not reuse the withdrawn candidate. Preflight security-information enrollment against existing policies and use an approved organizational network where required. Do not mark uncompleted sign-ins as passed.

## Private operator state and test credentials

Private state is `%LOCALAPPDATA%\MultiIdpPoC`, outside the repository. Manifests, `test-users.json`, `partner.json`, governance, registration configuration/state and DPAPI credential files are operator-only. They are excluded from downloadable source. DPAPI CurrentUser files can be imported only by the same Windows user on the original workstation.

Retrieve a synthetic test credential in a private PowerShell session without printing its password:

```powershell
$privateRoot = Join-Path $env:LOCALAPPDATA 'MultiIdpPoC'
$testUsers = Get-Content -LiteralPath (Join-Path $privateRoot 'test-users.json') -Raw |
    ConvertFrom-Json
$testUser = @($testUsers | Where-Object { $_.persona -eq 'Retiree' })
if ($testUser.Count -ne 1) { throw 'Select exactly one test identity.' }
$testCredential = Import-Clixml -LiteralPath $testUser[0].credentialFile
if ($testCredential -isnot [Management.Automation.PSCredential]) {
    throw 'Unexpected protected credential type.'
}
# Use $testCredential only in approved local sign-in automation or a private UI.
# For manual entry on the private workstation, copy without console output:
Set-Clipboard -Value ($testCredential.GetNetworkCredential().Password)
# Paste into the intended HTTPS sign-in page, then clear the clipboard:
# Set-Clipboard -Value ''
```

Use persona `Employee` or `Dependent` to select another synthetic account. Keep recovered passwords out of logs, command arguments, source, recordings and this handoff. The user-approved partner uses its home-organization credentials; do not create or reset a partner password or reuse the withdrawn candidate's private invitation record.

## Repeatable operation

See [script usage and contracts](../../scripts/poc/README.md) and [net48 source/deployment notes](../../samples/net48/README.md). Directory operations require the correct delegated administrator context; hosting operations explicitly select the Oguzhan subscription.

```powershell
$env:AZURE_CONFIG_DIR = Join-Path $env:LOCALAPPDATA 'MultiIdpPoC\AzureCli'
$workforceTenantId = '8a97b0ce-7bdf-4928-bff5-41b8697d81b7'
$externalTenantId = '516de683-24d0-4674-bb56-3fe3ed4e935e'
$subscriptionId = '25947d5c-0462-4b16-a85e-b29ff6b0dd19'

# Re-export verified, non-secret settings from the saved manifests.
.\scripts\poc\Export-PocConfiguration.ps1 `
    -WorkforceTenantId $workforceTenantId -ExternalTenantId $externalTenantId `
    -EmployeeDomains @('caldova07279263.onmicrosoft.com') `
    -ApprovedPartnerDomains @('diax16026166.onmicrosoft.com')

# Repeat with -Local for the separate https://localhost:44371 / :44372 sites.
# After reviewed source/configuration changes, deploy all three sites:
.\scripts\poc\Deploy-PocSites.ps1 -SubscriptionId $subscriptionId `
    -WorkforceTenantId $workforceTenantId -ExternalTenantId $externalTenantId
# Add -DriverOnly for just the driver/manifest/source package.
# Or add -ApplicationIds sampleapp02 for app02 plus the driver.
```

`Configure-PocApplications.ps1` reconciles the tagged registrations, roles, consent and saved credentials. `Configure-PocExternalFlow.ps1` uses Graph v1.0 and verifies flow association and disabled sign-up. `Add-PocAssignment.ps1` assigns an explicit object ID and writes its approved, expiring entitlement. Dependent assignment requires the stable linked employee IDs; partner assignment requires verified home-organization evidence and app02. `New-PocPartner.ps1` creates/reuses the organizational B2B invitation without sending email.

The applications load server configuration and the governance file from IIS-protected `App_Data`; four secret environment variables are separate App Service settings. Updating only a local governance file does not change cloud behavior: update the deployed protected file or redeploy. On every protected request the app rechecks entitlement, expiry and the dependent's linked employee; directory unassignment alone does not invalidate an existing application cookie.

## Sponsored registration

Only enabled Caldova members with the signed Employee role and current same-app approval can act. App01 Employee can invite a dependent. App02 additionally requires `admin` or `dependentRegistrant` for dependents; its vendor/partner section requires Employee plus `admin` only. Dependents require current employee benefit eligibility and relationship confirmation. Partner/external identities never receive these capabilities.

`Configure-PocRegistration.ps1` provisions owned managed-email resources and selected employee capabilities. Site managed identities perform workforce Graph and ACS operations; a separate external-directory provisioner manages customer identities/roles. Private absolute configuration paths are supplied through `MULTIIDP_SAMPLEAPP01_REGISTRATION_CONFIG` and `MULTIIDP_SAMPLEAPP02_REGISTRATION_CONFIG`; the provisioner credential is the server-only `MULTIIDP_REGISTRATION_EXTERNAL_SECRET`. Configuration remains replaceable in App_Data, while invitation/approval state is `D:\home\data\multiidp\<appId>\registration-state.json` outside `wwwroot`. Configure/deploy scripts use that path and never package runtime state or its lock file. Windows/IIS commits use same-directory `MoveFileExW` replacement/write-through, retaining a private recovery temp on commit failure without copy-overwrite or delete-then-move fallback.

The previous App_Data runtime file was lost during ZIP deployment: one `pending_identity` / `not_sent` row, no registration approval, and no email sent. It is not evidence of successful cancellation, delivery or redemption. The corrected runtime record survived several later ZIP deployments, confirmed in the live UI. Review existing directory objects/roles separately; never infer safe resend from missing state when delivery is uncertain.

Personal recipients receive an ACS link bound to their External ID tenant/object ID, expiring within 24 hours or earlier at the approval deadline. The invitation now opens email verification and password creation directly through the native setup client; the recipient is not directed to Forgot password. Existing accounts may use existing-account sign-in. No password is emailed. Organizational partners use one Graph B2B invitation with `sendInvitationMessage=false`; ACS delivers its native `inviteRedeemUrl` after the returned guest is bound and assigned Partner. Signed home-issuer evidence remains mandatory. A CSRF-protected confirmation refreshes sponsor roles/approval, consumes the link once and writes the app approval. Until then, the invitation cookie permits completion only. See [REGISTRATION.md](REGISTRATION.md) for setup and negative checks.

These capabilities and server integration are implemented and configured; one authorized personal-email send reached ACS `Succeeded`; inbox receipt, SSPR account setup and live one-use confirmation remain unverified. Existing manual partner onboarding evidence does not prove this new workflow.

The employee sees only their own masked invitation inventory. Cancel unsent is restricted to `pending_identity` or bound `ready`, `not_sent` and no operation ID, with CSRF, fresh sponsor checks and an atomic recheck. Live cancellation passed for both the pending and bound unsent rows and persisted. It preserves audit records and does not delete identities or grant approval. ACS queued status/operation ID are recorded before submission; uncertain operations must not be canceled or automatically resent.

Known consumer providers such as exact `gmail.com` use the personal External ID registration path without organizational discovery. Other-domain discovery supplies a candidate home tenant only; internal directories are excluded as partner homes. Signed home-issuer proof and current app02 governance remain required. This verifies an approved organizational identity, not a Microsoft 365 product license. The first personal-dependent attempt stopped before creation/email; the consumer-domain correction is covered by the current tests, with one subsequent ACS send confirmed successful and recipient completion still pending.

## Remaining acceptance and rollback

Complete synthetic employee MFA enrollment and the approved partner's resource-tenant MFA enrollment, then confirm protected app02 access. MFA remains required. Keep app01 partner routing empty. Verify receipt of the sent invitation, email-verified customer setup, one-use confirmation and expired/replayed/wrong-identity/revoked-sponsor denial cases. Record remaining checks as NOT RUN rather than inferring them from tests, role assignment or a queued email. Packaging verification should compare downloaded source with the recorded local source hashes through the authenticated driver.

For rollback, restore the customer's agreed Kerberos route and stop the PoC sites. Revoke the PoC-specific assignments and credentials through reviewed cleanup, then remove owned test resources when approved. Do not delete the workforce directory or unrelated identities/policies. Confirm teardown of the B1 plan and the new external-directory resource to end the PoC footprint. OIDC login establishes a claims identity; Windows impersonation/downstream Kerberos delegation requires a separate migration decision.


## Invitation password setup correction ? 1 October 2026

Both apps deployed from `artifacts/deploy-20261001-045411`. Build: zero warnings/errors; 176/176 checks passed. Microsoft native setup start succeeded against the separate setup client. Existing Sampleapp02 invitation in the owner Chrome profile showed **Verify email and create password**; clicking it reached **Verify your email** after Microsoft issued an email challenge. No replacement invitation was sent. Recipient code/password entry and final protected admission remain owner-pending. The driver now has six source-linked interaction walkthroughs, including personal registration, workforce login, organizational B2B, External ID and password setup. Both app code catalogs include `PasswordSetup.cs` and `PasswordSetupController.cs`; the source ZIP includes the new setup script and tests. Driver anonymous gate checks: 10/10 passed after deployment.

## Pending registration login correction — 1 October 2026

External ID sign-in logs confirmed successful authentication for the app01 dependent; the application then rejected ordinary Home login because its sent invitation was still unredeemed and no application approval existed. Ordinary login now resumes a unique sent, current invitation bound to the exact signed tenant/object, source, issuer, audience and app persona role. A short registration-only cookie opens **Confirm registration**. Confirmation still requires CSRF and current sponsor checks, consumes the invitation once and creates app-specific approval; fresh ordinary sign-in is required for benefits. Invalid explicit invitation links do not fall back to lookup. No runtime approvals were manually edited or replacement emails sent. Build: zero warnings/errors; 216/216 checks passed.

Live app01 validation passed in the owner's Chrome profile after deployment: ordinary dependent sign-in opened **Complete registration**, confirmation succeeded, and fresh sign-in opened **Application access approved** with persona `dependent`, source `external` and the existing bounded approval deadline. Proof: private artifact `artifacts/app01-dependent-access-approved.png`. This proves invitation resumption, confirmation and app01 admission for that account; it does not claim a fresh account's password setup or app02 admission was exercised.

## External-first Entra configuration guide

The protected driver now includes `entra-setup.html`, linked from its main navigation, view actions and Sampleapp01 migration guide. Its 15 numbered steps cover tenant creation/verification, identifier inventory, four web registrations, app roles and assignments, invitation-only EmailPassword flow, workforce optional `idp` claim, employee approval/capabilities, organizational B2B, service identities and Graph grants, ACS email, native password setup, sign-in policies, private application configuration, driver EasyAuth and acceptance tests. Portal steps, Graph-only settings, manual employee seed governance and repository-script dependencies are distinguished. Customer automation uses an isolated state folder; the existing-tenant path skips the directory-creating initializer. Credentials require explicit rotation rather than an automatic script rerun.

Driver-only deployment: `artifacts/deploy-20261001-111111`. Live owner Chrome verified navigation and the guide; screenshot: `artifacts/entra-setup-guide-live.png`. Guide anchors, PowerShell parsing and packaging checks passed. Anonymous driver/asset/download and spoofed-header checks passed, including the new page (14 checks). No application binaries, tenant policy or account assignments changed for this guide addition.

## Existing application change guide

The authenticated driver page `/migration-sampleapp01.html` explains how to extend an existing ASP.NET Framework 4.8 application using Sampleapp01. It maps customer project locations to tested source, covers both providers, login, stable user mapping, per-request authorization, dependent registration, IIS and rollback, and links directly to individual source files. It also identifies the App Service managed-identity dependency in the registration adapter and the adaptation required for other IIS hosts. The page and stylesheet are included in the driver deployment and source ZIP.

## Login routing source walkthrough

The protected driver now includes `/login-routing.html`, linked from the main navigation and view actions, Entra setup and migration guide. Seven sections trace the login POST, exact domain routing, App02 current partner approval overlay, separate OWIN/MSAL authorities and callbacks, token validation and admission, invitation-time organization discovery and bound first sign-in, and failure handling. Thirteen excerpts are extracted from the deployed source catalog with actual file/line references and full-file links. Normal home login does not discover every Microsoft 365 organization; discovery happens during business invitation. An invitation can challenge its bound workforce source before the partner domain becomes eligible for ordinary login. Authentication failure never switches realms.

Driver-only deployment `artifacts/deploy-20261001-123636` passed live operator Chrome navigation, all 13 excerpt loads and the full Policy.cs source link. Screenshot: `artifacts/login-routing-live.png`. Excerpt/catalog consistency, missing-catalog fallback, anchors, JavaScript syntax, PowerShell parsing and ZIP inclusion checks passed; all 16 anonymous-content/spoofed-header/identity-endpoint checks passed. The guide describes the existing application behavior; no application binary, tenant configuration or account assignment changed. The source ZIP includes the new page and loader. A final packaging refresh includes this handoff entry and clarified partial-excerpt wording.

## Automatic Sampleapp01 workforce lookup

Sampleapp01's async login now calls `RegistrationRuntime.RouteAsync` and `WorkforceAccountResolver.ResolveAsync` before the OWIN challenge. Its workforce managed identity queries Graph for the exact entered UPN with an escaped equality filter, selected stable identifiers and a two-row limit. Every workforce UPN suffix uses the same account lookup and authority; no employee-domain list is maintained. A matching account remains workforce, including disabled users or guests, and signed-role/current-approval admission still applies. Only HTTP 200 with a validated empty result selects External ID. Permission/service/timeout errors, malformed responses, mismatched identities, duplicates and pagination stop routing with a scrubbed HTTP 503; authentication failure never changes realms. SMTP aliases are not resolved by this exact-UPN implementation.

The existing workforce managed identity and `User.Read.All` permission are reused. No new directory permissions, accounts or policies are required. `employeeDomains` may be empty for Sampleapp01; the shared legacy configuration and App02 route remain available for their existing uses. The source catalog now includes `WorkforceAccountResolver.cs` (17 public source files). Build: zero warnings/errors; 232/232 checks passed, including 100 synthetic UPN suffixes absent from the configuration, disabled/guest realm retention and lookup failure cases. Independent source review found no critical issues.

The login-routing page now targets Sampleapp01 only, with 11 current source excerpts and automatic lookup examples. Its migration guide and developer Markdown explain the same Graph dependency, async controller changes and stable account/dependent identifiers. Driver values and generated App01 configuration no longer require employee routing domains.

Application + driver deployment: `artifacts/deploy-20261001-125806`, with only Sampleapp01 selected. Live anonymous, CSRF-protected login POST checks confirmed the existing workforce UPN selects `login.microsoftonline.com` and the existing personal dependent selects the correct `ciamlogin.com` tenant. These checks validate the server-side routing and initial OIDC challenge, not completion of a fresh authentication or password setup. Operator Chrome verified all 11 excerpts, App01-only guide content, the new resolver in the code catalog, and hidden/non-required employee-domain fields for App01 while App02 retains its existing fields. Driver authentication checks passed 16/16. Screenshot: `artifacts/app01-automatic-routing-guide-live.png`. A final driver packaging refresh includes this evidence and the updated developer handoff results.
