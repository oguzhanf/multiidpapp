# Validation evidence

Status updated 1 October 2026: sponsored registration is implemented and server/email setup is configured. Current implementation tests report 165/165 passed; one authorized personal-email invitation reached ACS `Succeeded`, with the live app confirming sent status. Inbox receipt, SSPR account setup and invitation redemption remain PENDING owner verification. The hosted driver's admin-only authentication gate passed anonymous and approved-operator checks. The user-authorized registration-restriction exception covers only the approved partner guest; other policy fields were verified preserved and MFA remains required. Partner enrollment and protected app02 admission remain PENDING.

Historical checks on 30 September 2026: build at 12:49 UTC, source-package audit at 13:00 UTC, both-app HTTP checks at 13:15 UTC after partner cleanup, and app02 recheck at 13:36 UTC with the approved partner route. The newer registration tests and driver checks are recorded separately below. Results distinguish synthetic tests, HTTP challenges and completed interactive authentication. No credentials, codes, tokens, state values or cookies are included.

## Build and behavioral tests

```powershell
dotnet restore samples/net48/MultiIdp.Net48.sln --locked-mode -p:MSBuildEnableWorkloadResolver=false
dotnet build samples/net48/MultiIdp.Net48.sln --no-restore -v minimal -p:MSBuildEnableWorkloadResolver=false
& tests/Net48/bin/Debug/net48/Net48.Tests.exe
```

The latest 1 October build completed with **zero warnings/errors** and **165/165 tests passed**, root-confirmed. A test result does not prove managed-email delivery, Microsoft account setup or live invitation admission.

Tests exercise exact email-domain routing; application, tenant, object, issuer and audience boundaries; signed persona roles; duplicate claims/entitlements; expiry and next-request file revocation; sponsor, dependent relationship and benefit eligibility; current same-app employee linkage; and verified partner home-organization matching through signed `idp`. Governance identities and approvals in these tests are synthetic inputs.

Registration coverage exercises exact `admin` / `dependentRegistrant` capabilities for approved workforce Employees, personal/organizational source boundaries, bound recipient identity, expiry, one-use/concurrent redemption, repeated-send suppression, refreshed sponsor roles, same-app employee benefit linkage and restricted invitation-cookie admission. Code is implemented; real Graph/ACS/SSPR results still require their own live evidence.

The initial live personal-dependent form stopped before customer creation or email when Microsoft metadata returned an organizational tenant for Gmail. The corrected adapter bypasses discovery for 13 exact known consumer-provider domains, including `gmail.com`, and excludes internal directories as partner homes. Seven added tests cover no-HTTP consumer resolution, Gmail dependent external binding, exact suffix/subdomain boundaries and custom organization classification. Discovery remains a candidate hint; signed `idp` and approved governance remain required, without a Microsoft 365 licensing claim. A subsequent authorized personal-email invitation reached ACS `Succeeded`; inbox receipt remains unverified.

The final backend includes owner-only masked invitation inventory and CSRF-protected cancellation of a `pending_identity` or bound `ready` row with `not_sent` and no operation ID. Fresh sponsor role/approval checks and an atomic unsent-state restriction protect cancellation. Directory-only failure recovery retains hash/audit records; queued/submitted/uncertain email operations cannot be canceled or automatically resent. The ACS operation ID and queued audit are persisted before submission. Live cancellation passed and persisted for both pending and bound unsent rows, root-confirmed. One subsequent ACS send succeeded; recipient completion and admission remain separate live checks.

**Live persistence failure, root-confirmed:** ZIP deployment erased the former App_Data runtime file containing one `pending_identity` / `not_sent` row and zero registration approvals. No email had been sent. Configure/deploy scripts now set `stateFile` to `D:\home\data\multiidp\<appId>\registration-state.json` outside `wwwroot` for each app and exclude state/lock files from ZIPs. The corrected private runtime record survived several later ZIP deployments, confirmed in the live UI; the lost row is not a cancellation or registration PASS.

**Storage commit correction:** the IIS worker reported generic `0x80070000` during file replacement; this does not establish an ACL cause. The Windows/IIS adapter now uses same-directory `MoveFileExW` replacement/write-through with a flushed writer and sidecar lock. Commit failures retain a private recovery temp; there is no copy-overwrite or delete-then-move fallback. The latest 165 checks pass. Live cancellation passed and persisted for both pending and bound unsent rows. Exactly one subsequent authorized personal-email ACS operation reached `Succeeded`; the live app confirmed sent status, without an inbox-receipt claim. An earlier attempt stopped before ACS submission because the send URI was interpreted as a scheme; the adapter now constructs an absolute HTTP send URI, with a regression check. Its bound `ready` / `not_sent` row was safely canceled before the successful send. Final private state contains two canceled unsent rows, one `ready` / `sent` row with an operation ID, and zero registration approvals; recipient confirmation remains pending.

The transport test executes the production redemption override with the real MSAL.NET client and a synthetic HTTP identity service. It verifies the authorization-code request includes the recovered PKCE verifier, client credential and exact callback. A missing verifier fails before network access. This proves request construction, not a live provider sign-in.

`StrictJwtSecurityTokenHandler` is necessary because Katana 4.2.3 relaxes `RequireSignedTokens` in its authorization-code branch. The regression first reproduced acceptance of an unsigned `alg:none` ID token under those parameters. The configured handler now forces signed-token/signing-key checks and retains standard validation: unsigned tokens, a foreign signing key, wrong issuer/audience and expired signed tokens are rejected; a correctly signed RSA fixture succeeds. [Source](../../samples/net48/Shared/StrictJwtSecurityTokenHandler.cs).

The MSAL handler replaces only redemption transport and returns the token response to Katana. It preserves Katana's protected state/PKCE and normal token-response/nonce validation; it does not call `HandleCodeRedemption`. [Source](../../samples/net48/Shared/MsalOpenIdConnect.cs).

## Deployed IIS HTTPS checks

The historical 13:15 UTC smoke omitted `-PartnerEmail` after candidate withdrawal. App02's 13:36 UTC recheck included the approved organizational routing address. Commands below use synthetic placeholders; substitute privately approved test addresses matching deployed routes before rerunning.

```powershell
& tests/Net48/Smoke-Iis.ps1 -BaseUri https://caldova-sampleapp01-07279263.azurewebsites.net -EmployeeEmail 'employee@workforce.example' -ExternalEmail 'customer@personal.example'
& tests/Net48/Smoke-Iis.ps1 -BaseUri https://caldova-sampleapp02-07279263.azurewebsites.net -EmployeeEmail 'employee@workforce.example' -ExternalEmail 'customer@personal.example' -PartnerEmail 'partner@approved-organization.example' -App02
```

Both application smoke checks exited 0 at 13:15 UTC; app02's recheck with the newly approved partner address also exited 0 at 13:36 UTC. Each checked app served its configured Framework 4.8 public home, rendered an antiforgery form, rejected login/logout without a form token with HTTP 400, redirected unauthenticated protected-page requests, and returned 404 for both protected App_Data JSON paths. The 13:15 UTC hosted setup manifest had empty partner routes after cleanup; app02 was subsequently deployed with the newly approved organizational routing domain.

Employee addresses selected workforce and the external address selected CIAM. App02's newly approved partner address selected workforce in the 13:36 UTC check. Challenges used HTTPS, `response_type=code`, PKCE S256, protected state, nonce, distinct callbacks and the expected login hint. Nonce cookies were Secure and HttpOnly. These HTTP checks intentionally do not submit credentials or prove protected admission. Earlier checks involving the withdrawn candidate are excluded from final partner acceptance.

## Interactive outcomes

| Case | Outcome and evidence |
|---|---|
| External retiree, sampleapp01 | **PASS, root agent confirmed:** real CIAM password sign-in completed, MSAL redeemed the code, and `/Benefits/Index` displayed approved access. This is a seeded PoC identity/persona, not independent HR evidence. |
| External retiree, sampleapp02 | **PASS, root agent confirmed:** generated PoC account credential completed real CIAM sign-in and `/Benefits/Index` displayed approved access. |
| External dependent, sampleapp01 | **PASS, root agent confirmed:** real CIAM sign-in completed and `/Benefits/Index` displayed approved dependent access. The employee relationship and benefit data are seeded PoC governance inputs. |
| Unassigned External dependent, sampleapp02 | **PASS denial, root agent confirmed:** the actual signed-in PoC dependent was rejected by External ID with `AADSTS50105` (assignment required). No callback or application cookie was created. Together with dependent/app01 approval, this exercises the intended cross-app assignment boundary. Screenshot retained locally in `artifacts/live-sampleapp02-dependent.png`. |
| Workforce operator assigned Employee persona, both applications | **PASS, root agent confirmed:** the workforce administrator's existing browser sign-in completed and `/Benefits/Index` displayed approved Employee access in both apps. This administrator may bypass assignment restrictions; negative admission coverage comes from application-policy tests and non-administrator cases. |
| Synthetic workforce Employee | **MFA enrollment pending:** the real browser reached MFA enrollment; application admission was not completed. |
| Newly approved organizational B2B partner, sampleapp02 | **ONBOARDING PASS; ENROLLMENT AND PROTECTED ADMISSION PENDING, root confirmed.** Real cached home-organization SSO and organizational consent completed; Graph verified B2B acceptance and the app02 Partner assignment. Resource-tenant MFA registration previously returned `AADSTS53003` before the application callback. On 1 October, a user-authorized exception excluded only this approved guest from that registration restriction; all other policy fields were verified preserved and MFA remains required. Post-change enrollment, MSAL code redemption, the actual signed `idp` check and a protected benefit page remain unconfirmed. Synthetic signed-home-issuer/governance/transport tests pass. The earlier candidate's PoC access was removed. Public evidence excludes individual partner usernames/object IDs, exclusion IDs and private policy/network details. |
| Authenticated local logout, retiree/sampleapp01 | **PASS, root agent confirmed:** the authenticated CSRF-protected logout button returned to home; a fresh `/Benefits/Index` request also returned to home, confirming app-cookie access was removed. Provider SSO remains a separate session by design. |
| Live entitlement revocation/expiry | **NOT RUN.** Synthetic next-request revocation, expiry and linked-employee revocation tests pass. |

Directory assignments, real partner onboarding and real benefit eligibility require their own tenant/governance evidence. Update this table only after a completed live check; provider failures never trigger an automatic switch to External ID.

## Driver and source-package review

**Live browser PASS, root agent confirmed:** Architecture opens by default; Code samples shows 12 files per app, including actual MSAL source, and navigation works. The live menu bottom 678.48px remained above tracker top 691.27px; tracker bottom 827.33px stayed inside the 843px viewport. Load hosted lab setup and app switching previously verified the correct values/demo URL/domain; all 12 runbook steps are present.

The first post-deployment browser reused stale CSS/JS. Driver staging now adds content-hash query versions to CSS, script and catalog URLs, and IIS sends `Cache-Control: no-store`; the refreshed live Code view and layout passed. Reusable offline HTML keeps local unversioned asset references. This caching fix does not alter the all-URL authentication gate.

The 30 September MIME/source audit verified JSON parsing and selected source/document hashes. The then-current package excluded bin/obj, App_Data, DPAPI/private keys, real identity/entitlement configuration, credentials and private recipient inventory. This historical audit precedes the new registration source and authentication gate; it is not a claim that the current driver is anonymously downloadable.

**Hosted gate PASS, root confirmed on 1 October:** anonymous checks were rejected/challenged across the driver, assets, catalog, manifest and ZIP; the approved Caldova operator authenticated successfully. EasyAuth uses a separate registration and an admin object-ID allowlist. The four demo clients retain their own code/PKCE authentication. Demo source pages remain publicly readable source snapshots; all hosted driver URLs require operator sign-in.

**Initial 1 October deployment PASS, root confirmed:** all three sites deployed, Architecture opened by default, all ten anonymous driver gate checks passed, and the 57-file source package passed the privacy audit. This deployment evidence does not mark new email delivery or registration as complete.

**Offline UI PASS on 1 October:** Architecture opens first even with saved runbook progress; diagram nodes explain source/design choices; code deep links select the app; 12 runbook steps and printing remain intact. At 1440×900 with a 24px root font, menu bottom 560.8px remained above progress top 580px and tracker bottom 876px stayed within the viewport. The 390px mobile layout had no horizontal overflow. The isolated local-file run made zero remote requests and reported zero script errors. Screenshots: `artifacts/driver-architecture-local.png`, `driver-architecture-zoom.png`, `driver-architecture-mobile.png`.

The regenerated catalog contains 14 actual source files, with 12 selections per application including all three registration files. All catalog files match local source after BOM/newline normalization. The browser verified each app02 selection's exact text, escaped rendering and purpose, app01 mapping, copy, hash/app switching, saved checkpoints, updated steps 6–8, 12-step print output and the diagram-to-registration-source link. Screenshots also include `artifacts/driver-registration-local.png` and `driver-code-local.png`.

## New registration acceptance

| Check | Status |
|---|---|
| Employee/capability policy and server invitation integration | Implemented; current synthetic test suite passes. |
| Live workforce Employee pages and app02 admin forms | PASS, root-confirmed in both apps; app02 renders dependent and business forms for the approved admin Employee. This does not prove recipient completion. |
| Managed identity / separate external provisioner / ACS setup | Configured; live service behavior is not inferred from setup. |
| Personal-email invitation send and customer SSPR account setup | ACS `Succeeded` and live app sent status PASS for exactly one authorized invitation. Inbox receipt, owner password setup/email verification and registration remain PENDING. No password-email workflow. |
| Recipient customer preparation | Customer creation/enabled state and provisioner role-assignment diagnostics passed. The old unsent runtime row was lost during ZIP deployment; no email or registration approval existed. Complete recipient registration remains pending. |
| Runtime invitation/approval persistence | PASS: private state outside wwwroot survived several ZIP deployments. Both guarded unsent cancellations persisted; final state has one sent invitation and zero registration approvals. |
| Native Graph B2B URL sent through ACS | Implemented as one invitation with `sendInvitationMessage=false`; delivery/redemption PENDING. |
| Matching recipient confirmation and protected app admission | PENDING live validation; invitation session grants no benefit-page access. |
| Expired/replayed/wrong-app/wrong-identity link and revoked sponsor/capability | Synthetic coverage passes; live denial checks NOT RUN. |

Current packaging verification must compare the authenticated source download to the exported local files and retain the privacy exclusions above. Never record an email-provider acceptance, link preview or directory role assignment as a completed registration.


## Invitation password setup correction ? 1 October 2026

Both apps deployed from `artifacts/deploy-20261001-045411`. Build: zero warnings/errors; 176/176 checks passed. Microsoft native setup start succeeded against the separate setup client. Existing Sampleapp02 invitation in the owner Chrome profile showed **Verify email and create password**; clicking it reached **Verify your email** after Microsoft issued an email challenge. No replacement invitation was sent. Recipient code/password entry and final protected admission remain owner-pending. The driver now has six source-linked interaction walkthroughs, including personal registration, workforce login, organizational B2B, External ID and password setup. Both app code catalogs include `PasswordSetup.cs` and `PasswordSetupController.cs`; the source ZIP includes the new setup script and tests. Driver anonymous gate checks: 10/10 passed after deployment.
