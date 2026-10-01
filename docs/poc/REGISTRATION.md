# Sponsored registration and account setup

Status on 1 October 2026: registration is implemented; Azure-managed sender and server setup are configured. One authorized personal-email invitation reached ACS operation `Succeeded`, with the live app confirming sent status; inbox receipt is not yet verified. The permission model and invitation lifecycle below describe the source contract. Live delivery, first-time account setup, one-use redemption and protected application admission must be recorded separately in [VALIDATION.md](VALIDATION.md); they are not yet confirmed for this new workflow.

## Who may send an invitation

The actor must be an enabled Caldova workforce member with the signed `Employee` application role and a current, approved employee entitlement for the selected application. A directory administrator title alone is insufficient. These capability values are application roles, not Microsoft Entra administrator roles.

| Selected application and action | Required application roles | Additional requirement |
| --- | --- | --- |
| App01: register a dependent | `Employee` | Current employee benefit eligibility and relationship confirmation |
| App02: register a dependent | `Employee` plus `admin` **or** `dependentRegistrant` | Current employee benefit eligibility and relationship confirmation |
| App02: register a vendor / business partner | `Employee` plus `admin` | Accountable sponsor and approved business purpose |
| Partner, retiree, dependent or other external identity | None permit registration | These identities cannot act as employee sponsors |

Use the exact case-sensitive values `admin` and `dependentRegistrant`; the UI may label them Admin and Dependent registrant. A dependent registrant does not receive the business section. App01 has no partner section or Partner admission.

Provision the selected employee's ordinary `Employee` role and app-specific approval first. Then assign the app02 capability in the **workforce** enterprise application, using **Users and groups → Add user/group → Select a role**. Sign out and sign in again so the signed application cookie reflects the new role. [Microsoft: assign enterprise-application access](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-user-or-group-access-portal).

The setup script [Configure-PocRegistration.ps1](../../scripts/poc/Configure-PocRegistration.ps1) defines the app02 capabilities and checks that capability recipients are enabled members with current Employee assignment and approval. `-AllowedOperatorObjectId` receives both capabilities; `-DependentRegistrantObjectIds` receives only `dependentRegistrant`. This does not add anyone to the driver's independent operator allowlist. Keep real object IDs in the private setup inventory.

## Configure the server services

Use the existing owned workforce/external manifests and the hosting subscription. The configuration script takes `-SubscriptionId`, `-WorkforceTenantId`, `-ExternalTenantId`, `-NameSuffix`, optional site names, selected capability object IDs and a future `-ApprovalLimitUtc`. Use `-WhatIf` to inspect the intended operation before an authorized setup. It creates owned, tagged communication/email resources in the same PoC resource group and subscription, an Azure-managed sender, and protected per-app registration configuration.

Provisioning is separate from the four interactive OIDC clients. The sample sites use their managed identities for workforce Graph operations and managed email. A separate external-directory provisioner creates customer identities and assigns customer roles. Interactive demo sign-in retains its identity scopes; it does not receive directory provisioning permissions.

The app process reads `MULTIIDP_SAMPLEAPP01_REGISTRATION_CONFIG` or `MULTIIDP_SAMPLEAPP02_REGISTRATION_CONFIG`, each an absolute protected JSON path. Replaceable configuration remains in IIS-protected `App_Data`. Runtime invitations/approvals use `D:\home\data\multiidp\<appId>\registration-state.json`, separately for `sampleapp01` and `sampleapp02`, outside `wwwroot`. The deployment ZIP must never contain or replace that state file or its lock file. Windows/IIS commits use a same-directory `MoveFileExW` rename with replace-existing/write-through flags, the sidecar lock and a flushed writer. A failed commit retains its private temporary file for recovery; there is no copy-overwrite or delete-then-move fallback. The external provisioner credential is `MULTIIDP_REGISTRATION_EXTERNAL_SECRET`, held privately and staged into the server environment. Keep recipient records, hashes, approvals, sender configuration and credentials out of displayed source.

During live verification, a ZIP deployment removed the former App_Data state file containing one `pending_identity` / `not_sent` record and zero registration approvals. No email had been sent. This was a failed unsent setup attempt, not a canceled or completed registration. Configure/deploy scripts now target the separate data path above. The corrected private runtime record survived several later ZIP deployments, confirmed in the live UI; delivery, account setup and redemption remain separate tests. An existing customer/role is not evidence that the lost invitation was completed, and a missing audit must never be treated as safe permission to resend an uncertain operation.

Before sending invitations, run `Configure-PocPasswordSetup.ps1 -TenantId <external-tenant-id>` after registration configuration. It creates a separate native account-setup client, associates it with the existing EmailPassword flow, and writes its client ID to both private registration configurations. It grants no Graph/API permissions. The four web sign-in clients remain confidential code + PKCE clients; public signup remains disabled.

The invitation opens **Verify email and create password**, then the Microsoft email-code verification screen and **Create your password**. For these pre-provisioned accounts, the implementation uses Microsoft's native SSPR protocol directly as initial password setup. It does not send the recipient to a Forgot password link. Existing customers can choose existing-account sign-in. A separate native client is needed because native APIs require a public/native registration; this is an account-setup extension to the MSAL web login architecture. [Microsoft native API reference](https://learn.microsoft.com/en-us/entra/identity-platform/reference-native-authentication-api).

`PasswordSetupController.cs` validates the invitation, enabled account/email identity, sponsor and CSRF token. `PasswordSetup.cs` calls `start`, `challenge`, `continue`, `submit` and `poll_completion`. Email codes and passwords are forwarded over HTTPS and never persisted or logged. Native continuation tokens remain in a ten-minute server session; this sample never redeems them for authentication tokens. Each step rechecks the current invitation. Verification-email starts have a persistent five-minute cooldown. Public signup, B2B authentication and app approval rules are unchanged. Successful password setup returns to MSAL sign-in and invitation confirmation. An app restart expires the temporary setup session; the recipient reopens the existing invitation.

## Personal-email invitation

1. The approved employee opens **Invite someone** in the selected app, enters the recipient's personal email and, for a dependent, confirms the relationship and benefit purpose. App02 shows the business section only to an eligible Employee with `admin`.
2. The server rechecks the actor's current directory roles and approval, provisions or locates the External ID customer, and assigns the selected app's `Dependent` or `External` role. It binds the invitation to that exact tenant/object ID before sending email.
3. The Azure-managed sender emails an HTTPS invitation link. The link expires after **at most 24 hours**, or earlier at the approved deadline. The server stores a token hash; the bearer link is not a password and is not placed in the driver or source package.
4. The recipient opens the link, selects **Verify email and create password**, verifies the Microsoft email code, and enters and confirms their password. Existing customers can select **Sign in with my existing account**. Microsoft confirms password completion before the app starts normal MSAL sign-in. No password is emailed.
5. Signed-in identity must match the bound customer object. The invitation session permits registration completion only; it does not grant protected business pages. The recipient confirms registration with a CSRF-protected POST.
6. The server rechecks the sponsor, current capabilities, expiry, directory role and application rules. Successful redemption atomically records the approval and consumes the invitation. A subsequent normal sign-in establishes ordinary application access.

Email delivery, email verification and business approval are three separate results. A provider-accepted send or generated link is insufficient evidence that the recipient received the email and completed registration. Do not automatically resend an operation whose delivery outcome is uncertain.

### Resume registration from ordinary sign-in

A recipient who has set their password but has not confirmed registration can sign in from the app's home page. After normal token validation, the app resumes registration only when there is exactly one current, bound, `ready` invitation with `emailStatus=sent` for that app. The signed tenant/object ID, identity source, issuer, audience and required target-app role must match the invitation; organizational partners must also present the expected signed home issuer. An email match alone is insufficient.

The protected application cookie holds the invitation ID and `registration_only` restriction, expires within 20 minutes or sooner at invitation expiry, and redirects to `/Registration/Complete`. It grants no benefit or other protected application access. **Confirm registration** remains a CSRF-protected POST that rechecks the invitation, current sponsor roles and approval before atomically consuming it and recording the recipient's approval. The recipient must then complete a fresh ordinary sign-in for application access.

Missing, duplicate, expired, canceled or unsent invitations cannot resume. When the sign-in explicitly carries an original invitation token, that token must be valid; a failed token never falls back to invitation lookup. The original emailed invitation and password-setup flow are unchanged.

The sponsor's **Invite someone** page shows only that sponsor's masked invitation statuses. **Cancel unsent invitation** is available only for a `pending_identity` or bound `ready` record with `emailStatus=not_sent` and no email operation ID. Its CSRF-protected POST refreshes current sponsor roles/approval and atomically rechecks those conditions. Cancellation preserves the record/hash/audit and creates no approval; it does not delete a customer or undo directory assignments. The server can also safely cancel a directory-only failure before any delivery attempt. Once an operation is queued, submitted or uncertain, do not cancel or automatically resend it: the operation ID and queued status are persisted before ACS submission.

For dependents, the approval records the sponsor's stable workforce tenant/object IDs as the linked employee. Admission requires that same-app employee approval to remain unique, current and benefit-eligible. The relationship confirmation is a PoC attestation; the production source of relationship and benefit evidence still needs customer agreement.

## Organizational vendor / partner invitation

App02's authorized employee administrator uses the business section. Personal business contacts follow the external-customer path above; a separate verified Microsoft 365/Entra organization follows workforce B2B. Domain discovery provides a candidate organizational tenant, not proof that the recipient belongs to it.

Exact known consumer-provider domains, including `gmail.com`, always take the personal External ID registration path and skip organizational metadata discovery. Matching is case-insensitive and exact; suffixes/subdomains do not inherit the classification. A returned organizational tenant is only a candidate, with internal workforce/external tenants excluded as partner homes. Signed home-issuer evidence plus app approval establishes partner admission; it does not prove a Microsoft 365 product license.

The server makes one Graph B2B invitation with `sendInvitationMessage=false`, binds the returned Caldova resource-tenant guest and assigns app02 `Partner`. ACS sends Graph's native `inviteRedeemUrl`; its return target is the app-specific invitation. There is no second Graph invitation or redemption reset. The recipient redeems using the expected home organizational account, completes required security-information enrollment/MFA and returns to the app. Microsoft supports delivering the returned redemption URL through the application's own communication service. [Microsoft: invitation resource](https://learn.microsoft.com/en-us/graph/api/resources/invitation?view=graph-rest-1.0).

Protected admission still checks the signed resource tenant/object ID and Partner role, the signed `idp` against the expected home issuer, accountable sponsor, verified organization and current app02 approval. Personal OTP fallback does not establish an organizational partner. A workforce authentication error must not reroute the account to External ID. Preflight the organization's permitted security-information enrollment procedure; MFA remains required.

The new partner domain route activates only after signed home proof and redeemed, current app02 approval. App01 never creates a dynamic partner route. Repeated sends for the same app/recipient are blocked while an invitation is current, including concurrent or differently cased addresses. Private email status records are operational evidence; they do not grant admission.

## Verify and hand off

Use synthetic business data and privately approved recipients. Record these checks individually:

- App01 Employee can invite a dependent; app02 Employee alone cannot; app02 `dependentRegistrant` can invite a dependent but cannot use the business section; app02 `admin` can use both. Partner/external identities cannot send invitations.
- The intended recipient receives the email and completes Microsoft-controlled account setup without receiving a password from the application.
- Wrong identity, wrong app, expired link, second redemption, forged/absent CSRF token and revoked sponsor/capability all fail. Concurrent redemption grants approval once.
- Ordinary sign-in resumes only a unique current, sent invitation for the exact validated identity and required role. The registration-only session cannot access benefits; confirmation consumes the invitation, and fresh sign-in is required. Invalid explicit tokens, duplicate invitations and unsent invitations fail.
- The new dependent enters only the approved app and loses access when the eligible linked employee expires or is revoked. The organizational partner presents the expected signed home issuer and enters app02 only.
- Every hosted driver URL, asset, catalog, manifest and source download requires the configured Caldova operator sign-in and object-ID allowlist. This separate EasyAuth boundary does not replace the demo apps' own authentication or capabilities. An offline driver copy remains local.

Inspect the actual source in [Registration.cs](../../samples/net48/Shared/Registration.cs), [RegistrationServices.cs](../../samples/net48/Shared/RegistrationServices.cs), [RegistrationControllers.cs](../../samples/net48/Shared/RegistrationControllers.cs), [Startup.cs](../../samples/net48/Shared/Startup.cs) and [Policy.cs](../../samples/net48/Shared/Policy.cs). Keep the generated code catalog aligned with those files. Record sender/resource identifiers and real recipient data only in the private handoff inventory; public documentation and downloadable source contain no credentials, invitation links or personal records.
