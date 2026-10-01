# .NET Framework 4.8 PoC Implementation Plan

> For agentic workers: use subagent-driven-development for the independent deliverables and review their integration.

**Goal:** Deliver two IIS .NET Framework 4.8 identity demonstrations, configured in Caldova and External ID, and an onsite driver.

**Architecture:** Shared OWIN/OIDC web authentication uses direct MSAL.NET code redemption against two tenant-specific authorities. Workforce B2B supports approved partner organizations; external users retain customer identities in External ID. Stable identity keys and explicit entitlements enforce application access.

**Tech stack:** ASP.NET MVC / System.Web, net48, Microsoft.Owin, Microsoft.Identity.Client, static HTML/CSS/JavaScript, PowerShell and Microsoft Graph administration.

**Spec:** docs/poc/DESIGN.md

## Constraints

- IIS-hosted net48, shared authentication source, separate sampleapp01/sampleapp02 registrations in each tenant.
- Concise copy, numbered onsite steps, no claims that a domain proves Microsoft 365 membership.
- Credentials and real governance records outside source control.
- Exact tenant and audience validation, antiforgery, secure cookies, app-specific entitlement and expiry checks.

## Tasks

- [x] Build net48 applications and behavioral routing/authorization tests under samples/net48 and tests/Net48.
- [x] Create driver/index.html, driver/site.css and driver/site.js with customer setup steps, sources, editable non-secret values, progress and acceptance evidence.
- [x] Identify Caldova workforce tenant; create the isolated resource group, new External ID directory, three hosted sites, four registrations/service principals, roles, separate credentials, flow association and targeted assignments.
- [x] Add idempotent tenant/configuration scripts and source demonstration documentation; publish the new driver and source package.
- [x] Add Architecture as the driver opening view, fix sidebar/progress overlap and preserve app-specific source browsing and the 12-step print runbook.
- [x] Implement employee-scoped registration capabilities, bound one-use invitations, separate directory provisioning and managed-email integration; synthetic suite reports 163/163 passed.
- [x] Protect every hosted driver URL with a separate Caldova EasyAuth registration and admin operator object-ID allowlist; anonymous and approved-operator checks pass.
- [x] Configure owned ACS sender, site managed identities, external provisioner, capability roles and private registration configuration.
- [x] Add sponsor-only masked invitation inventory and protected unsent-cancellation recovery; persist queued operation audit before ACS submission.
- [ ] Verify ACS delivery, customer SSPR, native organizational redemption and new protected admission.
- [ ] Build and test applications, review security/architecture, inspect driver in browser, verify Graph state and record unfinished live checks.

## Execution record

Ruling: work on poc/net48-dual-tenant in the requested checkout so the delivered source remains visible in C:\multiidpapp. The initial checkout was clean.

Ruling: the authorized scope already specifies implementation and tenant configuration; do not add a separate design-approval round.

Delivery: Windows B1 hosting and the new external-directory resource are in `rg-caldova-multiidp-poc` in the Oguzhan subscription. Code, registrations, flow, assignments and the driver are delivered. See [HANDOFF.md](HANDOFF.md) for live site/configuration identifiers, confirmed sign-ins, secret expiry and private credential access.

Status on 1 October 2026: validation remains open. Earlier real retiree sign-in passed in both apps; dependent app01 passed and app02 was denied as unassigned; approved workforce operator sign-in and retiree app01 CSRF logout passed. Synthetic employee MFA remains pending. The approved partner completed organizational SSO/consent and B2B acceptance; its app02 Partner assignment exists. Resource registration previously returned AADSTS53003. The user-authorized guest-only exception preserved other policy fields and MFA; enrollment and protected app02 admission remain PENDING. App01 has no partner route. The withdrawn candidate's PoC access and owned guest copy were removed, leaving its home account unchanged.

The driver gate and offline architecture/code/mobile/large-font checks pass. Historical HTTP/source privacy evidence is recorded separately from current packaging. Registration is implemented and configured: app01 Employee may invite dependents; app02 requires Employee plus `admin` or `dependentRegistrant` for dependents and Employee plus `admin` for the business section. ACS sends personal links or the native B2B redemption URL from one Graph invitation with `sendInvitationMessage=false`. New email delivery, SSPR and one-use confirmation are not yet verified live. See [REGISTRATION.md](REGISTRATION.md); final acceptance remains unchecked.
