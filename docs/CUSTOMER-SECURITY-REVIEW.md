# Security review and deployment status

Review date: **9 October 2026**. Scope: the checked-in .NET Framework PoC, ASP.NET Core reference, deployment scripts, customer architecture artifacts, and selected read-only cloud checks. This is a scoped engineering review, not a penetration-test or production certification.

## Corrected session lifetime

The shared OIDC configuration now sets `UseTokenLifetime = false` for both identity providers. Previously, Katana could copy an ID token's expiry into the authentication ticket, overriding the intended 20-minute application session. The application cookie now controls that lifetime, with sliding renewal disabled. Invitation-only sessions retain their earlier explicit expiry restriction.

Two regression tests execute the real startup configuration using synthetic values. Both failed before the correction; after it, the .NET Framework suite passes **234/234** with zero build warnings or errors. The separate ASP.NET Core reference passes **27/27**, also with a clean build. The mocked provisioning-script checks pass. Current NuGet advisory checks reported no known vulnerable direct or transitive packages in either solution.

The Windows CI job now builds and tests the Framework applications and mocked provisioning scripts. CI also runs on PoC branch pushes. The existing reference-app job remains in place. Local checks passed; a hosted CI run is a separate result.

## Privacy and repository content

The architecture SVG, PNG and companion documents use generic **Workforce tenant** and **External ID tenant** labels. They contain no real tenant, client, subscription or object IDs; deployment hostnames; personal addresses; credentials; tokens; or actual governance records. The SVG has no executable scripts or external assets.

The repository review covered eight existing reachable commits and 149 unique Git blobs, plus the proposed changes. No embedded private keys, recognized access-token formats, storage account keys or non-synthetic personal email addresses were found. Credential-like test strings are synthetic fixtures. Git author/committer attribution was outside the content scan. Pattern and source review reduce risk; they cannot prove that every possible secret format has been excluded.

Older operational documents and the driver still contain environment-specific tenant/resource metadata. They are not the customer-safe architecture deliverable. Share the architecture image and its companion documents, rather than assuming the entire repository is an anonymized customer package. Private configuration, credentials, deployment archives and runtime state remain outside tracked source.

## Live deployment findings

Read-only checks against the deployment's recorded subscription confirmed three running Windows App Service sites. All enforce HTTPS, minimum TLS 1.2 for site and deployment endpoints, and disabled FTP. Both sample applications own their OWIN authentication. The separate driver has platform authentication enabled, requires sign-in on all paths, has one explicitly allowed operator identity and has its token store disabled.

**Credential renewal is required.** Live directory metadata showed that each of the four interactive application registrations has one client secret, all expired on **7 October 2026**, with no unexpired replacement credentials. The private driver manifest also records an expired credential; its current directory credential metadata was not independently confirmed. Anonymous application home pages returned HTTP 200, which does not prove that sign-in works.

No cloud settings, credentials, assignments or deployments were changed by this review. The session-lifetime correction is a source change and must be deployed before it can protect live sessions. The deployment process does not expose a reliable source-commit marker; the exact currently deployed revision was not established.

## Remaining operational boundaries

- Application entitlement status and expiry are rechecked on protected requests. Directory account disablement or role changes do not immediately invalidate existing normal application cookies; they require fresh authentication or expiry.
- The automatic exact-UPN workforce lookup intentionally reveals a routing distinction. Public production exposure needs an explicit account-enumeration and abuse-control decision.
- Directory application permissions for provisioning are broad grants. Application checks constrain intended operations, but they do not narrow the underlying directory credential's authority.
- The PoC's dependent relationship and benefit eligibility inputs are sponsor attestation and application records, not independent HR verification. The file-backed state store also needs production decisions for backup, recovery and multi-instance coordination.
- Personal invitation receipt, account setup, completed redemption and real partner protected admission remain distinct end-to-end acceptance checks. Historical provider acceptance or a successful synthetic test is not proof of those journeys.

See the [architecture image](customer-architecture.svg) and [implementation walkthrough](CUSTOMER-ARCHITECTURE.md) for trust boundaries and source links.
