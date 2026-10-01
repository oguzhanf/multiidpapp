"use strict";
(() => {
  const storageKey = "multiidp.net48.driver.v1";
  const appIds = ["sampleapp01", "sampleapp02"];
  const defaultValues = app => ({
    baseUrl: app === "sampleapp01" ? "https://localhost:44371" : "https://localhost:44372",
    workforceTenantId: "11111111-1111-4111-8111-111111111111",
    workforceClientId: app === "sampleapp01" ? "33333333-3333-4333-8333-333333333331" : "33333333-3333-4333-8333-333333333332",
    workforceIssuer: "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/v2.0",
    employeeDomains: "employee.example",
    approvedPartnerDomains: app === "sampleapp02" ? "partner.example" : "",
    externalTenantId: "22222222-2222-4222-8222-222222222222",
    externalClientId: app === "sampleapp01" ? "44444444-4444-4444-8444-444444444441" : "44444444-4444-4444-8444-444444444442",
    ciamDomain: "poc-example.ciamlogin.com",
    externalIssuer: "https://poc-example.ciamlogin.com/22222222-2222-4222-8222-222222222222/v2.0"
  });
  const fieldNames = Object.keys(defaultValues("sampleapp01"));
  const state = { app: "sampleapp01", step: 0, values: {}, progress: {} };
  let currentView = "architecture";
  let architectureFlow = "signin";
  let architectureChoice = "applications";
  const selectedCodeFiles = { sampleapp01: "", sampleapp02: "" };
  let storageAvailable = true;
  appIds.forEach(app => { state.values[app] = defaultValues(app); state.progress[app] = {}; });
  try {
    const saved = JSON.parse(localStorage.getItem(storageKey) || "null");
    if (saved && typeof saved === "object") {
      if (appIds.includes(saved.app)) state.app = saved.app;
      if (Number.isInteger(saved.step) && saved.step >= 0 && saved.step < 12) state.step = saved.step;
      appIds.forEach(app => {
        fieldNames.forEach(key => {
          if (typeof saved.values?.[app]?.[key] === "string") state.values[app][key] = saved.values[app][key].slice(0, 1000);
        });
        Object.entries(saved.progress?.[app] || {}).forEach(([key, value]) => {
          if (/^\d{1,2}-\d{1,2}$/.test(key) && value === true) state.progress[app][key] = true;
        });
      });
    }
  } catch (_) { storageAvailable = false; }

  const esc = value => String(value).replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
  const inline = value => `<code>${esc(value)}</code>`;
  const refs = links => `<div class="references">${links.map(([label, path]) => `<a href="https://learn.microsoft.com/en-us/${path}" target="_blank" rel="noopener noreferrer">${esc(label)}</a>`).join("")}</div>`;
  const code = (title, value) => `<div class="code-block"><div class="code-toolbar"><span>${esc(title)}</span><button type="button" class="copy-button" aria-label="Copy ${esc(title)}">Copy</button></div><pre><code>${esc(value)}</code></pre></div>`;
  const list = items => `<ol class="instructions">${items.map(item => `<li>${item}</li>`).join("")}</ol>`;
  const callout = value => `<div class="callout">${value}</div>`;
  const table = (heads, rows) => `<div class="table-scroll"><table><thead><tr>${heads.map(h => `<th scope="col">${h}</th>`).join("")}</tr></thead><tbody>${rows.map(row => `<tr>${row.map(c => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
  const domains = value => value.split(",").map(item => item.trim().toLowerCase()).filter(Boolean);
  const workforceAuthority = v => `https://login.microsoftonline.com/${v.workforceTenantId}/v2.0`;
  const externalAuthority = v => `https://${v.ciamDomain}/${v.externalTenantId}/v2.0`;
  const callback = (v, source) => `${v.baseUrl}/signin-${source}`;
  const envPrefix = app => `MULTIIDP_${app.toUpperCase()}`;

  const steps = [
    {
      title: "Tenant readiness", short: "Tenant readiness",
      intro: "Confirm two separate directories and a safe test scope before making application changes.",
      body: (app, v) => list([
        `Open <a href="https://entra.microsoft.com/" target="_blank" rel="noopener noreferrer">Microsoft Entra admin center</a>. Switch to the workforce directory; record tenant ${inline(v.workforceTenantId)}. Switch to the External ID <strong>external tenant</strong>; record ${inline(v.externalTenantId)} and its CIAM hostname. Replace the synthetic application values above.`,
        "Confirm delegated operators for app registration/consent, customer users and user flows. Agree test accounts, sponsors, application owners, expiry and rollback owner. Keep real inventories and credentials outside the repository and driver.",
        "On the IIS host, confirm .NET Framework 4.8, ASP.NET 4.x support, trusted HTTPS bindings, and outbound access to discovery, signing-key and token endpoints. Confirm the build machine can restore the pinned NuGet packages.",
        "Keep the working Kerberos application available. Use separate PoC IIS sites and application pools; agree how OIDC identities map to business records before migrating existing users."
      ]) + callout("<strong>Kerberos → OIDC:</strong> the app receives a validated claims identity and an application cookie. This does not create a Windows token or automatically impersonate the user for files, SQL or other downstream services. Design those access paths separately.") + refs([
        ["Create an external tenant", "entra/external-id/customers/how-to-create-external-tenant-portal"],
        ["Supported external-tenant features", "entra/external-id/customers/concept-supported-features-customers"]
      ]),
      checks: ["Confirmed both directory IDs and the actual CIAM hostname.", "Agreed PoC owners, test scope, HTTPS host and rollback path."]
    },
    {
      title: "Register app01 in workforce", short: "App01 workforce registration",
      intro: "Create a single-tenant Web registration for sampleapp01 in the workforce directory.",
      body: (app, v) => {
        const current = state.values.sampleapp01;
        return list([
          "Select the workforce directory. Go to <strong>Entra ID → App registrations → New registration</strong>. Name it sampleapp01-net48-workforce. Choose <strong>Accounts in this organizational directory only</strong>.",
          `Set platform <strong>Web</strong> and redirect URI ${inline(callback(current, "workforce"))}. Record the Application (client) ID in the app01 values. Do not use an enterprise-app object ID as the client ID.`,
          "Keep implicit access-token and ID-token issuance disabled: this sample uses code flow with PKCE. Review sign-in scopes and admin consent; the interactive app does not need provisioning or directory-write permissions.",
          "Open the corresponding enterprise app. Set <strong>Assignment required? → Yes</strong>. App01 workforce exposes the exact Employee role only; employee assignment comes in step 6. Create the separate app credential only through the approved private process in step 9."
        ]) + code("App01 workforce redirect URI", callback(current, "workforce")) + refs([
          ["Register an application", "entra/identity-platform/quickstart-register-app"],
          ["Require assignment", "entra/identity/enterprise-apps/what-is-access-management"]
        ]);
      },
      checks: ["App01 workforce client ID and Web callback match the registration.", "Assignment requirement, app roles and consent reviewed."]
    },
    {
      title: "Register app01 in External ID", short: "App01 external registration",
      intro: "Create a second registration in the external directory. It is independent of the workforce registration.",
      body: (app, v) => {
        const current = state.values.sampleapp01;
        return list([
          "Switch to the External ID external tenant. Go to <strong>Entra ID → App registrations → New registration</strong>. Name it sampleapp01-net48-external; select the tenant-only account type.",
          `Set platform <strong>Web</strong> and redirect URI ${inline(callback(current, "external"))}. Record this separate Application (client) ID in app01 values.`,
          "Review the external registration's sign-in permissions and grant required administrator consent. Leave implicit issuance disabled and avoid Graph provisioning permissions on this web app.",
          "Review assignment requirement and the exact Retiree, Dependent and External roles. Its credential is separate from the workforce credential. Associate this registration with a customer user flow in step 5."
        ]) + code("App01 external redirect URI", callback(current, "external")) + callout("An External ID customer account belongs in the external directory. Inviting a guest administrator to that directory is a different operation; it does not create a customer account for the user flow.") + refs([
          ["Register an external application", "entra/external-id/customers/how-to-register-ciam-app"],
          ["Customer accounts", "entra/external-id/customers/how-to-manage-customer-accounts"]
        ]);
      },
      checks: ["App01 external client ID and Web callback match the registration.", "External consent, assignment requirement and separate credential owner reviewed."]
    },
    {
      title: "Repeat for app02", short: "App02 registrations",
      intro: "Create two more registrations. App02 has its own clients, credentials, callbacks and access decisions.",
      body: (app, v) => {
        const current = state.values.sampleapp02;
        return list([
          "Repeat steps 2 and 3 for <strong>sampleapp02-net48-workforce</strong> and <strong>sampleapp02-net48-external</strong>. Use the same two directories, with new client IDs and separate credentials. Switch the application tab above to edit app02 values.",
          `Workforce Web callback: ${inline(callback(current, "workforce"))}. External Web callback: ${inline(callback(current, "external"))}. Use the actual app02 IIS base URL if changed.`,
          "App02 workforce exposes Employee, Partner, admin and dependentRegistrant. App02 external exposes Retiree, Dependent and External. Require assignment for both enterprise apps. Grant administrator consent where required.",
          "Never reuse app01's client ID or credential for app02. A user's approval for app01 does not approve app02; record each application separately."
        ]) + table(["Registration", "Directory", "Web callback"], [
          ["sampleapp02-net48-workforce", "Workforce", inline(callback(current, "workforce"))],
          ["sampleapp02-net48-external", "External ID", inline(callback(current, "external"))]
        ]) + callout("Four registrations in total: two apps × two identity directories. The shared authentication source is reused by both IIS applications.");
      },
      checks: ["App02 has two separate client IDs, credentials and correct Web callbacks.", "App02 roles, assignment and consent reviewed independently of app01."]
    },
    {
      title: "Associate the external user flow", short: "External user flow",
      intro: "Give each external registration the intended customer sign-in experience.",
      body: (app, v) => list([
        "In the external directory, go to <strong>Entra ID → External Identities → User flows → New user flow</strong>. Choose the agreed email-with-password or email-one-time-passcode method. Configure recovery and MFA only within the agreed PoC scope.",
        `Open the flow → <strong>Use → Applications → Add application</strong>. Select ${inline(`${app}-net48-external`)} → <strong>Select</strong>. Repeat for the other external registration if it uses this flow.`,
        "Each application has one user flow; a flow can serve both apps. Check the client IDs in the flow's application list, then run the flow against the intended registration.",
        "For pre-registered-only users, set onInteractiveAuthFlowStart.isSignUpAllowed=false and verify the saved value. The setup script uses Microsoft Graph v1.0, which supports this property; Microsoft's older how-to shows a beta example. Assignment and application approval remain separate controls."
      ]) + callout("Do not treat a hidden sign-up link as an admission control. If self-service account creation remains enabled, an unapproved account must still fail assignment or application entitlement checks.") + refs([
        ["Create a user flow", "entra/external-id/customers/how-to-user-flow-sign-up-sign-in-customers"],
        ["Associate an application", "entra/external-id/customers/how-to-user-flow-add-application"],
        ["Disable sign-up", "entra/external-id/customers/how-to-disable-sign-up-user-flow"],
        ["Graph v1.0 flow setting", "graph/api/resources/oninteractiveauthflowstartexternalusersselfservicesignup?view=graph-rest-1.0"]
      ]),
      checks: ["Verified the selected external client appears in the intended flow.", "Verified sign-up policy, chosen email method and recovery/MFA scope."]
    },
    {
      title: "Assign employee roles and onboard partners", short: "Workforce users & partners",
      intro: "Separate application admission from employee registration capabilities. App02 partners use verified workforce B2B identities.",
      body: (app, v) => list([
        `In workforce <strong>Enterprise apps → ${esc(app)}-net48-workforce → Users and groups → Add user/group</strong>, assign the approved Caldova member the exact ${inline("Employee")} role. Record its tenant/object-ID key and current app-specific employee approval privately.`,
        app === "sampleapp01" ? "An approved, benefit-eligible app01 Employee may invite a dependent. App01 requires no extra registration capability and has no business/partner section." : `For app02 dependent registration, also assign ${inline("admin")} or ${inline("dependentRegistrant")}. The vendor/business-partner section requires Employee plus ${inline("admin")} only. These are application roles; a tenant administrator title alone does not grant the capability.`,
        "Only enabled Caldova workforce members with current Employee approval can sponsor registration. Partner and external identities cannot. Sign out and sign in after a role change. Configure-PocRegistration.ps1 provisions the selected member capabilities; keep real operator/object IDs private.",
        "For app02 partners, first verify the partner's home Entra organization with its administrator and approve the sponsor, allowed application and expiry. Microsoft 365 uses Entra organizational accounts; an email domain or arbitrary Gmail guest does not prove that relationship.",
        "In sponsored registration, exact known consumer providers such as gmail.com stay on the personal External ID path without organizational discovery. Other-domain discovery gives a candidate tenant only; signed home-issuer proof and approval are required, without any Microsoft 365 product-license guarantee.",
        `Manual onboarding uses workforce <strong>Users → New user → Invite external user</strong>, organizational redemption and the app02 ${inline("Partner")} assignment. The new app02 admin business section instead makes one Graph invitation with ${inline("sendInvitationMessage=false")}, binds the returned guest and sends the native Microsoft redemption URL through Azure Communication Services. New delivery/redemption is pending live validation.`,
        "Preflight security-information enrollment: existing registration policies may require an approved organizational network. Use the tenant's approved enrollment procedure and preserve existing security controls.",
        "Authenticate organizational guests through the Caldova resource workforce authority. Explicit partner routes require approved onboarding; the new invitation flow activates its partner domain route only after signed home proof and redeemed, current app02 approval. App01 never adds partner routes."
      ]) + table(["Registration action", "Required signed roles"], app === "sampleapp01" ? [["Dependent invitation", inline("Employee")]] : [["Dependent invitation", `${inline("Employee")} + (${inline("admin")} or ${inline("dependentRegistrant")})`], ["Vendor / partner invitation", `${inline("Employee")} + ${inline("admin")}`]]) + callout("<strong>Implemented; configured and pending live validation:</strong> employee capability checks, sponsored invitations and managed email. Neither an assigned role nor a sent email proves completed registration. The hosted driver has a separate admin object-ID allowlist; these app roles do not grant driver access.") + `<h3>Alternative: partner lifecycle in External ID</h3><p>Microsoft documents Entra tenant federation through a custom OIDC identity provider in External ID. Configure each approved partner IdP and add it to the user flow if this governance model is chosen. The demos use workforce B2B for partners by default.</p>` + refs([
        ["Assign enterprise-app users", "entra/identity/enterprise-apps/assign-user-or-group-access-portal"],
        ["Invite a workforce B2B guest", "entra/external-id/b2b-quickstart-add-guest-users-portal"],
        ["Graph invitation and custom email", "graph/api/resources/invitation?view=graph-rest-1.0"],
        ["Entra OIDC federation in External ID", "entra/external-id/customers/how-to-entra-id-federation-customers"]
      ]),
      checks: ["Employee role, approval and selected app's registration capabilities reviewed.", "For app02, partner home organization, invitation redemption, guest identity and role verified; for app01, partner access excluded."]
    },
    {
      title: "Invite and set up external customers", short: "Registered external users",
      intro: "Retirees, dependents and other approved personal identities use External ID. Account setup and application approval are separate.",
      body: (app, v) => list([
        "For seeded/administrator-managed customer identities, review <strong>Entra ID → Users</strong> in the external directory and capture the stable tenant/object-ID key privately. Do not use an external-tenant administrative guest invitation to create a customer account.",
        `After configuring registration and Email OTP, run ${inline("Configure-PocPasswordSetup.ps1 -TenantId <external-tenant-id>")}. This adds a separate public/native setup client with no API permissions to the controlled EmailPassword flow and records its ID in both private app configurations. Deploy both apps. Public signup stays disabled; normal login stays MSAL code + PKCE.`,
        `Assign the selected external enterprise application's exact ${inline("Retiree")}, ${inline("Dependent")} or ${inline("External")} persona role and app-specific approval. Preserve a separate unassigned non-admin customer for the denial test. Retirement eligibility still needs an approved business source.`,
        "For the new sponsored flow, sign in as an eligible Employee and open <strong>Invite someone</strong>. Use a personal email, select dependent or the app02 admin business purpose, and confirm the dependent relationship/benefit purpose where required.",
        "The server locates or provisions the customer, assigns the selected app's role, binds the exact tenant/object ID and sends an ACS invitation. The link expires within 24 hours or earlier at the approval deadline. Tokens are hashed in private server state; redemption is one-use.",
        "The recipient opens the HTTPS invitation, selects <strong>Verify email and create password</strong>, enters Microsoft's email code, then creates and confirms a password. Existing customers can choose their existing-account sign-in. The application does not email passwords.",
        "After a matching signed-in identity, a CSRF-protected confirmation creates the approval only if sponsor, roles and expiry still pass. An ordinary login can resume a unique sent, current invitation bound to that signed directory identity. Until confirmation, the session permits registration completion only; sign in again afterward for protected access."
      ]) + callout("<strong>Pending live validation:</strong> ACS delivery, Microsoft email-verified password setup and new invitation redemption. The current adapter expects email/password plus SSPR; an OTP-only flow is an alternative requiring separate validation. Changing the flow does not convert existing password accounts.") + refs([
        ["Manage customer accounts", "entra/external-id/customers/how-to-manage-customer-accounts"],
        ["Native account setup API", "entra/identity-platform/reference-native-authentication-api"],
        ["Customer authentication methods", "entra/external-id/customers/concept-authentication-methods-customers"],
        ["Supported external-tenant features", "entra/external-id/customers/concept-supported-features-customers"]
      ]),
      checks: ["Correct customer flow/account setup exercised; invitation delivery and redemption recorded separately.", "Approved role and app approval verified; unassigned denial account remains unassigned."]
    },
    {
      title: "Approve application entitlements", short: "Application governance",
      intro: "Make each application's access decision explicit, with a sponsor, approval, relationship and expiry.",
      body: (app, v) => list([
        "Use the verified issuing tenant + object ID as the stable identity key. Keep records server side in the protected entitlement file named by the application's configuration.",
        "Record allowed application, identity source, persona, sponsor, approval status and UTC expiry. For dependents, set linkedEmployeeTenantId and linkedEmployeeObjectId to the employee's stable identity. That employee needs a unique, approved, unexpired workforce entitlement for the same app with benefitEligible=true. Retiree eligibility needs an approved business source.",
        "Directory role assignment gates admission; the app checks its own entitlement on protected requests. App01 approval must not grant app02 access. Reject expired, unapproved, missing, wrong-source or disallowed-persona records.",
        "Registration approvals are server records, separate from the driver's local checkpoints. Creation and confirmation refresh the sponsor's directory roles and approval; redemption commits the approval and consumes the link once. Revoked capability, expired sponsor or a different recipient must fail.",
        "Registration uses site managed identities for workforce Graph and ACS, plus a separate External ID provisioner. Configuration stays in protected App_Data. Invitation and approval state stays outside wwwroot under D:\\home\\data\\multiidp\\<appId>, so publishing does not replace it. The four interactive clients retain sign-in scopes.",
        "Demonstrate the relationship and trip-benefit rules with synthetic records. Agree the production system of record, review cadence, sponsor offboarding and revocation behavior with the customer."
      ]) + table(["Persona", "Signed directory role", "Application rule"], [
        ["Employee", inline("Employee"), "Workforce identity; approved app-specific entitlement."],
        ["Retiree", inline("Retiree"), "External identity; approved app-specific entitlement."],
        ["Dependent", inline("Dependent"), "External identity; verified relationship and eligibility; current eligible linked employee in this app."],
        ["Other approved external customer", inline("External"), "External identity; sponsor and approved app-specific entitlement."],
        ["Partner", inline("Partner"), "App02 workforce B2B only; verified home-organization issuer and current approval."]
      ]) + code("Synthetic employee and dependent entitlement pair", JSON.stringify([
        { appId: app, tenantId: v.workforceTenantId, objectId: "55555555-5555-4555-8555-555555555555", source: "workforce", persona: "employee", status: "approved", expiresUtc: "2026-10-02T18:00:00Z", benefitEligible: true },
        { appId: app, tenantId: v.externalTenantId, objectId: "66666666-6666-4666-8666-666666666666", source: "external", persona: "dependent", sponsor: "synthetic-sponsor", status: "approved", expiresUtc: "2026-10-02T18:00:00Z", relationshipVerified: true, benefitEligible: true, linkedEmployeeTenantId: v.workforceTenantId, linkedEmployeeObjectId: "55555555-5555-4555-8555-555555555555" }
      ], null, 2)) + `<p class="source-note">Synthetic object IDs only. Replace with privately verified identities and the approved PoC expiry. Directory role assignments are separate from this file. The app rechecks the linked employee's approval, expiry and eligibility.</p>` + table(["Decision", "Evidence required"], [
        ["Who authenticated?", "Validated tenant, issuer, signature, audience, lifetime and object ID."],
        ["May this user enter this app?", "Directory role plus current, approved, app-specific entitlement."],
        ["May a dependent use a trip benefit?", "Verified employee/dependent relationship and business eligibility."],
        ["When does access end?", "Expiry, sponsor/employee changes and revocation policy."]
      ]) + callout("Invitation expiry is at most 24 hours; approval expiry is independently bounded by the sponsor and recorded PoC deadline. Duplicate active invitations for the same app/recipient are blocked; do not automatically resend uncertain email operations. Test expired/replayed links, wrong identity/app, missing CSRF and sponsor revocation before marking the new flow complete. See docs/poc/REGISTRATION.md in the source ZIP for setup details.") + refs([
        ["External-tenant feature support", "entra/external-id/customers/concept-supported-features-customers"]
      ]),
      checks: ["Synthetic records prove separate approval, sponsor, expiry and allowed application.", "Dependent access includes an approved employee relationship and eligibility decision."]
    },
    {
      title: "Configure credentials and IIS", short: "Credentials & IIS setup",
      intro: "Load the selected app's non-secret settings and separate credentials into its IIS process.",
      body: (app, v) => {
        const config = {
          appId: app,
          employeeDomains: app === "sampleapp01" ? [] : domains(v.employeeDomains),
          approvedPartnerDomains: app === "sampleapp02" ? domains(v.approvedPartnerDomains) : [],
          entitlementFile: `C:\\PocPrivate\\${app}.entitlements.json`,
          workforce: { tenantId: v.workforceTenantId, clientId: v.workforceClientId, clientSecretEnvironmentVariable: `${envPrefix(app)}_WORKFORCE_SECRET`, redirectUri: callback(v, "workforce"), issuer: v.workforceIssuer },
          external: { tenantId: v.externalTenantId, clientId: v.externalClientId, clientSecretEnvironmentVariable: `${envPrefix(app)}_EXTERNAL_SECRET`, redirectUri: callback(v, "external"), issuer: v.externalIssuer, ciamDomain: v.ciamDomain }
        };
        return list([
          `Build the net48 solution under ${inline("samples/net48")}, then publish each MVC application to its own IIS directory. Use a .NET CLR v4.0 Integrated application pool and ASP.NET 4.x. Bind ${inline(v.baseUrl)} to a trusted HTTPS certificate.`,
          "Enable Anonymous Authentication for the PoC application so OWIN owns the redirect; disable Windows Authentication on that PoC site. Keep the Kerberos site separately available. Configure cookie/machine-key protection consistently if using multiple IIS workers.",
          "Save the configuration below outside the repository. Restrict the config and entitlement files to the operator and app-pool identity. Verify both exact expected issuers against discovery before starting.",
          `Set ${inline(`${envPrefix(app)}_CONFIG`)} to that config file's absolute path. Provide the two credential environment variables to the correct IIS worker through an approved private process, then recycle that pool. A shell variable alone does not change an existing IIS worker's environment.`,
          "Keep credentials out of this page, source, command history and recordings. Use short PoC expiry and separate credentials for all four registrations. Confirm the app fails closed for absent or invalid configuration."
        ]) + code(`${app} non-secret configuration JSON`, JSON.stringify(config, null, 2)) + code("Configuration path environment variable", `$env:${envPrefix(app)}_CONFIG = 'C:\\PocPrivate\\${app}.json'\n# For a local launch process; configure the IIS worker separately.`) + callout("The JSON contains credential variable <strong>names</strong>, never secret values. IIS application startup and an actual tenant sign-in still need the privately supplied credentials. Changing driver values does not configure IIS or either tenant.");
      },
      checks: ["Configuration, entitlement file and separate credential references are loaded by the correct IIS pool.", "App starts on the registered HTTPS URL; protected access challenges through OWIN."]
    },
    {
      title: "Explain the shared source", short: "Source & authentication flow",
      intro: "Show where the tenant is chosen, the code is redeemed, and trusted identity becomes application access.",
      body: (app, v) => table(["Provider", "Authority", "Web callback"], [
        ["Workforce", inline(workforceAuthority(v)), inline(callback(v, "workforce"))],
        ["External ID", inline(externalAuthority(v)), inline(callback(v, "external"))]
      ]) + list([
        app === "sampleapp01" ? "Sampleapp01 awaits an exact UPN lookup in workforce Microsoft Graph across all tenant domains. A matching account chooses workforce; a successful empty result chooses External ID. Lookup errors stop login. A failed workforce sign-in never changes realms." : "The public sign-in page accepts an email routing hint. Employee domains and explicitly onboarded app02 partner domains choose workforce; other valid domains choose External ID. There is no retry against External ID after a workforce error.",
        "Both apps reuse the same System.Web/OWIN authentication source. Two tenant-specific OIDC middleware instances use separate client IDs and callback paths with code flow, state, nonce and PKCE S256.",
        "The MSAL code-redemption handler passes the returned ID token back through Katana's normal validation pipeline. A strict JWT validator requires signed tokens; Katana validates issuer, audience, lifetime and nonce. Application code then checks tenant, stable subject and allowed identity source.",
        "The app adds trusted source/subject claims and issues a secure application cookie. Protected actions require the current approved entitlement; app-owned authorization never trusts an email domain or sign-up persona."
      ]) + `<div class="source-excerpt"></div><p><a href="./source/net48-source.zip" download>Download packaged .NET 4.8 source</a> <span class="source-note">(included with the hosted driver; keep the source package alongside an offline copy)</span></p>` + callout("Use the shared source under <code>samples/net48</code> for this demonstration. The existing .NET 10 sample uses a different hosting and middleware model.") + refs([
        ["Code flow and PKCE", "entra/identity-platform/v2-oauth2-auth-code-flow"],
        ["ID token validation", "entra/identity-platform/id-token-claims-reference"]
      ]),
      checks: ["Explained tenant-specific authorities, callbacks, PKCE and Katana nonce validation from the shared source.", "Explained routing versus validated identity versus app-specific authorization."]
    },
    {
      title: "Run positive and negative logins", short: "Login acceptance tests",
      intro: "Use real non-admin test accounts, isolated browser sessions and synthetic business data. Record only checks actually exercised.",
      body: (app, v) => `<p>Open ${inline(v.baseUrl)}. Use a fresh private browser session between identities and confirm the address/client/callback before submitting credentials.</p>` + table(["Test", "Expected result"], [
        ["Assigned, approved employee", "Workforce challenge; correct tenant/client; protected page allowed."],
        ["Approved retiree / dependent", "External challenge and intended flow; correct tenant/client; current app entitlement allowed."],
        ["Approved M365 partner", app === "sampleapp02" ? "Workforce B2B organizational account; app02 partner role and entitlement allow." : "No partner route or entitlement; partner persona denied."],
        ["Unassigned non-admin user", "Directory or app denies access; no protected content."],
        ["Missing approval / wrong app / expired record", "Authentication may complete; app denies protected content."],
        ["Wrong tenant / issuer / audience / replayed response", "Validation fails; no session. Exercise with safe automated tests rather than changing live security controls."],
        ["Unknown email domain", "Routes to External ID; route alone grants no access."],
        ["Workforce sign-in error or cancellation", "Shows failure/cancellation; does not fall back to External ID."],
        ["Logout and revisit protected page", "App cookie cleared; a new challenge is required. Test each active provider."],
        ["Unregistered external email", "Account creation blocked when disable-sign-up is configured; otherwise unapproved access denied."]
      ]) + callout("Inspect the challenge for <code>response_type=code</code>, <code>code_challenge_method=S256</code>, state, nonce and the exact Web redirect URI. Do not save authorization codes, tokens, cookies or user credentials. Mark automated checks and live sign-ins separately.") + code("Non-secret acceptance record outline", `Application: ${app}\nBase URL: ${v.baseUrl}\nBuild/routing/entitlement checks: PASS / FAIL / NOT RUN\nLive employee sign-in: PASS / FAIL / NOT RUN\nLive external retiree/dependent sign-in: PASS / FAIL / NOT RUN\nLive partner sign-in (app02): PASS / FAIL / NOT RUN\nAssignment and entitlement denial tests: PASS / FAIL / NOT RUN\nLogout/revocation behavior: PASS / FAIL / NOT RUN\nOwner + test time: recorded in protected handoff inventory`) + refs([
        ["Code-flow request parameters", "entra/identity-platform/v2-oauth2-auth-code-flow"]
      ]),
      checks: ["Live approved employee login passed for the selected app.", "Live approved external retiree/dependent login passed for the selected app.", "App02 partner login passed, or app01 partner exclusion passed.", "Unassigned, missing-approval, wrong-app and expired access were denied.", "Invalid-token/routing checks passed; workforce errors do not fall back.", "Logout and external account-creation policy were exercised."]
    },
    {
      title: "Handoff and rollback", short: "Handoff & rollback",
      intro: "Leave a reproducible setup and a clear list of any live checks still needed.",
      body: (app, v) => list([
        "Record build version, IIS site/pool/binding, two directory IDs, four client IDs, flow association, consent/assignment evidence and credential owners/expiry in the protected deployment inventory. Include the source and configuration-file locations.",
        "Separate local build/routing/entitlement results from actual tenant sign-in results. Mark any unexercised live login, MFA, recovery or revocation check as NOT RUN. Print this runbook with the selected app's local checkpoints.",
        "Confirm who owns sponsor review, employee/dependent eligibility, partner offboarding, credential rotation, session revocation and production migration. Revalidate any outstanding customer requirement before retiring Kerberos.",
        "For rollback, stop the PoC IIS sites and restore the agreed original route to Kerberos. Revoke only the PoC assignments/credentials and remove only test registrations/accounts approved for cleanup. Preserve evidence; leave shared directories, policies and customer identities intact."
      ]) + callout("Assignment removal alone may not end an already issued application session. Validate the demo's entitlement recheck and agree the production session/revocation model before relying on offboarding."),
      checks: ["Handoff inventory separates verified results from remaining live checks.", "Rollback owner, PoC expiry and production migration decisions recorded."]
    }
  ];

  // Excerpts from samples/net48/Shared/Startup.cs and MsalOpenIdConnect.cs.
  const owinExcerpt = `var options = new OpenIdConnectAuthenticationOptions {
    AuthenticationType = source, AuthenticationMode = AuthenticationMode.Passive,
    SignInAsAuthenticationType = CookieScheme, Authority = authority + "/v2.0",
    ClientId = tenant.ClientId, RedirectUri = tenant.RedirectUri,
    CallbackPath = new PathString(new Uri(tenant.RedirectUri).AbsolutePath),
    ResponseType = OpenIdConnectResponseType.Code,
    ResponseMode = OpenIdConnectResponseMode.FormPost,
    Scope = "openid profile email", UsePkce = true,
    RedeemCode = true, SaveTokens = false,
    SecurityTokenValidator = new StrictJwtSecurityTokenHandler {
        MapInboundClaims = false
    },
    // See Startup.cs for exact token/tenant validation and notifications.
};
app.Use(typeof(MsalOpenIdConnectMiddleware), app, options, msal);`;
  const sourceExcerpt = `protected override async Task<OpenIdConnectMessage>
    RedeemAuthorizationCodeAsync(OpenIdConnectMessage request)
{
    string verifier;
    if (string.IsNullOrWhiteSpace(request.Code) ||
        !request.Parameters.TryGetValue("code_verifier", out verifier) ||
        string.IsNullOrWhiteSpace(verifier))
        throw new InvalidOperationException(
            "The protected PKCE verifier or authorization code is missing.");
    // MSAL adds reserved openid/profile/offline_access scopes.
    var result = await client
        .AcquireTokenByAuthorizationCode(new string[0], request.Code)
        .WithPkceCodeVerifier(verifier).ExecuteAsync().ConfigureAwait(false);
    // Return token response to Katana for normal token + nonce validation.
    return new OpenIdConnectMessage {
        IdToken = result.IdToken, AccessToken = result.AccessToken,
        TokenType = "Bearer",
        ExpiresIn = Math.Max(0, (int)(result.ExpiresOn -
            DateTimeOffset.UtcNow).TotalSeconds)
            .ToString(CultureInfo.InvariantCulture)
    };
}`;
  const sourceMarkup = () => code("OWIN provider (excerpt; see Shared/Startup.cs)", owinExcerpt) + code("MSAL redemption (Shared/MsalOpenIdConnect.cs)", sourceExcerpt) + `<p class="source-note">The override replaces only code redemption. It returns the token response to the base handler instead of handling redemption in an event, preserving Katana's nonce validation. The complete middleware construction and validation are in the source package.</p>`;
  function save() {
    try { localStorage.setItem(storageKey, JSON.stringify(state)); }
    catch (_) { storageAvailable = false; announce("Browser storage unavailable. Progress lasts for this page session only."); }
  }
  let announcementTimer;
  function announce(message) {
    const node = document.getElementById("status-message");
    node.textContent = message;
    clearTimeout(announcementTimer);
    announcementTimer = setTimeout(() => { node.textContent = ""; }, 4500);
  }
  function checkpointMarkup(index, printable = false) {
    return `<div class="checkpoints"><h3>Verify before continuing</h3>${steps[index].checks.map((check, number) => {
      const key = `${index}-${number}`;
      const checked = state.progress[state.app][key] === true;
      return printable ? `<span class="print-check">${checked ? "☑" : "☐"} ${esc(check)}</span>` : `<label><input type="checkbox" data-check="${key}"${checked ? " checked" : ""}> <span>${esc(check)}</span></label>`;
    }).join("")}</div>`;
  }
  function stepMarkup(index, printable = false) {
    const step = steps[index];
    return `<div class="step-heading"><span class="large-number" aria-hidden="true">${String(index + 1).padStart(2, "0")}</span><h2${printable ? "" : ' id="step-title" tabindex="-1"'}>${esc(step.title)}</h2></div><p class="step-intro">${esc(step.intro)}</p>${step.body(state.app, state.values[state.app])}${checkpointMarkup(index, printable)}`;
  }
  function renderProgress() {
    let completed = 0;
    const total = steps.reduce((sum, step) => sum + step.checks.length, 0);
    steps.forEach((step, index) => {
      const complete = step.checks.every((_, number) => state.progress[state.app][`${index}-${number}`] === true);
      completed += step.checks.filter((_, number) => state.progress[state.app][`${index}-${number}`] === true).length;
      const button = document.querySelector(`#step-nav [data-step="${index}"]`);
      button.classList.toggle("complete", complete);
      button.setAttribute("aria-label", `Step ${index + 1}: ${step.short}${complete ? ", checkpoints complete" : ""}`);
      if (currentView === "runbook" && index === state.step) button.setAttribute("aria-current", "step"); else button.removeAttribute("aria-current");
    });
    document.getElementById("progress-count").textContent = `${completed} of ${total} checkpoints`;
    const meter = document.getElementById("progress-meter");
    meter.max = total; meter.value = completed;
  }
  function fillValues() {
    const v = state.values[state.app];
    const form = document.getElementById("values-form");
    fieldNames.forEach(key => { form.elements[key].value = v[key]; });
    document.getElementById("partner-field").hidden = state.app !== "sampleapp02";
    document.getElementById("employee-field").hidden = state.app !== "sampleapp02";
    document.getElementById("employee-domains").required = state.app === "sampleapp02";
    document.getElementById("open-demo").href = v.baseUrl;
    for (const app of appIds) {
      const values = state.values[app];
      if (values.baseUrl === defaultValues(app).baseUrl && location.hostname === "caldova-pocdriver-07279263.azurewebsites.net") continue;
      try {
        const base = new URL(values.baseUrl);
        if (base.protocol !== "https:" || base.username || base.password || base.pathname !== "/" || base.search || base.hash) continue;
        for (const [prefix, path] of [["launch", "/"], ["register", "/Registration/Index"], ["code", "/Home/Code"]]) {
          const link = document.getElementById(`${prefix}-${app}`);
          if (link) link.href = new URL(path, base).href;
        }
      } catch (_) { /* Keep the explicit hosted launch links if setup values are invalid. */ }
    }
    const synthetic = v.workforceTenantId === defaultValues(state.app).workforceTenantId || v.externalTenantId === defaultValues(state.app).externalTenantId;
    document.getElementById("values-summary").textContent = synthetic ? "Synthetic defaults present · edit before setup" : `${state.app} · ${v.baseUrl}`;
    document.getElementById("values-status").textContent = "";
  }
  function render(focus = false, refreshFields = true) {
    document.querySelectorAll(".app-switch [role='tab']").forEach(tab => {
      const selected = tab.dataset.app === state.app;
      tab.setAttribute("aria-selected", String(selected)); tab.tabIndex = selected ? 0 : -1;
    });
    document.getElementById("app-panel").setAttribute("aria-labelledby", `tab-${state.app === "sampleapp01" ? "app01" : "app02"}`);
    ["architecture", "runbook", "code"].forEach(view => {
      document.getElementById(`${view}-view`).hidden = currentView !== view;
      document.getElementById(`${view}-button`).setAttribute("aria-pressed", String(currentView === view));
    });
    if (currentView === "architecture") document.getElementById("architecture-nav").setAttribute("aria-current", "page");
    else document.getElementById("architecture-nav").removeAttribute("aria-current");
    document.querySelector(".skip-link").href = `#${currentTitleId()}`;
    document.getElementById("active-step").innerHTML = stepMarkup(state.step);
    if (state.step === 9) document.querySelector("#active-step .source-excerpt").innerHTML = sourceMarkup();
    document.getElementById("step-select").value = state.step;
    document.getElementById("previous-step").disabled = state.step === 0;
    document.getElementById("next-step").disabled = state.step === steps.length - 1;
    document.getElementById("step-position").textContent = `Step ${state.step + 1} of ${steps.length}`;
    if (refreshFields) fillValues();
    renderProgress();
    if (currentView === "code") renderCodeSamples();
    if (currentView === "architecture") renderArchitecture();
    if (focus) document.getElementById(currentTitleId()).focus();
  }
  function currentTitleId() { return currentView === "architecture" ? "architecture-title" : currentView === "code" ? "code-title" : "step-title"; }
  const architectureChoices = {
    "app01-identities": { title: "Automatic workforce account lookup", text: ["Sampleapp01 queries the exact entered UPN in Caldova through server-side Microsoft Graph. Every workforce UPN domain uses that same lookup and authority; no domain list is maintained. A confirmed empty result selects External ID.", "Lookup errors stop login. A found disabled or unassigned account stays on workforce and cannot bypass its policy through External ID. Signed tenant, object, role and current approval decide admission."], source: "samples/net48/Shared/WorkforceAccountResolver.cs" },
    identities: { title: "A routing hint is not an identity", text: ["Employee domains and explicitly onboarded app02 partner domains select the workforce authority. Other valid domains select External ID. An email address alone never proves organizational membership or application access.", "A workforce error is not retried against External ID. Signed tenant, object, role and application approvals decide admission."], source: "samples/net48/Shared/Policy.cs" },
    workforce: { title: "Caldova is the workforce resource tenant", text: ["Employees authenticate in Caldova. Approved organizational partners authenticate through workforce B2B as resource-tenant guest objects, after home-organization verification.", "Every app binds a tenant-specific authority, client ID, exact discovery issuer and callback. Identity keys use tenant/object IDs rather than email addresses."], source: "samples/net48/Shared/Configuration.cs" },
    partners: { title: "Partner admission is app02-specific", text: ["Partner requires the signed Partner role, a resource-tenant guest identity, a verified home organization and exact signed home-issuer evidence in idp. The app-local record also requires a sponsor, approved status and expiry.", "App01 has no partner route or Partner entitlement. Invitation acceptance is separate from MFA, token redemption and protected application admission."], source: "samples/net48/Shared/Policy.cs" },
    external: { title: "Customer identities use a dedicated external directory", text: ["Retirees, dependents and other approved personal identities belong in External ID. The controlled customer flow serves the separate external registrations; public account creation is disabled in the configured lab flow.", "Customer creation does not prove retirement, employee relationship or benefit eligibility. The signed role and each application's approved record are still required."], source: "samples/net48/Shared/Configuration.cs" },
    applications: { title: "Four demo registrations, with independent app boundaries", text: ["App01 and app02 each have a workforce client and an external client. Each app runs two OWIN OIDC schemes, distinct tenant audiences and /signin-workforce or /signin-external callbacks.", "All four demo clients use authorization code and PKCE; their credentials are separate. The operator driver's separate fifth registration and EasyAuth configuration do not change the demo authentication flow."], source: "samples/net48/Shared/Startup.cs" },
    msal: { title: "MSAL replaces redemption transport only", text: ["OWIN protects state, nonce and the PKCE verifier. Direct MSAL.NET code redemption uses the recovered S256 verifier, the configured client credential and exact redirect URI.", "The redemption override returns the token response to Katana's normal validation pipeline. It does not use HandleCodeRedemption to bypass nonce validation."], source: "samples/net48/Shared/MsalOpenIdConnect.cs" },
    tokens: { title: "Signed tokens and exact tenant validation are mandatory", text: ["StrictJwtSecurityTokenHandler restores mandatory signature and signing-key checks in Katana's code-flow branch. Issuer, audience, lifetime, tenant/object identity and signed role claims are checked.", "Katana retains state and nonce protocol validation. Foreign issuers, wrong audiences, unsigned tokens and expired responses fail without creating an application session."], source: "samples/net48/Shared/StrictJwtSecurityTokenHandler.cs" },
    cookie: { title: "Each app owns its session", text: ["The __Host- application cookie is Secure, HttpOnly and SameSite Lax, scoped to /, with a 20-minute lifetime and no sliding expiration. App01 and app02 use separate cookie names.", "Authentication establishes claims, not automatic Windows impersonation. Downstream Kerberos delegation or Windows-identity requirements need a separate migration decision."], source: "samples/net48/Shared/Startup.cs" },
    governance: { title: "Admission combines signed roles with current business approval", text: ["Every protected request reloads an app-specific record keyed by appId, tenantId and objectId. It requires the correct identity source and signed persona role, approved status, sponsor where required and current expiry.", "Dependent access requires verified relationship and benefit eligibility plus a stable link to one approved, unexpired, benefit-eligible workforce employee in the same app. Local revocation affects the next request; directory unassignment alone may leave an existing app cookie."], source: "samples/net48/Shared/Policy.cs" },
    hosting: { title: "One isolated hosting footprint", text: ["The three sites use Windows App Service B1 in Sweden Central, classic IIS/System.Web and .NET Framework 4.8 in one PoC resource group in Oguzhan. The new external-directory resource belongs to that isolated resource group; Caldova remains the existing workforce directory.", "The B1 plan stays billable until scaled down or removed. The existing .NET 10 sample is not the middleware or hosting model used by these demos."], source: "samples/net48/Directory.Build.props" },
    driver: { title: "The driver has its own authentication boundary", text: ["A separate workforce registration and App Service EasyAuth protect every driver URL, including assets, code catalog, lab manifest and ZIP. The Caldova object-ID allowlist permits the approved admin operator only; application capability roles do not grant driver access.", "Public code pages exist in the two demo applications and show source snapshots only. Every hosted driver page and download requires sign-in; a complete offline copy uses local assets without authentication or network access."], source: "" },
    private: { title: "Private configuration and durable invitation records", text: ["Credentials remain server settings. Configuration stays in IIS-hidden App_Data; invitation and approval records stay outside wwwroot under D:\\home\\data\\multiidp\\<appId>.", "Windows commits use a locked, atomic rename. Failed commits retain a private recovery file. Code samples and downloads exclude credentials and real identity records. Production approval and partner lifecycle need the customer's owned processes."], source: "samples/net48/Shared/Registration.cs" },
    registration: { title: "Implemented: Caldova-only registration capabilities", text: ["Only an approved Caldova workforce Employee can act. App01 allows dependent registration with Employee. App02 additionally requires a signed admin or dependentRegistrant role for dependents, and Employee plus admin for the vendor/partner section.", "Partner and external identities receive no registration capability. The exact role values are lowercase admin and camel-case dependentRegistrant. Server setup is configured; live delivery, customer setup and complete workflow verification remain pending."], source: "samples/net48/Shared/Registration.cs" },
    invitation: { title: "Implemented: server-enforced invitation lifecycle", text: ["An invitation is bound to the authorized actor, target app and exact recipient tenant/object ID, with a sponsor or stable employee link. It expires after at most 24 hours, or earlier at the approval deadline. Its hashed token permits one server-recorded redemption.", "A CSRF-protected confirmation rechecks current sponsor roles and approval before consuming the link and writing approval. Repeated active invitations for the same app/recipient are blocked. New live redemption remains pending."], source: "samples/net48/Shared/Registration.cs" },
    "personal-invitation": { title: "Personal-email verification and password creation", text: ["The ACS invitation opens email verification and password creation in the app. Microsoft verifies the email code and validates the password through its native API. The native continuation token stays in a ten-minute server session; passwords and codes are never persisted.", "The invitation cookie permits registration completion only. Normal access still requires the signed customer role and current app approval; a dependent also needs the same-app eligible employee link. A separate native client performs password setup on the pre-provisioned account through the SSPR protocol. Normal login remains MSAL code + PKCE. Recipient completion and protected admission require a live test."], source: "samples/net48/Shared/RegistrationControllers.cs" },
    "b2b-invitation": { title: "Pending live validation: organizational invitations", text: ["Exact known consumer providers such as gmail.com use External ID. Other-domain discovery gives a candidate home tenant, not account or product-license evidence. App02 Employee plus admin uses one Graph invitation with sendInvitationMessage=false; ACS delivers its bound guest's native inviteRedeemUrl.", "Resource-tenant redemption and app confirmation require signed home-issuer proof, the assigned Partner role and current sponsored approval. Delivery and end-to-end admission remain pending; app01 never admits Partner."], source: "samples/net48/Shared/RegistrationServices.cs" },
    email: { title: "Configured: Azure managed email delivery", text: ["The approved ACS sender supports personal invitations and native organizational B2B URLs. Site managed identities use workforce Graph and ACS; a separate external provisioner creates customers and assigns their persona roles. Interactive OIDC clients retain sign-in scopes.", "Credentials, configuration and recipient records stay server-side. Queued/sent/pending/failed email status does not grant approval. Confirm actual receipt, account setup and redemption before marking the workflow complete."], source: "samples/net48/Shared/RegistrationServices.cs" }
  };
  function currentArchitectureChoice() { return architectureChoices[architectureChoice === "identities" && state.app === "sampleapp01" ? "app01-identities" : architectureChoice]; }
  function renderArchitecture() {
    document.querySelectorAll(".architecture-tabs [role='tab']").forEach(tab => {
      const selected = tab.dataset.flow === architectureFlow;
      tab.setAttribute("aria-selected", String(selected)); tab.tabIndex = selected ? 0 : -1;
    });
    document.getElementById("architecture-signin").hidden = architectureFlow !== "signin";
    document.getElementById("architecture-registration").hidden = architectureFlow !== "registration";
    document.querySelectorAll("[data-choice]").forEach(node => node.setAttribute("aria-pressed", String(node.dataset.choice === architectureChoice)));
    const choice = currentArchitectureChoice();
    document.getElementById("architecture-choice-title").textContent = choice.title;
    document.getElementById("architecture-choice-body").replaceChildren(...choice.text.map(text => {
      const paragraph = document.createElement("p"); paragraph.textContent = text; return paragraph;
    }));
    const sourceButton = document.getElementById("architecture-choice-source");
    sourceButton.hidden = !choice.source;
    sourceButton.disabled = !codeFilesForApp().some(file => file.path === choice.source);
    sourceButton.textContent = sourceButton.disabled ? "Source not yet packaged" : `Read ${choice.source.replace(/^samples\/net48\//, "")}`;
  }
  function selectArchitectureFlow(flow, focusTab = false) {
    architectureFlow = flow; architectureChoice = flow === "signin" ? "applications" : "registration"; renderArchitecture();
    if (focusTab) document.querySelector(`[data-flow="${flow}"]`).focus();
  }
  document.getElementById("architecture-view").addEventListener("click", event => {
    const node = event.target.closest("[data-choice]");
    if (node) { architectureChoice = node.dataset.choice; renderArchitecture(); }
    const tab = event.target.closest("[data-flow]");
    if (tab) selectArchitectureFlow(tab.dataset.flow);
  });
  document.querySelector(".architecture-tabs").addEventListener("keydown", event => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault(); selectArchitectureFlow(event.key === "Home" ? "signin" : event.key === "End" ? "registration" : architectureFlow === "signin" ? "registration" : "signin", true);
  });
  document.getElementById("architecture-choice-source").addEventListener("click", () => {
    selectedCodeFiles[state.app] = currentArchitectureChoice().source; selectView("code");
  });
  function updateRailHeight() {
    document.documentElement.style.setProperty("--header-height", `${document.querySelector(".site-header").getBoundingClientRect().height}px`);
  }
  if (window.ResizeObserver) new ResizeObserver(updateRailHeight).observe(document.querySelector(".site-header"));
  window.addEventListener("resize", updateRailHeight); updateRailHeight();
  function codeFilesForApp() {
    const catalog = window.pocCodeSamples;
    if (!Array.isArray(catalog?.files) || !Array.isArray(catalog.apps?.[state.app])) return [];
    const files = new Map(catalog.files.filter(file => file && typeof file.path === "string" && typeof file.content === "string").map(file => [file.path, file]));
    return [...new Set(catalog.apps[state.app])].map(path => files.get(path)).filter(Boolean);
  }
  function renderSelectedCode() {
    const path = document.getElementById("code-file").value;
    const file = codeFilesForApp().find(candidate => candidate.path === path);
    if (!file) return;
    selectedCodeFiles[state.app] = path;
    document.getElementById("code-path").textContent = file.path;
    document.getElementById("code-purpose").textContent = typeof file.description === "string" ? file.description : typeof file.title === "string" ? file.title : "Application source file.";
    document.getElementById("code-language").textContent = typeof file.language === "string" ? file.language : "Source";
    document.getElementById("code-content").textContent = file.content;
    const pre = document.querySelector("#code-reader pre");
    pre.setAttribute("aria-label", `Source code: ${file.path}`);
    pre.scrollTop = 0; pre.scrollLeft = 0;
    document.getElementById("copy-source").setAttribute("aria-label", `Copy file ${file.path}`);
  }
  function renderCodeSamples() {
    const files = codeFilesForApp();
    document.getElementById("code-title").textContent = `Code samples: ${state.app === "sampleapp01" ? "Sampleapp01" : "Sampleapp02"}`;
    document.getElementById("code-unavailable").hidden = files.length > 0;
    document.getElementById("code-reader").hidden = files.length === 0;
    const select = document.getElementById("code-file");
    select.replaceChildren(...files.map(file => {
      const option = document.createElement("option");
      option.value = file.path;
      option.textContent = file.path.replace(/^samples\/net48\//, "");
      return option;
    }));
    select.value = files.some(file => file.path === selectedCodeFiles[state.app]) ? selectedCodeFiles[state.app] : files[0]?.path || "";
    if (files.length) renderSelectedCode();
    else document.getElementById("code-content").textContent = "";
    renderCodeJourney();
  }
  const codeJourneys = [
    { id: "dependent", title: "Employee invites a dependent", summary: "App01: approved Caldova employee. App02: approved Caldova employee with admin or dependentRegistrant.", steps: [
      ["RegistrationPolicy.Authorize checks Employee, app approval and the required registration capability. CurrentSponsorRolesAsync rechecks enabled Caldova membership and current app roles.", "Registration.cs"],
      ["InviteAsync validates the personal address and relationship, creates a hashed 24-hour invitation, provisions or reuses the External ID customer, assigns Dependent and binds tenant/object IDs.", "RegistrationServices.cs"],
      ["ACS sends the link. Accept displays Verify email and create password. StartPasswordSetup rechecks the sponsor and bound account before requesting Microsoft's email code.", "PasswordSetupController.cs"],
      ["Microsoft verifies the code, accepts the recipient's password and confirms completion. No password is saved or emailed. Continue to sign in starts the normal External ID code flow.", "PasswordSetup.cs"],
      ["If the recipient signs in from Home before confirming, Validate resumes their unique sent, current invitation using exact signed tenant/object, issuer, audience and Dependent role. It issues a registration-only cookie and opens Confirm registration.", "RegistrationControllers.cs"],
      ["The registration cookie permits confirmation only. Confirm rechecks the sponsor, consumes the link and records the employee relationship and expiry. Fresh sign-in is required for benefits.", "RegistrationControllers.cs"]
    ] },
    { id: "vendor", app: "sampleapp02", title: "Admin invites a vendor or business partner", summary: "Only an enabled Caldova Member with Employee + admin and current Sampleapp02 approval can invite a business user.", steps: [
      ["InviteAsync discovers the organization from the email domain. Personal domains such as hotmail.com and gmail.com select External ID. Discovery alone is not proof of the user's organization.", "RegistrationServices.cs"],
      ["Organizational user: Graph /invitations creates or reuses the workforce B2B guest; Partner is assigned. ACS delivers Microsoft's native inviteRedeemUrl. Personal user: an External ID customer receives External and an account-bound setup link.", "RegistrationServices.cs"],
      ["Personal recipient: verify email and create a password. Organizational recipient: redeem B2B using the existing work account and its organization's authentication requirements.", "PasswordSetupController.cs"],
      ["MatchesBoundIdentity validates the signed home issuer for partners plus expected tenant, object, audience and persona. Confirm commits app approval only after these checks.", "RegistrationControllers.cs"]
    ] },
    { id: "workforce", app: "sampleapp01", title: "Caldova employee login", summary: "Sampleapp01 automatically looks up the workforce UPN across all tenant domains before sign-in.", steps: [
      ["AccountController.Login awaits RegistrationRuntime.RouteAsync. The server's managed identity queries the exact UPN in workforce Graph using User.Read.All; no employee-domain list is used.", "WorkforceAccountResolver.cs"],
      ["A matching account selects workforce. Only a successful empty result selects External ID. Permission, service, timeout or malformed-response failures stop routing with HTTP 503.", "WorkforceAccountResolver.cs"],
      ["Startup registers one workforce authority, client and callback for all workforce UPN suffixes. Katana handles nonce, state and PKCE; MSAL redeems the code.", "Startup.cs"],
      ["AdmissionPolicy requires the signed Employee role and a current approval for this app + tenant + object. A disabled or unassigned workforce account cannot switch realms to gain access.", "Policy.cs"]
    ] },
    { id: "workforce", app: "sampleapp02", title: "Caldova employee login", summary: "Workforce tenant authenticates the employee; the application separately decides access.", steps: [
      ["IdentityRouter selects workforce for the configured Caldova employee domain. The server starts the workforce challenge.", "Controllers.cs"],
      ["Startup registers the tenant-specific authority, app registration and redirect URI. Katana handles nonce, state and PKCE; MSAL redeems the authorization code.", "Startup.cs"],
      ["RedeemAuthorizationCodeAsync sends the protected code verifier to MSAL. The returned ID token passes signature, issuer, audience and lifetime validation.", "MsalOpenIdConnect.cs"],
      ["AdmissionPolicy requires the signed Employee role and an approved, unexpired record for this app + tenant + object. Registration capabilities are separate admin/dependentRegistrant checks.", "Policy.cs"]
    ] },
    { id: "partner", app: "sampleapp02", title: "Microsoft 365 partner login through B2B", summary: "Authentication uses the partner's home tenant. Sampleapp02 trusts the Caldova workforce token for its approved B2B guest.", steps: [
      ["Approved partner domains route to workforce. A failed workforce sign-in is not retried against External ID.", "Policy.cs"],
      ["The workforce OIDC authority performs B2B federation. MSAL redeems the code for the Sampleapp02 workforce registration.", "Startup.cs"],
      ["Signed Partner, Caldova guest object ID, home-tenant idp issuer, current app approval and verified organization evidence must agree. Consumer identities cannot satisfy the partner issuer check.", "Policy.cs"]
    ] },
    { id: "external", title: "Retiree, dependent or personal vendor login", summary: "External ID uses its own client, CIAM authority and callback. Roles and approvals remain application-specific.", steps: [
      ["Personal email selects external. An invitation supplies the exact bound identity during registration; the email string never grants access.", "RegistrationServices.cs"],
      ["MSAL code + PKCE sign-in uses the External ID registration. Token validation accepts only its exact CIAM issuer, tenant and client audience.", "Startup.cs"],
      ["AdmissionPolicy requires Retiree, Dependent or External plus a current app approval. Dependents also require a verified relationship and an eligible employee in the same app.", "Policy.cs"],
      ["Before approval, a unique sent invitation for that exact signed identity resumes Confirm registration. The protected cookie carries only registration permission. Confirmation rechecks the sponsor and consumes the invitation once; then sign in again.", "RegistrationControllers.cs"],
      ["A registration-only cookie cannot access benefits, even before a fresh login after confirmation. Each protected request reloads governance records so local revocation takes effect.", "RegistrationControllers.cs"]
    ] },
    { id: "password", title: "Invitation → verify email → create password", summary: "A separate native-authentication client performs account setup. On the pre-provisioned account this uses Microsoft's SSPR protocol directly; the user does not navigate a Forgot password link. MSAL remains the login implementation.", steps: [
      ["Accept shows the setup button. StartPasswordSetup validates the expiring invitation, current sponsor and exact Graph email identity; it reserves a five-minute verification-email cooldown.", "PasswordSetupController.cs"],
      ["POST resetpassword/v1.0/start and /challenge. The native client is associated with the controlled EmailPassword flow. Public signup stays disabled.", "PasswordSetup.cs"],
      ["POST /continue with the recipient's code. Only a verified server-side session can render and submit the password form. Every mutation requires an anti-forgery token.", "PasswordSetupController.cs"],
      ["POST /submit with new_password, then /poll_completion. Only succeeded displays completion. Passwords and codes are never persisted; native tokens never become app sign-in tokens.", "PasswordSetup.cs"],
      ["Begin returns to normal OIDC code + PKCE; Confirm records the app approval only after the signed identity and sponsor checks pass.", "RegistrationControllers.cs"]
    ] }
  ];
  function renderCodeJourney() {
    const select = document.getElementById("code-journey");
    const current = select.value;
    const available = codeJourneys.filter(j => !j.app || j.app === state.app);
    select.replaceChildren(...available.map(j => { const o = document.createElement("option"); o.value = j.id; o.textContent = j.title; return o; }));
    select.value = available.some(j => j.id === current) ? current : available[0].id;
    const journey = available.find(j => j.id === select.value);
    document.getElementById("code-journey-summary").textContent = journey.summary;
    document.getElementById("code-journey-steps").replaceChildren(...journey.steps.map(([text, source]) => {
      const li = document.createElement("li"); const p = document.createElement("p"); p.textContent = text;
      const button = document.createElement("button"); button.type = "button"; button.className = "secondary"; button.textContent = `Read ${source}`;
      button.addEventListener("click", () => { document.getElementById("code-file").value = `samples/net48/Shared/${source}`; renderSelectedCode(); document.getElementById("code-path").scrollIntoView({ block: "start" }); });
      li.append(p, button); return li;
    }));
  }
  document.getElementById("code-journey").addEventListener("change", renderCodeJourney);
  function updateViewHash() {
    const hash = currentView === "architecture" ? "#architecture" : `#${currentView}/${state.app}`;
    if (location.hash !== hash) location.hash = hash;
  }
  function selectView(view) {
    currentView = view; render(true, false); updateViewHash();
  }
  function applyHashRoute(initial = false) {
    const route = location.hash.match(/^#(code|runbook)\/(sampleapp01|sampleapp02)(?:\/([^/]+))?$/);
    if (!route && location.hash && location.hash !== "#architecture") return false;
    let file = "";
    if (route?.[3]) {
      if (route[1] !== "code") return false;
      try { file = decodeURIComponent(route[3]); } catch (_) { return false; }
      if (!window.pocCodeSamples?.apps?.[route[2]]?.includes(file)) return false;
    }
    const app = route ? route[2] : state.app;
    const view = route ? route[1] : "architecture";
    const changed = app !== state.app || view !== currentView || Boolean(file && file !== selectedCodeFiles[app]);
    if (file) selectedCodeFiles[app] = file;
    state.app = app; currentView = view;
    if (changed) save();
    if (changed || initial) render(!initial);
    return true;
  }
  function selectStep(index) {
    const viewChanged = currentView !== "runbook";
    state.step = index; currentView = "runbook"; save(); render(true, false);
    if (viewChanged) updateViewHash();
  }
  document.getElementById("architecture-button").addEventListener("click", () => selectView("architecture"));
  document.getElementById("architecture-nav").addEventListener("click", () => selectView("architecture"));
  document.getElementById("runbook-button").addEventListener("click", () => selectView("runbook"));
  document.getElementById("architecture-runbook").addEventListener("click", () => selectView("runbook"));
  document.getElementById("architecture-code").addEventListener("click", () => selectView("code"));
  document.getElementById("code-button").addEventListener("click", () => selectView("code"));
  document.getElementById("back-runbook").addEventListener("click", () => selectView("runbook"));
  document.getElementById("code-file").addEventListener("change", renderSelectedCode);
  document.querySelector(".skip-link").addEventListener("click", event => {
    event.preventDefault(); document.getElementById(currentTitleId()).focus();
  });
  window.addEventListener("hashchange", () => applyHashRoute());
  document.getElementById("step-nav").innerHTML = steps.map((step, index) => `<li><button type="button" data-step="${index}"><span class="step-number" aria-hidden="true">${String(index + 1).padStart(2, "0")}</span><span>${esc(step.short)}</span></button></li>`).join("");
  document.getElementById("step-select").innerHTML = steps.map((step, index) => `<option value="${index}">${index + 1}. ${esc(step.short)}</option>`).join("");
  document.getElementById("step-nav").addEventListener("click", event => { const button = event.target.closest("[data-step]"); if (button) selectStep(Number(button.dataset.step)); });
  document.getElementById("step-select").addEventListener("change", event => selectStep(Number(event.target.value)));
  document.getElementById("previous-step").addEventListener("click", () => selectStep(Math.max(0, state.step - 1)));
  document.getElementById("next-step").addEventListener("click", () => selectStep(Math.min(steps.length - 1, state.step + 1)));
  function selectApp(app, focusTab = false) {
    state.app = app; save(); render();
    updateViewHash();
    if (focusTab) document.querySelector(`[data-app="${app}"]`).focus();
  }
  document.querySelector(".app-switch").addEventListener("click", event => { const tab = event.target.closest("[data-app]"); if (tab) selectApp(tab.dataset.app); });
  document.querySelector(".app-switch").addEventListener("keydown", event => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    selectApp(event.key === "Home" ? appIds[0] : event.key === "End" ? appIds[1] : appIds[state.app === appIds[0] ? 1 : 0], true);
  });
  document.getElementById("active-step").addEventListener("change", event => {
    if (!event.target.matches("[data-check]")) return;
    const key = event.target.dataset.check;
    if (event.target.checked) state.progress[state.app][key] = true; else delete state.progress[state.app][key];
    save(); renderProgress();
  });
  document.getElementById("reset-progress").addEventListener("click", () => { state.progress[state.app] = {}; save(); render(false, false); announce(`${state.app} progress reset. Application values retained.`); });
  function validateValues(v, app = state.app) {
    let error = "";
    const guid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (["workforceTenantId", "workforceClientId", "externalTenantId", "externalClientId"].some(key => !guid.test(v[key]))) error = "Use GUIDs for both tenant IDs and both client IDs.";
    if (!error) {
      for (const key of ["baseUrl", "workforceIssuer", "externalIssuer"]) {
        try { const u = new URL(v[key]); if (u.protocol !== "https:" || u.username || u.password || u.search || u.hash || (key === "baseUrl" && u.pathname !== "/")) throw new Error(); }
        catch (_) { error = "Use absolute HTTPS URLs without credentials, query strings or fragments."; break; }
      }
    }
    v.baseUrl = v.baseUrl.replace(/\/+$/, "");
    v.ciamDomain = v.ciamDomain.toLowerCase();
    if (!error && !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.ciamlogin\.com$/.test(v.ciamDomain)) error = "Use the actual CIAM hostname, without https:// or a path.";
    const domainPattern = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/;
    if (!error && app === "sampleapp02" && [...domains(v.employeeDomains), ...domains(v.approvedPartnerDomains)].some(domain => !domainPattern.test(domain))) error = "Use comma-separated domains without email addresses, wildcards or URLs.";
    if (!error && app === "sampleapp02" && domains(v.employeeDomains).length === 0) error = "Provide at least one employee routing domain.";
    if (!error && v.workforceTenantId.toLowerCase() === v.externalTenantId.toLowerCase()) error = "Workforce and External ID must be separate tenant IDs.";
    if (!error && v.workforceClientId.toLowerCase() === v.externalClientId.toLowerCase()) error = "Workforce and External ID must use separate client IDs.";
    if (!error) {
      for (const source of ["workforce", "external"]) {
        const issuer = new URL(v[`${source}Issuer`]);
        const tid = v[`${source}TenantId`].toLowerCase();
        if (issuer.pathname !== `/${tid}/v2.0` || (source === "workforce" && issuer.hostname !== "login.microsoftonline.com") || (source === "external" && ![v.ciamDomain, `${tid}.ciamlogin.com`].includes(issuer.hostname))) {
          error = "Use the exact tenant-specific v2.0 discovery issuer; check tenant IDs and issuer hostnames."; break;
        }
      }
    }
    return error;
  }
  document.getElementById("values-form").addEventListener("submit", event => {
    event.preventDefault();
    const form = event.target;
    const v = Object.fromEntries(fieldNames.map(key => [key, form.elements[key].value.trim()]));
    const status = document.getElementById("values-status");
    const error = validateValues(v);
    status.dataset.error = String(Boolean(error));
    if (error) { status.textContent = error; return; }
    v.employeeDomains = state.app === "sampleapp01" ? "" : domains(v.employeeDomains).join(", ");
    v.approvedPartnerDomains = state.app === "sampleapp02" ? domains(v.approvedPartnerDomains).join(", ") : "";
    state.values[state.app] = v;
    state.progress[state.app] = {};
    save(); render();
    status.textContent = storageAvailable ? "Saved locally. Reverify checkpoints after configuration changes." : "Updated for this session. Browser storage unavailable.";
    status.dataset.error = "false";
  });
  const hasSyntheticValues = () => appIds.every(app => fieldNames.every(key => state.values[app][key] === defaultValues(app)[key]));
  async function loadLab(automatic = false) {
    const button = document.getElementById("load-lab");
    button.disabled = true;
    try {
      const response = await fetch("./lab-settings.json", { cache: "no-store", credentials: "same-origin", redirect: "error" });
      if (!response.ok) throw new Error("No hosted lab manifest is available here. Enter the values manually.");
      const manifest = await response.json();
      const values = {};
      for (const app of appIds) {
        const source = manifest.apps?.[app];
        if (!source || typeof source !== "object") throw new Error("Lab manifest is incomplete. Enter the values manually.");
        values[app] = Object.fromEntries(fieldNames.map(key => [key, Array.isArray(source[key]) ? source[key].join(", ") : typeof source[key] === "string" ? source[key].trim() : ""]));
        const error = validateValues(values[app], app);
        if (error) throw new Error(`Lab values for ${app}: ${error}`);
        values[app].employeeDomains = app === "sampleapp01" ? "" : domains(values[app].employeeDomains).join(", ");
        values[app].approvedPartnerDomains = app === "sampleapp02" ? domains(values[app].approvedPartnerDomains).join(", ") : "";
      }
      if (automatic && !hasSyntheticValues()) return;
      state.values = values;
      if (!automatic) state.progress = { sampleapp01: {}, sampleapp02: {} };
      save(); render();
      if (!automatic) announce("Loaded both apps' non-secret lab values. Reverify all checkpoints.");
    } catch (error) { if (!automatic) announce(error.message?.startsWith("Lab") || error.message?.startsWith("No hosted") ? error.message : "Lab setup is unavailable offline. Enter the values manually."); }
    finally { button.disabled = false; }
  }
  document.getElementById("load-lab").addEventListener("click", () => loadLab());
  document.addEventListener("click", async event => {
    const button = event.target.closest(".copy-button");
    if (!button) return;
    const value = button.closest(".code-block").querySelector("pre code").textContent;
    try {
      if (navigator.clipboard?.writeText && window.isSecureContext) await navigator.clipboard.writeText(value);
      else {
        const input = document.createElement("textarea"); input.value = value; input.style.position = "fixed"; input.style.opacity = "0"; document.body.appendChild(input); input.select();
        const copied = document.execCommand("copy"); input.remove(); button.focus(); if (!copied) throw new Error();
      }
      announce("Copied to clipboard.");
    } catch (_) { announce("Clipboard unavailable. Select the snippet and copy it manually."); }
  });
  function preparePrint() {
    const v = state.values[state.app];
    const labels = { baseUrl: "HTTPS base URL", workforceTenantId: "Workforce tenant ID", workforceClientId: "Workforce client ID", workforceIssuer: "Workforce expected issuer", employeeDomains: "Employee routing domains", approvedPartnerDomains: "Approved partner routing domains", externalTenantId: "External tenant ID", externalClientId: "External client ID", ciamDomain: "CIAM hostname", externalIssuer: "External expected issuer" };
    document.getElementById("print-runbook").innerHTML = `<h2 style="margin-top:8mm">${esc(state.app)} runbook</h2><p>Checkboxes reflect locally recorded verification, not automated tenant validation.</p><dl class="print-config">${fieldNames.filter(key => !["employeeDomains", "approvedPartnerDomains"].includes(key) || state.app === "sampleapp02").map(key => `<dt>${esc(labels[key])}</dt><dd>${esc(v[key])}</dd>`).join("")}</dl>${steps.map((_, index) => `<article>${stepMarkup(index, true)}</article>`).join("")}`;
    document.querySelector("#print-runbook .source-excerpt").innerHTML = sourceMarkup();
  }
  document.getElementById("print-button").addEventListener("click", () => { preparePrint(); window.print(); });
  window.addEventListener("beforeprint", preparePrint);
  if (!applyHashRoute(true)) render();
  if (location.protocol === "https:" && hasSyntheticValues()) loadLab(true);
  if (!storageAvailable) announce("Browser storage unavailable. Values and progress last for this page session only.");
})();
