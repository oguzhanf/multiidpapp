# Classic ASP.NET identity PoC scripts

After configuring sponsored registration, run `Configure-PocPasswordSetup.ps1 -TenantId <external-tenant-id>` and deploy both apps. The script adds a separate native account-setup registration with no API permissions to the controlled EmailPassword flow. It persists `external.passwordSetupClientId` in both private registration configs. Existing invitation links then open email verification and password creation directly. See [the registration flow](../../docs/poc/REGISTRATION.md) and the driver **Code samples → Follow an interaction**.

Run these scripts from Windows PowerShell with the expected tenant administrator signed in through Azure CLI. Set `$env:AZURE_CONFIG_DIR` to the isolated CLI profile you intend to use (for this PoC, `$env:LOCALAPPDATA\MultiIdpPoC\AzureCli`). Each Graph script checks the requested tenant, delegated user identity and active administrator role before mutation. Azure CLI tokens and password responses are never printed.

The default state folder is `$env:LOCALAPPDATA\MultiIdpPoC`, outside the repository. Its DACL grants the current Windows user access. Seven-day application secrets are exported as DPAPI CurrentUser SecureStrings; a rerun reuses the saved credential and refuses missing, expired or mismatched credential state. Copying these files to another Windows identity does not make the secrets usable.

| Script | Purpose |
|---|---|
| [Initialize-PocInfrastructure.ps1](Initialize-PocInfrastructure.ps1) | Create the isolated Azure resource group, external tenant and Windows hosting. |
| [Configure-PocApplications.ps1](Configure-PocApplications.ps1) | Create/reconcile the two tagged single-tenant registrations in one directory, their service principals, baseline OIDC consent and seven-day secrets. Run once for Workforce and once for External. |
| [Configure-PocExternalFlow.ps1](Configure-PocExternalFlow.ps1) | Associate the two external registrations with a controlled email/password sign-in flow and verify new sign-up is disabled. |
| [Configure-PocRegistration.ps1](Configure-PocRegistration.ps1) | Prepare owned ACS email resources, sample-site managed identities, separate customer provisioner, private registration configuration and explicitly selected employee capabilities. Does not send mail or deploy content. |
| [Secure-PocDriver.ps1](Secure-PocDriver.ps1) | Require workforce authentication on all driver paths and allow only the explicitly supplied enabled Member. Uses documented Easy Auth hybrid sign-in. |
| [New-PocTestUsers.ps1](New-PocTestUsers.ps1) | Provision explicitly selected synthetic PoC accounts. Review its parameters before use. |
| [Add-PocAssignment.ps1](Add-PocAssignment.ps1) | Assign an existing explicit user object to a persona role and save its approved, expiring business entitlement. Creates no users. |
| [Export-PocConfiguration.ps1](Export-PocConfiguration.ps1) | Merge tenant manifests into the two application configuration files, retaining exact live discovery issuers. |
| [Start-PocLocal.ps1](Start-PocLocal.ps1) | Load protected credentials into process environment and start installed Microsoft IIS Express hidden, using a supplied HTTPS configuration. |
| [Deploy-PocSites.ps1](Deploy-PocSites.ps1) | Stage the classic System.Web applications and deploy the Windows web apps. |
| [Test-PocScripts.ps1](Test-PocScripts.ps1) | Exercise app/credential reruns, ownership, roles, callbacks, JSON arrays and entitlement checks with a mocked directory. Makes no network calls or tenant mutations. |

Configure each directory with the actual cloud roots:

```powershell
.\scripts\poc\Configure-PocApplications.ps1 -TenantId '<tenant-guid>' `
  -TenantKind Workforce -App01BaseUrl 'https://app01.azurewebsites.net' `
  -App02BaseUrl 'https://app02.azurewebsites.net'
# Repeat with -TenantKind External -CiamDomain '<subdomain>.ciamlogin.com'.
```

The sample registrations use distinct `/signin-workforce` and `/signin-external` callbacks. Local roots default to `https://localhost:44371` and `https://localhost:44372`. Their implicit access-token/ID-token issuance is disabled. Only delegated `openid`, `profile`, `email` and `offline_access` consent is granted; these four interactive clients have no Graph application privileges. Workforce ID tokens request the signed `idp` claim for partner checks. App01 Workforce exposes `Employee`; app02 also exposes `Partner`, `admin` and `dependentRegistrant`. Both External registrations expose `Retiree`, `Dependent` and `External`. The separate driver uses Easy Auth's documented confidential hybrid flow with ID-token issuance enabled, access-token issuance disabled, a server-side client secret and an explicit operator OID gate.

Export requires at least one approved employee domain. Domains are explicit routing hints, without wildcards; they do not establish account existence or authorization. App01 never exports partner domains. Configuration files contain secret environment variable names, not values. The applications read `MULTIIDP_SAMPLEAPP01_CONFIG` and `MULTIIDP_SAMPLEAPP02_CONFIG` as absolute JSON paths, and use the corresponding four `MULTIIDP_SAMPLEAPP0[12]_(WORKFORCE|EXTERNAL)_SECRET` process settings.

```powershell
.\scripts\poc\Export-PocConfiguration.ps1 -WorkforceTenantId '<guid>' `
  -ExternalTenantId '<guid>' -EmployeeDomains @('approved.example') -Local
```

Assign employees with `-BenefitEligible` when they can sponsor a dependent. Dependent assignment requires `-RelationshipVerified -BenefitEligible`, an accountable `-Sponsor`, and stable `-LinkedEmployeeTenantId`/`-LinkedEmployeeObjectId` matching a unique approved, unexpired, benefit-eligible employee entitlement for the same app. Partners require a Workforce B2B guest, app02, a sponsor, approved home tenant and a completed organization-verification timestamp. Retiree and External personas use External ID and require a sponsor. Every persona requires `-ExpiresUtc`; no email address is used as an entitlement key.

Changing the entitlement's status or expiry affects admission on the next application request because the app reloads it. For Azure hosting, redeploy the updated entitlement data or update the deployed data file; changing only the local copy does not update the cloud. Directory unassignment alone does not invalidate an existing app cookie.

Classic System.Web builds use `dotnet build`, then package the project root's `web.config`, `Global.asax` and complete `bin` output. `dotnet publish` is not the packaging path. Local startup requires installed IIS Express, configured HTTPS bindings/certificates and the same current Windows user; it does not configure full IIS worker-process identities.

`Deploy-PocSites.ps1` deploys both applications and the driver by default. Add `-ApplicationIds sampleapp02` to deploy only app02 plus the driver; the hosted manifest and downloadable source still include both apps. `-DriverOnly` updates only the driver, non-secret manifest and source archive without rebuilding or deploying either application.

Registration setup takes explicit subscription and tenant IDs, a resource name suffix, and an optional approved operator OID. `-AllowedOperatorObjectId` grants `admin` and `dependentRegistrant` only to an already approved app02 workforce Employee who is an enabled Member. `-DependentRegistrantObjectIds` grants only the latter capability to explicitly selected approved employees. Guests never receive these capabilities. Existing `Employee`/`Partner` role IDs are preserved. The script uses the earliest current local approval expiry as its conservative deadline unless `-ApprovalLimitUtc` is supplied explicitly.

Both sample-site identities receive workforce Graph `Application.Read.All` and `User.Read.All`; app02 also receives `AppRoleAssignment.ReadWrite.All` and `User.Invite.All`. Sponsor roles are read from the app's service-principal assignments and matched to the sponsor locally. The separate External provisioner receives `User.ReadWrite.All`, `Application.Read.All` and `AppRoleAssignment.ReadWrite.All`. The ACS custom role contains only `Microsoft.Communication/CommunicationServices/read` and `/write`, assigned at the dedicated communication resource to these two sample identities. Azure-managed email limits are 5 sends/minute and 10/hour per subscription; status checks are 10/minute and 20/hour. [Microsoft mail limits](https://learn.microsoft.com/en-us/azure/communication-services/concepts/service-limits#rate-limits-for-email).

Private per-app `sampleapp01.registration.json` / `sampleapp02.registration.json` files contain target tenant/SP/role IDs, mail endpoint/sender, deadline, secret environment variable name and the protected state path. Hosting uses `MULTIIDP_SAMPLEAPP01_REGISTRATION_CONFIG` / `MULTIIDP_SAMPLEAPP02_REGISTRATION_CONFIG` pointing to `App_Data\registration.json`. Deployment must preserve existing `App_Data\registration-state.json`. Registration passwords, tokens and recipient email addresses do not belong in source or the downloadable archive.

For first-time customer setup, provision a unique unknown random password and send only the account invitation link. The customer chooses **Forgot password**, verifies an email code and sets their own password. The controlled flow retains email/password sign-in and disabled sign-up. Setup verifies the new External tenant's Email OTP policy; `-EnableExternalEmailPasswordReset` explicitly enables its all-users reset coverage while preserving other methods. An operator must separately verify the company-branding password-reset link is visible. [Microsoft customer reset instructions](https://learn.microsoft.com/en-us/entra/external-id/customers/how-to-enable-password-reset-customers).

Azure CLI's delegated Graph token may lack the authentication-method policy scope. For policy setup, use the installed `Microsoft.Graph.Authentication` module in the same PowerShell process: `Connect-MgGraph -TenantId <external-tenant-id> -Scopes Policy.ReadWrite.AuthenticationMethod,User.Read -ContextScope Process -NoWelcome`, then run the registration script with `-UseMicrosoftGraphPolicyContext`. Complete Microsoft's delegated operator sign-in and consent first. The script requires the exact External tenant, the same setup administrator object ID, a delegated process session and the policy scope; only Email OTP policy requests use this client. All other setup requests retain the isolated Azure CLI context. No runtime app receives authentication-policy permissions. [Microsoft policy API permissions](https://learn.microsoft.com/en-us/graph/api/emailauthenticationmethodconfiguration-update?view=graph-rest-1.0), [Microsoft Graph PowerShell sign-in](https://learn.microsoft.com/en-us/powershell/microsoftgraph/authentication-commands).

External tenants support customer app roles and assignments. Full Microsoft Entra ID Governance is unavailable there. Inviting external tenant guests serves administration and is incompatible with customer user flows; customer accounts use local provisioning or supported federation. [Current Microsoft feature matrix](https://learn.microsoft.com/en-us/entra/external-id/customers/concept-supported-features-customers).
