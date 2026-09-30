# Prerequisites and deployment

This guide deploys one generic app against a Workforce tenant and a separate External ID external tenant. Supply your own values. No deployed environment or working credential is included.

Commands use Windows PowerShell 7. Replace all `<PLACEHOLDERS>` before executing a command. Do not put passwords, secret values, tokens, account screenshots, or real tenant/resource inventories into source control.

## 1. Readiness checklist

| Requirement | Owner / evidence |
|---|---|
| Workforce tenant and approved hosting subscription/RG/region/budget | Identity and Azure platform owners. Azure resource permissions do not grant directory administrator roles. |
| External tenant, region/domain choice, billing linkage or approved trial | Tenant-creation owner; external country/region cannot be changed after creation. |
| Application management and admin consent in both tenants | Approved application administrator and consent operator; external customers cannot grant app consent themselves. |
| External customer-account administration | User Administrator in the external tenant. Do not assign directory admin roles to customer test identities. |
| External flow administration | External ID User Flow Administrator and approved Graph permissions for controlled sign-up configuration. |
| MFA policy | Security Administrator, agreed methods/scope/recovery, and SMS cost approval if selected. |
| Deployment tooling | .NET 10 SDK, public NuGet access, Azure CLI, PowerShell 7, and approved SCM deployment access. |
| Credentials | Separate app credentials and expiry owners; secure development input and an approved cloud secret store. |
| Vault permissions | Human secret operator needs approved secret-write data-plane rights; app managed identity needs secret-read rights. Contributor alone is not Key Vault data-plane permission. |
| Network | Browser access to HTTPS portal/sign-in; app access to discovery/JWKS/token endpoints and vault; administrator access to Graph; build/deploy package and SCM connectivity. |
| Proxy boundary | Actual TLS-terminating proxy IPs/CIDRs approved by the platform owner; do not enable trust-all forwarding. |
| Test scope | Assigned/unassigned non-admin workforce and external accounts, a real external mailbox, allowed Workforce email domains, synthetic data, and an agreed POC teardown date. |

### Tenant creation and role scope

1. In the Entra admin center, start in Workforce and open tenant management > Create.
2. Choose tenant type **External**, not a second Workforce tenant or a Workforce B2B invitation.
3. Select the approved subscription/resource group, or an eligible 30-day trial with a recorded end date.
4. Choose the tenant name, unique domain prefix, and approved country/region.
5. Create and switch to that external directory; record its tenant ID and domain prefix internally.
6. Verify billing linkage/trial ownership and provision dedicated MFA-protected administrative access.

Subscription-backed creation requires the documented Tenant Creator role scoped to the selected subscription/resource group. Application administration in external tenants uses the supported Cloud Application Administrator role. Use separate named administrators or scoped roles as appropriate; do not grant Global Administrator to every POC operator.

The web host stays in a Workforce-owned Azure subscription. Customer identities and assignments stay in the external directory. The billing relationship does not merge the identity populations.

## 2. Register the two applications

Create one **single-tenant Web registration** in each directory. Record each tenant/client ID and the tenant-local enterprise-app object ID in an internal deployment record, not a public repository.

Use the actual HTTPS hostname from the newly created web app. For local development, the included profile listens on `https://localhost:7016`.

| Tenant | Sign-in Web redirect | Additional post-logout Web redirect | Front-channel logout |
|---|---|---|---|
| Workforce | `/signin-oidc` | `/signout-callback-workforce-oidc` | `/signout-workforce-oidc` |
| External ID | `/signin-external-oidc` | `/signout-callback-external-oidc` | `/signout-external-oidc` |

Prefix every deployed path with the deployed HTTPS base URL. Add optional local sign-in and post-logout URLs using the actual local listener. Entra's localhost redirect matching has a documented port exception, but the browser still must reach the correct local port.

1. Create the Workforce registration in Workforce with the Workforce paths.
2. Create the External registration in the external directory with the External paths.
3. Create separate short-lived POC client secrets; securely capture the **secret value**, not the secret ID.
4. Review/consent the required delegated sign-in permissions. The app requests `openid profile`; it does not call Microsoft Graph. Do not add directory/provisioning permissions to the interactive app. If default `User.Read` remains on the registration, review/admin-consent it or remove it when not needed.
5. Open each matching enterprise app: enable sign-in and set **Assignment required = Yes**.
6. Assign approved non-admin test users directly. Use Default Access if the app has no named app roles.

The code explicitly uses authorization-code flow with PKCE. Implicit access-token/ID-token issuance is not required for this profile. Tenant object IDs, enterprise-app object IDs and client IDs are not interchangeable.

External authority format:

```text
https://<EXTERNAL_SUBDOMAIN>.ciamlogin.com/<EXTERNAL_TENANT_ID>/v2.0
```

Do not use `/common`, a Workforce authority, or a `b2clogin.com` policy URL. OIDC metadata can return a tenant-GUID hostname as issuer; allow the middleware's discovery-based issuer validation instead of forcing the issuer to equal the display hostname.

## 3. User flow, controlled accounts, and MFA

### Associate the customer flow

1. In the external directory, create an external sign-up/sign-in user flow.
2. For the baseline, select Email Accounts > Email with password.
3. Collect only the attributes you need; self-declared attributes are not authorization evidence.
4. Open the flow's Applications page and add the External registration. An application can be associated with only one flow.

### Disable public sign-up for controlled provisioning

Assignment-required controls app admission; it does not itself prevent account registration. Hiding a sign-up link is not a security control.

Microsoft currently documents `onInteractiveAuthFlowStart.isSignUpAllowed=false` through **Microsoft Graph `/beta`**. Beta APIs may change and are not supported for production application use. Obtain approval for the POC administration dependency and review production support before adopting it long term.

Use an external-tenant user-flow administrator with consented delegated `EventListener.ReadWrite.All`, not the web application's credentials:

```powershell
$ErrorActionPreference = 'Stop'
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
}
Import-Module Microsoft.Graph.Authentication
$ExternalTenantId = '<EXTERNAL_TENANT_ID>'
$ExternalClientId = '<EXTERNAL_CLIENT_ID>'
Connect-MgGraph -TenantId $ExternalTenantId `
    -Scopes 'EventListener.ReadWrite.All' -ContextScope Process -NoWelcome
if ((Get-MgContext).TenantId -ne $ExternalTenantId) {
    throw 'Wrong Graph tenant. Stop before writing.'
}
$filter = "microsoft.graph.externalUsersSelfServiceSignUpEventsFlow/" +
    "conditions/applications/includeApplications/" +
    "any(appId:appId/appId eq '$ExternalClientId')"
$lookup = 'https://graph.microsoft.com/v1.0/identity/' +
    'authenticationEventsFlows?$filter=' + [Uri]::EscapeDataString($filter)
$result = Invoke-MgGraphRequest -Method GET -Uri $lookup
$flows = @($result.value)
if ($flows.Count -ne 1) {
    throw 'Expected exactly one associated flow. Check app association.'
}
$flowId = $flows[0].id
$flowUri = "https://graph.microsoft.com/beta/identity/" +
    "authenticationEventsFlows/$flowId"
$before = Invoke-MgGraphRequest -Method GET -Uri $flowUri
$body = @{
    '@odata.type' = '#microsoft.graph.externalUsersSelfServiceSignUpEventsFlow'
    onInteractiveAuthFlowStart = @{
        '@odata.type' =
            '#microsoft.graph.onInteractiveAuthFlowStartExternalUsersSelfServiceSignUp'
        isSignUpAllowed = $false
    }
} | ConvertTo-Json -Depth 5
Invoke-MgGraphRequest -Method PATCH -Uri $flowUri `
    -ContentType 'application/json' -Body $body
$after = Invoke-MgGraphRequest -Method GET -Uri $flowUri
if ($after.onInteractiveAuthFlowStart.isSignUpAllowed -ne $false) {
    throw 'Sign-up was not disabled. Stop and investigate.'
}
Disconnect-MgGraph
```

Record the prior/current non-secret setting in an internal change record. Test an unprovisioned email in a fresh browser and confirm no account is created. Setting the flag back to true deliberately reopens registration; it is not a generic troubleshooting step.

### Provision test customers

1. In the external directory, use **Create new external user**, choose Email identity, and enter a real customer-controlled mailbox.
2. Use a domain outside the Workforce allowlist. Otherwise the router sends the account to Workforce.
3. Securely deliver the generated bootstrap password using the approved process.
4. Confirm the customer is enabled and has no directory admin role.
5. Assign the customer to the external enterprise app; leave a separate non-admin customer unassigned for denial tests.
6. Confirm no customer user/guest was created in Workforce.

Do not use an admin account to demonstrate assignment denial. Customer account creation is not the same operation as inviting an administrator to the external directory.

### MFA

With an approved Security Administrator, enable the supported second-factor method and create a Conditional Access policy scoped to the external POC app/customer population. Review emergency-admin exclusions before enabling.

For an Email with password baseline, Email OTP can be a second factor. Email OTP used as the primary factor cannot also be the Email OTP second factor. If SMS is selected, approve subscription linkage, cost, allowed regions, recovery, and an actual test. Workforce accounts continue using Workforce policy.

## 4. Configure local development

The project already declares a **generic**, non-personal User Secrets ID. User Secrets avoids source control but is not encrypted and is only for development.

```powershell
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$project = '.\src\MultiIdpApp\MultiIdpApp.csproj'
dotnet restore .\MultiIdpApp.slnx --configfile .\NuGet.Config --locked-mode
dotnet build .\MultiIdpApp.slnx -c Release --no-restore
dotnet dev-certs https --trust
$WorkforceTenantId = '<WORKFORCE_TENANT_ID>'
$WorkforceClientId = '<WORKFORCE_CLIENT_ID>'
$ExternalTenantId = '<EXTERNAL_TENANT_ID>'
$ExternalClientId = '<EXTERNAL_CLIENT_ID>'
$ExternalSubdomain = '<EXTERNAL_SUBDOMAIN>'
$WorkforceDomain = '<WORKFORCE_EMAIL_DOMAIN>'
$wfSecret = Read-Host 'Workforce secret VALUE' -AsSecureString
$extSecret = Read-Host 'External app secret VALUE' -AsSecureString
$settings = @{
    'AzureAd:TenantId' = $WorkforceTenantId
    'AzureAd:ClientId' = $WorkforceClientId
    'AzureAd:ClientSecret' =
        [System.Net.NetworkCredential]::new('', $wfSecret).Password
    'ExternalId:Authority' =
        "https://${ExternalSubdomain}.ciamlogin.com/$ExternalTenantId/v2.0"
    'ExternalId:TenantId' = $ExternalTenantId
    'ExternalId:ClientId' = $ExternalClientId
    'ExternalId:ClientSecret' =
        [System.Net.NetworkCredential]::new('', $extSecret).Password
    'IdentityRouting:WorkforceDomains:0' = $WorkforceDomain
}
$settings | ConvertTo-Json -Compress | dotnet user-secrets set --project $project
Remove-Variable settings, wfSecret, extSecret
dotnet run --project $project --launch-profile https
```

Use `:1`, `:2`, etc. for additional approved Workforce domains. Remove stale domains when changing configuration. A listed parent domain includes its subdomains.

Startup explicitly rejects missing/empty IDs, credentials, unresolved vault expressions, shared tenant IDs, invalid CIAM authority, or an empty routing allowlist. Do not disable validation to make an unconfigured sample start.

Never run `dotnet user-secrets list` in a recorded/shareable session. Do not store the prompts' values in this repository.

## 5. Deploy once to Azure App Service

### Host and trust boundary

1. In an approved Workforce-owned Azure subscription/RG, create a Linux Web App with Publish=Code and .NET 10 runtime.
2. Select the approved region and plan. Review policy, quota, cost, and load/availability needs.
3. Copy the **actual** default hostname from Overview, rather than assuming a name from the app resource's label.
4. Enable HTTPS Only, an approved minimum TLS setting, and Always On if supported by the plan.
5. Leave App Service platform authentication disabled for this application's own two-scheme authentication; do not put a Workforce-only Easy Auth gate in front of external customers.
6. Register the final HTTPS callback/logout URLs in both registrations.
7. Identify the actual TLS-terminating proxy IPs/CIDRs with the platform owner. Set `ReverseProxy__Enabled=true` and the explicit trusted list before relying on forwarded scheme/client address.

Do not use `/0` trust-all networks or clear the proxy lists. Do not blindly set `ASPNETCORE_FORWARDEDHEADERS_ENABLED` to bypass the explicit trust configuration. If you cannot establish a safe proxy trust boundary, resolve that platform prerequisite before declaring cloud deployment complete.

### Vault references

1. Enable the App Service system-assigned managed identity.
2. Store the Workforce and External client-secret **values** as separate secrets in an approved Key Vault.
3. Grant the app identity **Key Vault Secrets User** at the approved scope when using Azure RBAC, or the required secret Get access in a legacy access-policy vault.
4. A human creating/rotating secrets needs a separate approved secret-write role, such as Key Vault Secrets Officer.
5. Prove vault network/DNS reachability, including VNet/private endpoints where applicable.
6. Use approved secret URI references in application settings and verify both references show resolved.

The managed identity retrieves credentials. It does not automatically replace either OIDC app registration's confidential-client credential.

### Environment variables

| Setting | Value |
|---|---|
| `ASPNETCORE_ENVIRONMENT` | `Production` |
| `AzureAd__TenantId` | Your Workforce tenant GUID |
| `AzureAd__ClientId` | Your Workforce application client GUID |
| `AzureAd__ClientSecret` | `@Microsoft.KeyVault(SecretUri=<WORKFORCE_SECRET_URI>)` |
| `ExternalId__Authority` | Tenant-specific `ciamlogin.com` v2.0 authority |
| `ExternalId__TenantId` | Your external tenant GUID |
| `ExternalId__ClientId` | Your External application client GUID |
| `ExternalId__ClientSecret` | `@Microsoft.KeyVault(SecretUri=<EXTERNAL_SECRET_URI>)` |
| `IdentityRouting__WorkforceDomains__0` | Approved Workforce email domain; additional entries use `__1`, `__2`, etc. |
| `AllowedHosts` | Actual approved hostname(s), separated by semicolons, with no scheme/path |
| `ReverseProxy__Enabled` | `true` only with the approved proxy trust list |
| `ReverseProxy__KnownProxies__0` | Actual trusted proxy IP; additional IPs use numeric suffixes |
| `ReverseProxy__KnownNetworks__0` | Approved proxy CIDR instead of, or in addition to, individual IPs |

The two callback configurations and code-flow settings already have safe generic defaults in `appsettings.json`. Change callback paths only if you also update the correct app registration.

Azure uses double underscores to bind hierarchical configuration; a single underscore is not equivalent.

### Publish and deploy

Use your own non-secret identifiers, confirm the intended subscription/tenant, and suppress application-setting outputs that could display sensitive values:

```powershell
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$SubscriptionId = '<SUBSCRIPTION_ID>'
$WorkforceTenantId = '<WORKFORCE_TENANT_ID>'
$ResourceGroup = '<RESOURCE_GROUP>'
$WebAppName = '<APP_SERVICE_NAME>'
az login --tenant $WorkforceTenantId
az account set --subscription $SubscriptionId
az account show --query '{id:id,tenantId:tenantId}' --output json
az webapp list-runtimes --os-type linux --output table
dotnet restore .\MultiIdpApp.slnx --configfile .\NuGet.Config --locked-mode
dotnet publish .\src\MultiIdpApp\MultiIdpApp.csproj -c Release --no-restore `
    -o .\artifacts\publish
Compress-Archive -Path .\artifacts\publish\* `
    -DestinationPath .\artifacts\multiidpapp.zip -Force
az webapp deploy --resource-group $ResourceGroup --name $WebAppName `
    --src-path .\artifacts\multiidpapp.zip --type zip --restart true --output none
az webapp show --resource-group $ResourceGroup --name $WebAppName `
    --query '{state:state,host:defaultHostName,httpsOnly:httpsOnly}' --output json
```

The ZIP root must contain `MultiIdpApp.dll`, runtime/dependency files and published assets, not an outer publish folder. The build output is framework-dependent, so the host needs .NET 10. Set an explicit `dotnet MultiIdpApp.dll` startup command if the hosting configuration requires it.

Use an approved pipeline instead of interactive CLI when required by policy. Do not enable FTP/basic-auth or weaken SCM restrictions merely to work around deployment errors.

## 6. Acceptance checks

Run complete identity tests in the deployment environment; a build or generated OAuth redirect alone is not successful authentication.

| Test | Expected result |
|---|---|
| Anonymous `/Profile` | Redirects to the single sign-in page, with no protected content. |
| Assigned Workforce account | Correct Workforce client/tenant and `/signin-oidc`; reaches the session page with Workforce source. |
| Assigned external customer | Correct External client/flow and `/signin-external-oidc`; reaches the session page with ExternalId source. |
| OAuth challenge | `response_type=code`, PKCE `S256`, exact registered callback, normal nonce/state protection. |
| Directory separation | Customer identity exists in external directory only, not as a Workforce customer guest/member. |
| Unassigned non-admin users | Fresh sign-in denied by the enterprise app in the issuing tenant. |
| Disabled customer | Fresh sign-in denied; separately assess an already-issued cookie. |
| Open sign-up blocked | An unprovisioned email cannot register; no new user appears. |
| MFA/recovery | Actual configured second factor and selected recovery flow work with the real mailbox. |
| Logout | Antiforgery-protected POST clears both local cookies, signs out from the active provider, returns home, and `/Profile` is protected again. |
| Input errors | Invalid/display-name/overlength email does not start OIDC; stale/missing antiforgery returns to fresh sign-in. |
| Proxy/HTTPS | Correct external scheme/host, secure-cookie delivery, no redirect loop, and only approved forwarding sources. |

Record only sanitized results and correlation IDs internally. Never commit JWTs, authorization codes, nonce/state values, cookies, secret values, real claim screenshots, or account inventories.

## 7. Failure diagnosis and production gates

- Missing configuration: set required IDs, credentials, authority and Workforce domains; the sample fails explicitly.
- Redirect mismatch: compare actual host/path/scheme against the right tenant registration; use the actual local listener.
- Invalid/expired secret: check value versus ID, matching registration, expiry, vault resolution and network access.
- Assignment or consent error: inspect the enterprise app in the **issuing** tenant; use a non-admin denial test.
- External experience absent: associate the correct external client with exactly one intended user flow.
- HTTPS/correlation failures: validate proxy trust, scheme, host, cookies, restart/scale-out Data Protection behavior and callback configuration.
- Disable/unassign seems ineffective: test a new browser session; existing app cookies are not continuously revalidated.

Before production, implement business-specific authorization, account linking/eligibility, ongoing entitlement/session revalidation, an approved certificate/federated-credential strategy, protected Data Protection persistence/sharing as the topology requires, monitoring and log retention, incident/recovery procedures, capacity testing, privacy and accessibility review, and budget/teardown ownership.

External tenants are not the full Workforce feature set. Do not claim Workforce ID Protection/Entra ID Governance parity from this sample's MFA or assignments.

## Official references

- [Create an external tenant](https://learn.microsoft.com/en-us/entra/external-id/customers/how-to-create-external-tenant-portal)
- [Billing and subscription linkage](https://learn.microsoft.com/en-us/entra/external-id/external-identities-pricing)
- [Supported external-tenant features](https://learn.microsoft.com/en-us/entra/external-id/customers/concept-supported-features-customers)
- [Register an external application and grant consent](https://learn.microsoft.com/en-us/entra/external-id/customers/how-to-register-ciam-app)
- [Create a user flow](https://learn.microsoft.com/en-us/entra/external-id/customers/how-to-user-flow-sign-up-sign-in-customers)
- [Associate an application](https://learn.microsoft.com/en-us/entra/external-id/customers/how-to-user-flow-add-application)
- [Disable sign-up](https://learn.microsoft.com/en-us/entra/external-id/customers/how-to-disable-sign-up-user-flow)
- [Graph flow update permissions and beta support warning](https://learn.microsoft.com/en-us/graph/api/authenticationeventsflow-update?view=graph-rest-beta)
- [Customer accounts](https://learn.microsoft.com/en-us/entra/external-id/customers/how-to-manage-customer-accounts)
- [External MFA](https://learn.microsoft.com/en-us/entra/external-id/customers/how-to-multifactor-authentication-customers)
- [Enterprise app assignments](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-user-or-group-access-portal)
- [Redirect URI constraints](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url)
- [Development User Secrets](https://learn.microsoft.com/en-us/aspnet/core/security/app-secrets?view=aspnetcore-10.0)
- [Trusted proxy/forwarded headers](https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/proxy-load-balancer?view=aspnetcore-10.0)
- [App Service ASP.NET Core hosting](https://learn.microsoft.com/en-us/azure/app-service/configure-language-dotnetcore)
- [Key Vault references](https://learn.microsoft.com/en-us/azure/app-service/app-service-key-vault-references)
- [Key Vault RBAC roles](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide)
- [App Service ZIP deployment](https://learn.microsoft.com/en-us/azure/app-service/deploy-zip)
