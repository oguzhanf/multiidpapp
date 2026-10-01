using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Mail;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace MultiIdp.Net48
{
    public sealed class RegistrationDirectoryConfiguration
    {
        public string TenantId { get; set; }
        public string GraphAuthentication { get; set; }
        public string InitialDomain { get; set; }
        public string ClientId { get; set; }
        public string PasswordSetupClientId { get; set; }
        public string ClientSecretEnvironmentVariable { get; set; }
        public string ServicePrincipalId { get; set; }
        public Dictionary<string, string> RoleIds { get; set; }
    }
    public sealed class RegistrationEmailConfiguration { public string Endpoint { get; set; } public string SenderAddress { get; set; } }
    public sealed class RegistrationConfiguration
    {
        public string AppId { get; set; }
        public string AppBaseUrl { get; set; }
        public string StateFile { get; set; }
        public DateTimeOffset ApprovalLimitUtc { get; set; }
        public RegistrationDirectoryConfiguration Workforce { get; set; }
        public RegistrationDirectoryConfiguration External { get; set; }
        public RegistrationEmailConfiguration Email { get; set; }
    }

    // Provisioning uses the website's managed identity and a separate external-tenant
    // provisioner. The four interactive sign-in clients retain identity-only scopes.
    public static class RegistrationRuntime
    {
        private static readonly HashSet<string> PersonalEmailDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
            "yahoo.com", "ymail.com", "aol.com", "icloud.com", "me.com", "proton.me", "protonmail.com"
        };
        // Shared consumer domains do not identify a user's Microsoft 365 organization.
        // Microsoft metadata discovery can return a tenant for a shared mail domain.
        public static bool IsPersonalEmailDomain(string domain) => domain != null && PersonalEmailDomains.Contains(domain.Trim());
        private static readonly HttpClient Http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(45) };
        public static bool Enabled(AppConfiguration config) => config != null && !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("MULTIIDP_" + config.AppId.ToUpperInvariant() + "_REGISTRATION_CONFIG"));
        public static IReadOnlyList<Entitlement> ReadEntitlements(AppConfiguration config)
        {
            var initial = new JsonEntitlementStore(config.EntitlementFile).Read();
            return Enabled(config) ? initial.Concat(Store(config).ReadApprovedEntitlements()).ToArray() : initial;
        }
        public static JsonInvitationStore Store(AppConfiguration config) => new JsonInvitationStore(Settings(config).StateFile);
        public static DateTimeOffset ApprovalLimit(AppConfiguration config) => Settings(config).ApprovalLimitUtc;
        public static IdentitySource Route(AppConfiguration config, string email)
        {
            var route = IdentityRouter.Route(config, email);
            if (route == IdentitySource.Workforce || !Enabled(config)) return route;
            var domain = new MailAddress(email.Trim()).Host;
            return Store(config).HasApprovedPartnerDomain(config, domain, DateTimeOffset.UtcNow) ? IdentitySource.Workforce : IdentitySource.External;
        }

        public static RegistrationConfiguration Settings(AppConfiguration config)
        {
            if (!Enabled(config)) throw new RegistrationException("Registration is not configured for this application.");
            var path = Environment.GetEnvironmentVariable("MULTIIDP_" + config.AppId.ToUpperInvariant() + "_REGISTRATION_CONFIG");
            RequirePrivatePath(path);
            RegistrationConfiguration settings;
            try { settings = JsonConvert.DeserializeObject<RegistrationConfiguration>(File.ReadAllText(path)); }
            catch (Exception ex) when (ex is IOException || ex is JsonException || ex is UnauthorizedAccessException) { throw new RegistrationException("Registration configuration is unavailable."); }
            Uri origin, endpoint;
            if (settings == null || settings.AppId != config.AppId || settings.Workforce == null || settings.External == null || settings.Email == null ||
                !RegistrationPolicy.SameGuid(settings.Workforce.TenantId, config.Workforce.TenantId) || !RegistrationPolicy.SameGuid(settings.External.TenantId, config.External.TenantId) ||
                !Uri.TryCreate(settings.AppBaseUrl, UriKind.Absolute, out origin) || origin.Scheme != "https" || origin.AbsolutePath != "/" || !string.IsNullOrEmpty(origin.UserInfo + origin.Query + origin.Fragment) ||
                origin.GetLeftPart(UriPartial.Authority) != new Uri(config.Workforce.RedirectUri).GetLeftPart(UriPartial.Authority) ||
                !Uri.TryCreate(settings.Email.Endpoint, UriKind.Absolute, out endpoint) || endpoint.Scheme != "https" || !endpoint.Host.EndsWith(".communication.azure.com", StringComparison.OrdinalIgnoreCase) || endpoint.AbsolutePath != "/" || !string.IsNullOrEmpty(endpoint.UserInfo + endpoint.Query + endpoint.Fragment) ||
                settings.Workforce.GraphAuthentication != "managedIdentity" || settings.External.ClientSecretEnvironmentVariable != "MULTIIDP_REGISTRATION_EXTERNAL_SECRET" ||
                string.IsNullOrWhiteSpace(settings.External.InitialDomain) || !settings.External.InitialDomain.EndsWith(".onmicrosoft.com", StringComparison.OrdinalIgnoreCase))
                throw new RegistrationException("Registration configuration does not match this application.");
            RegistrationPolicy.GuidValue(settings.Workforce.ServicePrincipalId); RegistrationPolicy.GuidValue(settings.External.ServicePrincipalId); RegistrationPolicy.GuidValue(settings.External.ClientId);
            foreach (var directory in new[] { settings.Workforce, settings.External }) {
                if (directory.RoleIds == null || directory.RoleIds.Count == 0) throw new RegistrationException("Directory roles are not configured.");
                foreach (var role in directory.RoleIds.Values) RegistrationPolicy.GuidValue(role);
            }
            RequirePrivatePath(settings.StateFile);
            try { if (new MailAddress(settings.Email.SenderAddress).Address != settings.Email.SenderAddress) throw new FormatException(); }
            catch (Exception ex) when (ex is FormatException || ex is ArgumentException) { throw new RegistrationException("The registration email sender is not configured."); }
            return settings;
        }
        private static void RequirePrivatePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !Path.IsPathRooted(path)) throw new RegistrationException("Set an absolute private configuration or state path.");
            var root = Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            var full = Path.GetFullPath(path);
            if (full.StartsWith(root, StringComparison.OrdinalIgnoreCase) && !full.StartsWith(Path.Combine(root, "App_Data") + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new RegistrationException("Registration files must be protected by IIS App_Data or kept outside the web root.");
        }

        public static async Task<string[]> CurrentSponsorRolesAsync(AppConfiguration config, InvitationRecord invitation)
        {
            if (invitation == null || invitation.AppId != config.AppId || !RegistrationPolicy.SameGuid(invitation.SponsorTenantId, config.Workforce.TenantId)) throw new RegistrationException("The sponsor does not belong to this application.");
            var settings = Settings(config);
            var oid = RegistrationPolicy.GuidValue(invitation.SponsorObjectId);
            var user = await GraphAsync(settings, false, HttpMethod.Get, "/users/" + oid + "?$select=id,userType,accountEnabled").ConfigureAwait(false);
            if ((string)user["id"] != oid || (string)user["userType"] != "Member" || (bool?)user["accountEnabled"] != true) throw new RegistrationException("The employee sponsor is no longer enabled.");
            // Direct assignments are the PoC capability model. Query THIS enterprise app
            // so app01 needs Application.Read.All rather than directory role-write access.
            var assignments = await GraphCollectionAsync(settings, false, "/servicePrincipals/" + settings.Workforce.ServicePrincipalId + "/appRoleAssignedTo").ConfigureAwait(false);
            return settings.Workforce.RoleIds.Where(role => assignments.Any(a => RegistrationPolicy.SameGuid((string)a["principalId"], oid) && RegistrationPolicy.SameGuid((string)a["resourceId"], settings.Workforce.ServicePrincipalId) && RegistrationPolicy.SameGuid((string)a["appRoleId"], role.Value))).Select(role => role.Key).ToArray();
        }

        public static async Task<InvitationRecord> InviteAsync(AppConfiguration config, ClaimsPrincipal sponsor, RegistrationKind kind, string recipientEmail, bool relationshipAttested)
        {
            var settings = Settings(config);
            var entries = ReadEntitlements(config);
            var initial = RegistrationPolicy.Authorize(config, sponsor, entries, kind, DateTimeOffset.UtcNow);
            if (!initial.Allowed) throw new RegistrationException(initial.Reason);
            if (kind == RegistrationKind.Dependent && !relationshipAttested) throw new RegistrationException("Confirm the dependent relationship and benefit purpose.");
            string email;
            try { var address = new MailAddress((recipientEmail ?? "").Trim()); email = address.Address.ToLowerInvariant(); if (!string.Equals(address.Address, (recipientEmail ?? "").Trim(), StringComparison.OrdinalIgnoreCase) || email.Length > 254 || recipientEmail.Contains("\r") || recipientEmail.Contains("\n")) throw new FormatException(); }
            catch (Exception ex) when (ex is FormatException || ex is ArgumentException) { throw new RegistrationException("Enter a complete email address without a display name."); }
            var homeTenant = await ResolveOrganizationAsync(new MailAddress(email).Host).ConfigureAwait(false);
            if (kind == RegistrationKind.Dependent && homeTenant != null) throw new RegistrationException("Use the dependent's personal email address.");
            if (kind != RegistrationKind.Dependent && homeTenant != null) kind = RegistrationKind.OrganizationalPartner;
            if (kind == RegistrationKind.OrganizationalPartner && (homeTenant == null || RegistrationPolicy.SameGuid(homeTenant, config.Workforce.TenantId) || RegistrationPolicy.SameGuid(homeTenant, config.External.TenantId))) throw new RegistrationException("A partner must use an account in a verified separate Microsoft 365 organization.");
            var check = new InvitationRecord { AppId = config.AppId, Kind = kind, SponsorTenantId = initial.SponsorEntitlement.TenantId, SponsorObjectId = initial.SponsorEntitlement.ObjectId };
            var currentRoles = await CurrentSponsorRolesAsync(config, check).ConfigureAwait(false);
            var current = RegistrationPolicy.RecheckSponsor(config, check, ReadEntitlements(config), currentRoles, DateTimeOffset.UtcNow);
            if (!current.Allowed) throw new RegistrationException(current.Reason);
            var store = Store(config);
            var issued = store.Create(config, sponsor, ReadEntitlements(config), kind, email, DateTimeOffset.UtcNow, settings.ApprovalLimitUtc);
            var landing = settings.AppBaseUrl.TrimEnd('/') + "/Registration/Accept?token=" + Uri.EscapeDataString(issued.Token);
            var destination = landing;
            try {
                if (kind == RegistrationKind.OrganizationalPartner) {
                    // Bind the native B2B identity before sending its Microsoft redemption
                    // URL through the approved email service. Never reset an existing guest.
                    var body = JObject.FromObject(new { invitedUserEmailAddress = email, inviteRedirectUrl = landing, sendInvitationMessage = false });
                    var invitation = await GraphAsync(settings, false, HttpMethod.Post, "/invitations", body).ConfigureAwait(false);
                    var guestId = RegistrationPolicy.GuidValue((string)invitation["invitedUser"]?["id"]);
                    await AssignRoleAsync(settings, false, guestId, "Partner").ConfigureAwait(false);
                    store.BindIdentity(config, issued.Invitation.Id, new InvitationIdentityBinding { TenantId = settings.Workforce.TenantId, ObjectId = guestId, HomeTenantId = homeTenant, OrganizationVerifiedUtc = DateTimeOffset.UtcNow }, DateTimeOffset.UtcNow);
                    Uri redeemUrl;
                    if (!Uri.TryCreate((string)invitation["inviteRedeemUrl"], UriKind.Absolute, out redeemUrl) || redeemUrl.Scheme != "https" || (redeemUrl.Host != "invitations.microsoft.com" && redeemUrl.Host != "login.microsoftonline.com"))
                        throw new RegistrationException("Microsoft did not provide a valid B2B redemption URL.");
                    destination = redeemUrl.AbsoluteUri;
                } else {
                    var objectId = await GetOrCreateCustomerAsync(settings, email).ConfigureAwait(false);
                    await AssignRoleAsync(settings, true, objectId, kind == RegistrationKind.Dependent ? "Dependent" : "External").ConfigureAwait(false);
                    store.BindIdentity(config, issued.Invitation.Id, new InvitationIdentityBinding { TenantId = settings.External.TenantId, ObjectId = objectId }, DateTimeOffset.UtcNow);
                }
            } catch (Exception ex) when (ex is RegistrationException || ex is HttpRequestException || ex is TaskCanceledException || ex is IOException || ex is JsonException) {
                // This catch surrounds directory work only. Email has not been called.
                // Preserve an expired audit row so the employee can issue a fresh link.
                try { store.CancelBeforeDelivery(config, issued.Invitation.Id, DateTimeOffset.UtcNow); }
                catch (Exception cleanup) when (cleanup is RegistrationException || cleanup is IOException || cleanup is UnauthorizedAccessException || cleanup is JsonException) { }
                throw;
            }
            await SendRegistrationEmailAsync(config, store, issued.Invitation.Id, settings, email, destination, kind).ConfigureAwait(false);
            return store.Preview(config, issued.Token, DateTimeOffset.UtcNow);
        }

        private static async Task<string> ResolveOrganizationAsync(string domain)
        {
            if (Uri.CheckHostName(domain) != UriHostNameType.Dns || !domain.Contains(".")) throw new RegistrationException("Enter a valid email domain.");
            if (IsPersonalEmailDomain(domain)) return null;
            using (var response = await Http.GetAsync("https://login.microsoftonline.com/" + Uri.EscapeDataString(domain) + "/v2.0/.well-known/openid-configuration").ConfigureAwait(false)) {
                if (response.StatusCode == HttpStatusCode.BadRequest || response.StatusCode == HttpStatusCode.NotFound) return null;
                if (!response.IsSuccessStatusCode) throw new RegistrationException("Microsoft organization discovery is unavailable. Retry without changing identity source.");
                var data = await ReadJsonAsync(response).ConfigureAwait(false);
                Uri issuer;
                if (!Uri.TryCreate((string)data["issuer"], UriKind.Absolute, out issuer) || issuer.Scheme != "https" || issuer.Host != "login.microsoftonline.com") throw new RegistrationException("Microsoft organization discovery returned an unexpected issuer.");
                var segments = issuer.AbsolutePath.Trim('/').Split('/');
                if (segments.Length != 2 || segments[1] != "v2.0") throw new RegistrationException("Microsoft organization discovery did not resolve an organizational tenant.");
                var tenantId = RegistrationPolicy.GuidValue(segments[0]);
                return tenantId == "9188040d-6c67-4c5b-b112-36a304b66dad" ? null : tenantId;
            }
        }
        private static async Task<string> GetOrCreateCustomerAsync(RegistrationConfiguration settings, string email)
        {
            var filter = "identities/any(i:i/issuerAssignedId eq '" + email.Replace("'", "''") + "' and i/issuer eq '" + settings.External.InitialDomain.Replace("'", "''") + "')";
            var users = await GraphCollectionAsync(settings, true, "/users?$filter=" + Uri.EscapeDataString(filter) + "&$select=id,accountEnabled,identities").ConfigureAwait(false);
            if (users.Count > 1) throw new RegistrationException("The external account lookup is ambiguous.");
            if (users.Count == 1) {
                if ((bool?)users[0]["accountEnabled"] != true || !((JArray)users[0]["identities"]).Any(i => (string)i["signInType"] == "emailAddress" && string.Equals((string)i["issuerAssignedId"], email, StringComparison.OrdinalIgnoreCase) && (string)i["issuer"] == settings.External.InitialDomain))
                    throw new RegistrationException("The external account cannot be used for registration.");
                return RegistrationPolicy.GuidValue((string)users[0]["id"]);
            }
            var bytes = new byte[32]; using (var random = RandomNumberGenerator.Create()) random.GetBytes(bytes);
            // Unknown random password is transient provisioning input only. The recipient
            // sets their own password through Microsoft email-verified password reset.
            var password = "Aa1!" + Convert.ToBase64String(bytes);
            var body = JObject.FromObject(new { accountEnabled = true, displayName = "Invited application user", mail = email, creationType = "LocalAccount", passwordPolicies = "DisablePasswordExpiration", identities = new[] { new { signInType = "emailAddress", issuer = settings.External.InitialDomain, issuerAssignedId = email } }, passwordProfile = new { password, forceChangePasswordNextSignIn = false } });
            var created = await GraphAsync(settings, true, HttpMethod.Post, "/users", body).ConfigureAwait(false);
            return RegistrationPolicy.GuidValue((string)created["id"]);
        }
        private static async Task AssignRoleAsync(RegistrationConfiguration settings, bool external, string objectId, string role)
        {
            var directory = external ? settings.External : settings.Workforce;
            string roleId; if (!directory.RoleIds.TryGetValue(role, out roleId)) throw new RegistrationException("The required persona role is not configured.");
            var assigned = await GraphCollectionAsync(settings, external, "/users/" + objectId + "/appRoleAssignments").ConfigureAwait(false);
            if (assigned.Any(a => (string)a["resourceId"] == directory.ServicePrincipalId && (string)a["appRoleId"] == roleId)) return;
            await GraphAsync(settings, external, HttpMethod.Post, "/servicePrincipals/" + directory.ServicePrincipalId + "/appRoleAssignedTo", JObject.FromObject(new { principalId = objectId, resourceId = directory.ServicePrincipalId, appRoleId = roleId })).ConfigureAwait(false);
        }
        internal static async Task<JObject> GraphAsync(RegistrationConfiguration settings, bool external, HttpMethod method, string path, JObject body = null)
        {
            string token;
            if (external) {
                var secret = Environment.GetEnvironmentVariable(settings.External.ClientSecretEnvironmentVariable);
                if (string.IsNullOrWhiteSpace(secret)) throw new RegistrationException("The external registration service is not configured.");
                var client = ConfidentialClientApplicationBuilder.Create(settings.External.ClientId).WithClientSecret(secret).WithAuthority("https://login.microsoftonline.com/" + settings.External.TenantId).Build();
                try { token = (await client.AcquireTokenForClient(new[] { "https://graph.microsoft.com/.default" }).ExecuteAsync().ConfigureAwait(false)).AccessToken; }
                catch (MsalException) { throw new RegistrationException("The external directory registration service is unavailable."); }
            } else token = await ManagedIdentityTokenAsync("https://graph.microsoft.com").ConfigureAwait(false);
            var uri = path.StartsWith("https://graph.microsoft.com/v1.0/", StringComparison.Ordinal) ? path : "https://graph.microsoft.com/v1.0" + path;
            if (!uri.StartsWith("https://graph.microsoft.com/v1.0/", StringComparison.Ordinal)) throw new RegistrationException("An unexpected directory endpoint was rejected.");
            using (var request = new HttpRequestMessage(method, uri)) {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                if (body != null) request.Content = new StringContent(body.ToString(Formatting.None), System.Text.Encoding.UTF8, "application/json");
                using (var response = await Http.SendAsync(request).ConfigureAwait(false)) {
                    if (!response.IsSuccessStatusCode) {
                        var area = external ? "External ID" : "Workforce";
                        var action = path.Contains("appRole") ? "persona assignment" : path.Contains("/users") ? "account operation" : "directory operation";
                        throw new RegistrationException(area + " " + action + " failed (HTTP " + (int)response.StatusCode + "). Check the service permissions and account state.");
                    }
                    return response.StatusCode == HttpStatusCode.NoContent ? new JObject() : await ReadJsonAsync(response).ConfigureAwait(false);
                }
            }
        }
        private static async Task<List<JObject>> GraphCollectionAsync(RegistrationConfiguration settings, bool external, string path)
        {
            var result = new List<JObject>();
            do { var page = await GraphAsync(settings, external, HttpMethod.Get, path).ConfigureAwait(false); result.AddRange(((JArray)page["value"] ?? new JArray()).OfType<JObject>()); path = (string)page["@odata.nextLink"]; } while (!string.IsNullOrEmpty(path));
            return result;
        }
        private static async Task<string> ManagedIdentityTokenAsync(string resource)
        {
            var endpoint = Environment.GetEnvironmentVariable("IDENTITY_ENDPOINT"); var header = Environment.GetEnvironmentVariable("IDENTITY_HEADER");
            Uri uri;
            if (string.IsNullOrWhiteSpace(header) || !Uri.TryCreate(endpoint, UriKind.Absolute, out uri) || !uri.IsLoopback) throw new RegistrationException("The website managed identity is unavailable.");
            var target = endpoint + (endpoint.Contains("?") ? "&" : "?") + "api-version=2019-08-01&resource=" + Uri.EscapeDataString(resource);
            using (var request = new HttpRequestMessage(HttpMethod.Get, target)) {
                request.Headers.Add("X-IDENTITY-HEADER", header);
                using (var response = await Http.SendAsync(request).ConfigureAwait(false)) {
                    if (!response.IsSuccessStatusCode) throw new RegistrationException("The website managed identity could not authenticate.");
                    var data = await ReadJsonAsync(response).ConfigureAwait(false); var token = (string)data["access_token"];
                    if (string.IsNullOrWhiteSpace(token)) throw new RegistrationException("The managed identity response was incomplete."); return token;
                }
            }
        }
        private static async Task SendRegistrationEmailAsync(AppConfiguration config, JsonInvitationStore store, string invitationId, RegistrationConfiguration settings, string email, string landing, RegistrationKind kind)
        {
            var token = await ManagedIdentityTokenAsync("https://communication.azure.com").ConfigureAwait(false);
            var label = kind == RegistrationKind.Dependent ? "dependent" : kind == RegistrationKind.OrganizationalPartner ? "business partner" : "external user";
            var instructions = kind == RegistrationKind.OrganizationalPartner
                ? "Continue with your own Microsoft 365 work account. Microsoft completes the standard B2B invitation and redirects you to the application to confirm registration. The application also checks your verified home organization."
                : "Open the invitation, verify your email, and create your password. If you already have an account in this External ID directory, choose the existing-account sign-in option. No password is included in this message.";
            var text = "You have been invited as a " + label + " to " + settings.AppId + ".\n\nOpen this registration link within 24 hours:\n" + landing + "\n\n" + instructions + "\n\nFinal application registration is single-use. Your approval requires a current sponsor and ends at the recorded PoC expiry. If you did not expect this invitation, do not use the link.";
            var body = JObject.FromObject(new { senderAddress = settings.Email.SenderAddress, recipients = new { to = new[] { new { address = email } } }, content = new { subject = settings.AppId + " account registration", plainText = text } });
            var root = new Uri(settings.Email.Endpoint);
            var operationId = Guid.NewGuid().ToString();
            using (var request = new HttpRequestMessage(HttpMethod.Post, EmailSendUri(root))) {
                // Persist a nonsecret operation ID BEFORE network submission. An uncertain
                // response can then be inspected without resending or revoking its link.
                request.Headers.Add("Operation-Id", operationId);
                store.RecordDelivery(config, invitationId, "queued", operationId, DateTimeOffset.UtcNow);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token); request.Content = new StringContent(body.ToString(Formatting.None), System.Text.Encoding.UTF8, "application/json");
                using (var response = await Http.SendAsync(request).ConfigureAwait(false)) {
                    if (response.StatusCode != HttpStatusCode.Accepted) {
                        store.RecordDelivery(config, invitationId, "failed", operationId, DateTimeOffset.UtcNow);
                        throw new RegistrationException("The registration email service did not accept the invitation (HTTP " + (int)response.StatusCode + "). Do not repeatedly resend it.");
                    }
                    IEnumerable<string> values; Uri operation;
                    if (!response.Headers.TryGetValues("Operation-Location", out values) || !Uri.TryCreate(values.SingleOrDefault(), UriKind.Absolute, out operation) || operation.Scheme != "https" || operation.Host != root.Host || !operation.AbsolutePath.StartsWith("/emails/operations/", StringComparison.Ordinal))
                        throw new RegistrationException("The registration email response did not provide a valid operation endpoint.");
                    Guid operationGuid;
                    if (!Guid.TryParse(operation.AbsolutePath.Substring("/emails/operations/".Length).Trim('/'), out operationGuid) || operationGuid.ToString() != operationId) throw new RegistrationException("The registration email operation identifier was invalid. Do not automatically resend.");
                    var delay = RetryDelay(response);
                    for (var attempt = 0; attempt < 4; attempt++) {
                        await Task.Delay(delay).ConfigureAwait(false);
                        using (var poll = new HttpRequestMessage(HttpMethod.Get, operation)) {
                            poll.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                            using (var status = await Http.SendAsync(poll).ConfigureAwait(false)) {
                                if (!status.IsSuccessStatusCode) {
                                    store.RecordDelivery(config, invitationId, "pending", operationId, DateTimeOffset.UtcNow);
                                    throw new RegistrationException("Email status is unavailable. The invitation may already be queued; do not automatically resend.");
                                }
                                var data = await ReadJsonAsync(status).ConfigureAwait(false);
                                if (string.Equals((string)data["status"], "Succeeded", StringComparison.OrdinalIgnoreCase)) {
                                    store.RecordDelivery(config, invitationId, "sent", operationId, DateTimeOffset.UtcNow);
                                    return;
                                }
                                if (string.Equals((string)data["status"], "Failed", StringComparison.OrdinalIgnoreCase) || string.Equals((string)data["status"], "Canceled", StringComparison.OrdinalIgnoreCase)) {
                                    store.RecordDelivery(config, invitationId, "failed", operationId, DateTimeOffset.UtcNow);
                                    throw new RegistrationException("The email send operation failed.");
                                }
                                delay = RetryDelay(status);
                            }
                        }
                    }
                    store.RecordDelivery(config, invitationId, "pending", operationId, DateTimeOffset.UtcNow);
                    throw new RegistrationException("Email delivery is still pending. Do not automatically resend this invitation.");
                }
            }
        }
        internal static Uri EmailSendUri(Uri root) => new Uri(root, "/emails:send?api-version=2025-09-01");
        private static TimeSpan RetryDelay(HttpResponseMessage response)
        {
            var requested = response.Headers.RetryAfter?.Delta;
            if (!requested.HasValue && response.Headers.RetryAfter?.Date != null) requested = response.Headers.RetryAfter.Date.Value - DateTimeOffset.UtcNow;
            return requested.HasValue && requested.Value > TimeSpan.FromSeconds(15) ? requested.Value : TimeSpan.FromSeconds(15);
        }
        private static async Task<JObject> ReadJsonAsync(HttpResponseMessage response)
        {
            try { return JObject.Parse(await response.Content.ReadAsStringAsync().ConfigureAwait(false)); }
            catch (JsonException) { throw new RegistrationException("The registration service response was incomplete."); }
        }
    }
}
