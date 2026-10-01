using System;
using System.Net.Http;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Mail;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace MultiIdp.Net48
{
    public sealed class WorkforceAccountResolver
    {
        private readonly HttpClient client;
        private readonly Func<CancellationToken, Task<string>> tokenProvider;
        public WorkforceAccountResolver(HttpClient client, Func<CancellationToken, Task<string>> tokenProvider)
        {
            this.client = client ?? throw new ArgumentNullException(nameof(client));
            this.tokenProvider = tokenProvider ?? throw new ArgumentNullException(nameof(tokenProvider));
        }
        public async Task<IdentitySource> ResolveAsync(string identifier, CancellationToken cancellationToken = default(CancellationToken))
        {
            var upn = NormalizeIdentifier(identifier);
            try
            {
                var token = await tokenProvider(cancellationToken).ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(token)) throw new RegistrationException("Workforce account lookup authentication is unavailable.");
                // The site's managed identity is provisioned in the configured workforce
                // tenant. Do not query mail/proxyAddresses or infer identity from a domain.
                var filter = "userPrincipalName eq '" + upn.Replace("'", "''") + "'";
                var uri = new Uri("https://graph.microsoft.com/v1.0/users?$filter=" + Uri.EscapeDataString(filter) + "&$select=id,userPrincipalName&$top=2");
                using (var request = new HttpRequestMessage(HttpMethod.Get, uri))
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                    using (var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false))
                    {
                        if (response.StatusCode != HttpStatusCode.OK) throw new RegistrationException("Workforce account lookup did not return a confirmed result.");
                        var data = JObject.Parse(await response.Content.ReadAsStringAsync().ConfigureAwait(false));
                        var values = data["value"] as JArray;
                        if (values == null || data.Property("@odata.nextLink") != null || data.Property("error") != null || values.Count > 1)
                            throw new RegistrationException("Workforce account lookup returned an incomplete or ambiguous result.");
                        if (values.Count == 0) return IdentitySource.External;
                        var user = values[0] as JObject;
                        Guid objectId;
                        if (user == null || user["id"]?.Type != JTokenType.String || !Guid.TryParse((string)user["id"], out objectId) || objectId == Guid.Empty || user["userPrincipalName"]?.Type != JTokenType.String || !string.Equals((string)user["userPrincipalName"], upn, StringComparison.OrdinalIgnoreCase))
                            throw new RegistrationException("Workforce account lookup did not match the exact sign-in address.");
                        // Disabled users and guests still belong to this realm. Authentication
                        // and the existing signed-role/entitlement policy decide admission.
                        return IdentitySource.Workforce;
                    }
                }
            }
            catch (RegistrationException) { throw; }
            catch (Exception) { throw new RegistrationException("Workforce account lookup is temporarily unavailable. Try again or contact your application administrator."); }
        }
        public static string NormalizeIdentifier(string identifier)
        {
            var normalized = (identifier ?? "").Trim(); MailAddress address;
            try { address = new MailAddress(normalized); }
            catch (Exception ex) when (ex is FormatException || ex is ArgumentException) { throw new ArgumentException("Enter your complete sign-in address (UPN)."); }
            if (normalized.Length > 254 || (identifier ?? "").IndexOfAny(new[] { '\r', '\n' }) >= 0 || !string.Equals(address.Address, normalized, StringComparison.OrdinalIgnoreCase) || !address.Host.Contains(".") || Uri.CheckHostName(address.Host) != UriHostNameType.Dns)
                throw new ArgumentException("Enter your exact sign-in address (UPN) without a display name.");
            return address.Address.ToLowerInvariant();
        }
    }
}
