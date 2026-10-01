using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using MultiIdp.Net48;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;

internal static class WorkforceResolverTests
{
    private const string ObjectId = "11111111-1111-1111-1111-111111111111";
    internal static void Run(Action<string, Func<bool>> check)
    {
        check("automatic workforce lookup resolves 100 unlisted UPN suffixes", () => {
            using (var client = Client(request => {
                var filter = HttpUtility.ParseQueryString(request.RequestUri.Query)["$filter"];
                var upn = filter.Substring("userPrincipalName eq '".Length).TrimEnd('\'');
                return Reply(HttpStatusCode.OK, new JObject { ["value"] = new JArray(new JObject { ["id"] = ObjectId, ["userPrincipalName"] = upn }) }.ToString());
            })) {
                var resolver = Resolver(client); return Enumerable.Range(0, 100).All(i => resolver.ResolveAsync("employee@domain" + i + ".example").GetAwaiter().GetResult() == IdentitySource.Workforce);
            }
        });
        check("automatic workforce lookup confirmed empty collection selects External", () => Resolve("{\"value\":[]}") == IdentitySource.External);
        check("automatic workforce lookup disabled account remains Workforce", () => Resolve("{\"value\":[{\"id\":\"" + ObjectId + "\",\"userPrincipalName\":\"employee@organization.example\",\"accountEnabled\":false}]}") == IdentitySource.Workforce);
        check("automatic workforce lookup guest account remains Workforce", () => Resolve("{\"value\":[{\"id\":\"" + ObjectId + "\",\"userPrincipalName\":\"employee@organization.example\",\"userType\":\"Guest\"}]}") == IdentitySource.Workforce);
        check("automatic workforce lookup failure never falls back on 401 403 404 429 500", () => new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden, HttpStatusCode.NotFound, (HttpStatusCode)429, HttpStatusCode.InternalServerError }.All(status => Denied(() => Resolve("{\"value\":[]}", status))));
        check("automatic workforce lookup redirects fail closed", () => Denied(() => Resolve("{\"value\":[]}", HttpStatusCode.Redirect)));
        check("automatic workforce lookup malformed response fails closed", () => new[] { "not json", "{}", "{\"value\":null}", "{\"value\":{}}", "{\"value\":[\"user\"]}" }.All(json => Denied(() => Resolve(json))));
        check("automatic workforce lookup ambiguous results fail closed", () => Denied(() => Resolve("{\"value\":[{\"id\":\"" + ObjectId + "\",\"userPrincipalName\":\"employee@organization.example\"},{\"id\":\"" + ObjectId + "\",\"userPrincipalName\":\"employee@organization.example\"}]}")));
        check("automatic workforce lookup mismatched UPN or invalid id fail closed", () => Denied(() => Resolve("{\"value\":[{\"id\":\"" + ObjectId + "\",\"userPrincipalName\":\"alias@organization.example\"}]}")) && Denied(() => Resolve("{\"value\":[{\"id\":\"not-a-guid\",\"userPrincipalName\":\"employee@organization.example\"}]}")));
        check("automatic workforce lookup pagination is not confirmed absence", () => Denied(() => Resolve("{\"value\":[],\"@odata.nextLink\":\"https://graph.microsoft.com/v1.0/users?next\"}")));
        check("automatic workforce lookup UPN is OData escaped then URL encoded", () => {
            using (var client = Client(request => {
                var query = HttpUtility.ParseQueryString(request.RequestUri.Query);
                if (request.RequestUri.Scheme != "https" || request.RequestUri.Host != "graph.microsoft.com" || request.RequestUri.AbsolutePath != "/v1.0/users" || query["$filter"] != "userPrincipalName eq 'o''brien+tag@organization.example'" || query["$top"] != "2" || query["$select"] != "id,userPrincipalName" || request.Headers.Authorization?.Scheme != "Bearer") throw new Exception("unexpected query boundary");
                return Reply(HttpStatusCode.OK, "{\"value\":[{\"id\":\"" + ObjectId + "\",\"userPrincipalName\":\"o'brien+tag@organization.example\"}]}");
            })) return Resolver(client).ResolveAsync(" O'Brien+tag@organization.example ").GetAwaiter().GetResult() == IdentitySource.Workforce;
        });
        check("automatic workforce lookup token failure is scrubbed and fail closed", () => {
            using (var client = Client(_ => throw new Exception("HTTP must not run"))) {
                var resolver = new WorkforceAccountResolver(client, _ => throw new Exception("private credential details"));
                try { resolver.ResolveAsync("employee@organization.example").GetAwaiter().GetResult(); return false; }
                catch (RegistrationException ex) { return !ex.Message.Contains("private credential"); }
            }
        });
        check("automatic workforce lookup transport timeout fails closed", () => {
            using (var client = Client(_ => throw new TaskCanceledException("private URL"))) return Denied(() => Resolver(client).ResolveAsync("employee@organization.example").GetAwaiter().GetResult());
        });
        check("automatic workforce lookup display-name input is rejected before HTTP", () => {
            using (var client = Client(_ => throw new Exception("HTTP must not run"))) {
                try { Resolver(client).ResolveAsync("Employee <employee@organization.example>").GetAwaiter().GetResult(); return false; }
                catch (ArgumentException) { return true; }
            }
        });
        check("automatic App01 configuration accepts an empty employee domain list", () => EmptyDomainsLoad("sampleapp01", true));
        check("App02 configuration still requires employee domains", () => EmptyDomainsLoad("sampleapp02", false));
    }
    private static bool EmptyDomainsLoad(string app, bool expectedSuccess)
    {
        var path = Path.Combine(Path.GetTempPath(), "net48-upn-config-" + Guid.NewGuid() + ".json");
        var variable = "MULTIIDP_" + app.ToUpperInvariant() + "_CONFIG"; var prior = Environment.GetEnvironmentVariable(variable);
        var config = new AppConfiguration {
            AppId = app, EmployeeDomains = new string[0], ApprovedPartnerDomains = new string[0], EntitlementFile = path + ".approvals",
            Workforce = new TenantConfiguration { TenantId = "11111111-1111-1111-1111-111111111111", ClientId = "33333333-3333-3333-3333-333333333333", Issuer = "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0", RedirectUri = "https://localhost:44371/signin-workforce", ClientSecretEnvironmentVariable = "FIXTURE_WORKFORCE_SECRET" },
            External = new TenantConfiguration { TenantId = "22222222-2222-2222-2222-222222222222", ClientId = "44444444-4444-4444-4444-444444444444", Issuer = "https://example.ciamlogin.com/22222222-2222-2222-2222-222222222222/v2.0", CiamDomain = "example.ciamlogin.com", RedirectUri = "https://localhost:44371/signin-external", ClientSecretEnvironmentVariable = "FIXTURE_EXTERNAL_SECRET" }
        };
        try {
            File.WriteAllText(path, JsonConvert.SerializeObject(config)); Environment.SetEnvironmentVariable(variable, path);
            try { var loaded = ConfigurationLoader.Load(app); return expectedSuccess && loaded.EmployeeDomains.Length == 0; }
            catch (ConfigurationException) { return !expectedSuccess; }
        } finally { Environment.SetEnvironmentVariable(variable, prior); File.Delete(path); }
    }
    private static WorkforceAccountResolver Resolver(HttpClient client) => new WorkforceAccountResolver(client, _ => Task.FromResult("fixture-token"));
    private static IdentitySource Resolve(string json, HttpStatusCode status = HttpStatusCode.OK)
    {
        using (var client = Client(_ => Reply(status, json))) return Resolver(client).ResolveAsync("employee@organization.example").GetAwaiter().GetResult();
    }
    private static bool Denied(Action action) { try { action(); return false; } catch (RegistrationException) { return true; } }
    private static HttpClient Client(Func<HttpRequestMessage, HttpResponseMessage> response) => new HttpClient(new Handler(response));
    private static HttpResponseMessage Reply(HttpStatusCode status, string json) => new HttpResponseMessage(status) { Content = new StringContent(json) };
    private sealed class Handler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> response;
        internal Handler(Func<HttpRequestMessage, HttpResponseMessage> response) { this.response = response; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.FromResult(response(request));
    }
}
