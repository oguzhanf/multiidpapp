using System;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin.Logging;
using MultiIdp.Net48;
using Newtonsoft.Json;

internal static class MsalTransportTests
{
    private const string Tenant = "11111111-1111-1111-1111-111111111111";
    private const string ClientId = "66666666-6666-6666-6666-666666666666";
    private const string Redirect = "https://localhost:44371/signin-workforce";
    private const string Verifier = "synthetic-pkce-verifier-abcdefghijklmnopqrstuvwxyz0123456789";
    public static bool RedemptionUsesPkce()
    {
        using (var transport = new SyntheticIdentityTransport())
        {
            var handler = Handler(transport);
            var request = new OpenIdConnectMessage { Code = "synthetic-one-time-code", RedirectUri = Redirect };
            request.Parameters["code_verifier"] = Verifier;
            var response = Redeem(handler, request).GetAwaiter().GetResult();
            var form = HttpUtility.ParseQueryString(transport.TokenRequest);
            return transport.TokenCalls == 1 && form["grant_type"] == "authorization_code" && form["code"] == "synthetic-one-time-code"
                && form["code_verifier"] == Verifier && form["client_id"] == ClientId && form["redirect_uri"] == Redirect
                && form["client_secret"] == "synthetic-client-secret" && form["scope"].Contains("openid")
                && response.IdToken == transport.IdToken && response.AccessToken == "synthetic-access-token" && response.TokenType == "Bearer";
        }
    }
    public static bool MissingVerifierRejected()
    {
        using (var transport = new SyntheticIdentityTransport())
        {
            try { Redeem(Handler(transport), new OpenIdConnectMessage { Code = "synthetic-code", RedirectUri = Redirect }).GetAwaiter().GetResult(); return false; }
            catch (InvalidOperationException) { return transport.TokenCalls == 0; }
        }
    }
    private static MsalOpenIdConnectHandler Handler(SyntheticIdentityTransport transport)
    {
        var client = ConfidentialClientApplicationBuilder.Create(ClientId).WithClientSecret("synthetic-client-secret")
            .WithAuthority("https://login.microsoftonline.com/" + Tenant).WithInstanceDiscovery(false)
            .WithRedirectUri(Redirect).WithHttpClientFactory(transport).Build();
        return new MsalOpenIdConnectHandler(new QuietLogger(), client);
    }
    private static Task<OpenIdConnectMessage> Redeem(MsalOpenIdConnectHandler handler, OpenIdConnectMessage request)
        => (Task<OpenIdConnectMessage>)typeof(MsalOpenIdConnectHandler).GetMethod("RedeemAuthorizationCodeAsync", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(handler, new object[] { request });
    private sealed class QuietLogger : ILogger
    {
        public bool WriteCore(System.Diagnostics.TraceEventType eventType, int eventId, object state, Exception exception, Func<object, Exception, string> formatter) => false;
    }
    // Only HTTP is synthetic: the test executes the real MSAL client and production handler.
    private sealed class SyntheticIdentityTransport : HttpMessageHandler, IMsalHttpClientFactory
    {
        private readonly HttpClient client;
        public int TokenCalls { get; private set; }
        public string TokenRequest { get; private set; }
        public string IdToken { get; }
        public SyntheticIdentityTransport()
        {
            client = new HttpClient(this, false);
            IdToken = Encode("{\"alg\":\"none\"}") + "." + Encode(JsonConvert.SerializeObject(new {
                aud = ClientId, iss = "https://login.microsoftonline.com/" + Tenant + "/v2.0", tid = Tenant,
                oid = "33333333-3333-3333-3333-333333333333", sub = "synthetic-subject", preferred_username = "synthetic@employee.test",
                exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()
            })) + ".";
        }
        public HttpClient GetHttpClient() => client;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string response;
            if (request.RequestUri.AbsolutePath.EndsWith("/.well-known/openid-configuration"))
                response = JsonConvert.SerializeObject(new { authorization_endpoint = "https://login.microsoftonline.com/" + Tenant + "/oauth2/v2.0/authorize", token_endpoint = "https://login.microsoftonline.com/" + Tenant + "/oauth2/v2.0/token", issuer = "https://login.microsoftonline.com/" + Tenant + "/v2.0" });
            else if (request.RequestUri.AbsolutePath.EndsWith("/oauth2/v2.0/token"))
            {
                TokenCalls++; TokenRequest = await request.Content.ReadAsStringAsync();
                response = JsonConvert.SerializeObject(new { token_type = "Bearer", scope = "openid profile offline_access", expires_in = 3600, access_token = "synthetic-access-token", id_token = IdToken, client_info = Encode(JsonConvert.SerializeObject(new { uid = "33333333-3333-3333-3333-333333333333", utid = Tenant })) });
            }
            else throw new InvalidOperationException("Unexpected synthetic test HTTP endpoint.");
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(response, Encoding.UTF8, "application/json") };
        }
        protected override void Dispose(bool disposing) { if (disposing) client.Dispose(); base.Dispose(disposing); }
        private static string Encode(string value) => Convert.ToBase64String(Encoding.UTF8.GetBytes(value)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
