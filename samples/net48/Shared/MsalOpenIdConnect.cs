using System;
using System.Globalization;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

namespace MultiIdp.Net48
{
    // Replace just the code-redemption transport. Katana still validates the returned
    // signed ID token, audience, issuer, protocol response and nonce cookie.
    public sealed class MsalOpenIdConnectMiddleware : OpenIdConnectAuthenticationMiddleware
    {
        private readonly ILogger logger;
        private readonly IConfidentialClientApplication client;
        public MsalOpenIdConnectMiddleware(OwinMiddleware next, IAppBuilder app, OpenIdConnectAuthenticationOptions options, IConfidentialClientApplication client)
            : base(next, app, options) { logger = app.CreateLogger<MsalOpenIdConnectMiddleware>(); this.client = client; }
        protected override AuthenticationHandler<OpenIdConnectAuthenticationOptions> CreateHandler() => new MsalOpenIdConnectHandler(logger, client);
    }

    public sealed class MsalOpenIdConnectHandler : OpenIdConnectAuthenticationHandler
    {
        private readonly IConfidentialClientApplication client;
        public MsalOpenIdConnectHandler(ILogger logger, IConfidentialClientApplication client) : base(logger) { this.client = client; }
        protected override async Task<OpenIdConnectMessage> RedeemAuthorizationCodeAsync(OpenIdConnectMessage request)
        {
            string verifier;
            if (string.IsNullOrWhiteSpace(request.Code) || !request.Parameters.TryGetValue("code_verifier", out verifier) || string.IsNullOrWhiteSpace(verifier))
                throw new InvalidOperationException("The protected PKCE verifier or authorization code is missing.");
            // MSAL adds the reserved openid/profile/offline_access scopes itself.
            // No Graph scope is needed for this identity-only demonstration.
            var result = await client.AcquireTokenByAuthorizationCode(new string[0], request.Code)
                .WithPkceCodeVerifier(verifier).ExecuteAsync().ConfigureAwait(false);
            // AccessToken is transient protocol input; never saved to cookie, logged or rendered.
            return new OpenIdConnectMessage {
                IdToken = result.IdToken, AccessToken = result.AccessToken, TokenType = "Bearer",
                ExpiresIn = Math.Max(0, (int)(result.ExpiresOn - DateTimeOffset.UtcNow).TotalSeconds).ToString(CultureInfo.InvariantCulture)
            };
        }
    }
}
