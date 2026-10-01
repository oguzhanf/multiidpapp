using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Helpers;
using System.Web.Mvc;
using System.Web.Routing;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Host.SystemWeb;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

[assembly: OwinStartup(typeof(MultiIdp.Net48.Startup))]
namespace MultiIdp.Net48
{
    public sealed class Startup
    {
#if SAMPLEAPP01
        public const string AppId = "sampleapp01";
#else
        public const string AppId = "sampleapp02";
#endif
        public const string CookieScheme = "AppCookie";
        public static AppConfiguration Config { get; private set; }
        public static string ConfigurationError { get; private set; }
        public void Configuration(IAppBuilder app) => Configure(app);
        private void Configure(IAppBuilder app)
        {
            AntiForgeryConfig.UniqueClaimTypeIdentifier = "subject_key";
            AntiForgeryConfig.RequireSsl = true;
            app.SetDefaultSignInAsAuthenticationType(CookieScheme);
            app.UseCookieAuthentication(new CookieAuthenticationOptions {
                AuthenticationType = CookieScheme, CookieName = "__Host-" + AppId,
                CookieHttpOnly = true, CookieSecure = CookieSecureOption.Always, CookieSameSite = SameSiteMode.Lax,
                CookiePath = "/", ExpireTimeSpan = TimeSpan.FromMinutes(20), SlidingExpiration = false,
                CookieManager = new SystemWebCookieManager(), AuthenticationMode = AuthenticationMode.Active
            });
            try
            {
                Config = ConfigurationLoader.Load(AppId);
                var workforceSecret = ConfigurationLoader.ReadSecret(Config.Workforce);
                var externalSecret = ConfigurationLoader.ReadSecret(Config.External);
                AddProvider(app, Config.Workforce, false, workforceSecret);
                AddProvider(app, Config.External, true, externalSecret);
            }
            catch (ConfigurationException ex) { ConfigurationError = ex.Message; }
        }
        private static void AddProvider(IAppBuilder app, TenantConfiguration tenant, bool external, string secret)
        {
            var source = external ? "external" : "workforce";
            var authority = external ? "https://" + tenant.CiamDomain + "/" + tenant.TenantId : "https://login.microsoftonline.com/" + tenant.TenantId;
            var msal = ConfidentialClientApplicationBuilder.Create(tenant.ClientId)
                .WithClientSecret(secret).WithAuthority(authority).WithRedirectUri(tenant.RedirectUri).Build();
            var options = new OpenIdConnectAuthenticationOptions {
                AuthenticationType = source, AuthenticationMode = AuthenticationMode.Passive,
                SignInAsAuthenticationType = CookieScheme, Authority = authority + "/v2.0",
                ClientId = tenant.ClientId, RedirectUri = tenant.RedirectUri, CallbackPath = new PathString(new Uri(tenant.RedirectUri).AbsolutePath),
                ResponseType = OpenIdConnectResponseType.Code, ResponseMode = OpenIdConnectResponseMode.FormPost,
                Scope = "openid profile email", UsePkce = true, RedeemCode = true, SaveTokens = false,
                RequireHttpsMetadata = true, CookieManager = new SystemWebCookieManager(),
                SecurityTokenValidator = new StrictJwtSecurityTokenHandler { MapInboundClaims = false },
                TokenValidationParameters = new TokenValidationParameters {
                    ValidateIssuer = true, ValidIssuer = tenant.Issuer,
                    IssuerValidator = (issuer, token, parameters) => issuer == tenant.Issuer ? issuer : throw new SecurityTokenInvalidIssuerException("Unexpected tenant issuer."),
                    ValidateAudience = true, ValidAudience = tenant.ClientId, ValidateLifetime = true, RequireSignedTokens = true,
                    RequireExpirationTime = true, ClockSkew = TimeSpan.FromMinutes(2), NameClaimType = "name", RoleClaimType = "roles"
                },
                Notifications = new OpenIdConnectAuthenticationNotifications {
                    RedirectToIdentityProvider = notification => {
                        if (notification.ProtocolMessage.RequestType == OpenIdConnectRequestType.Authentication) {
                            string email;
                            if (notification.OwinContext.Authentication.AuthenticationResponseChallenge?.Properties.Dictionary.TryGetValue("login_hint", out email) == true)
                                notification.ProtocolMessage.LoginHint = email;
                        }
                        return Task.FromResult(0);
                    },
                    SecurityTokenValidated = notification => {
                        RegistrationSignInPolicy.Validate(Config, notification.AuthenticationTicket.Identity,
                            notification.AuthenticationTicket.Properties, source, RegistrationRuntime.ReadEntitlements(Config),
                            RegistrationRuntime.Enabled(Config) ? RegistrationRuntime.Store(Config) : null, DateTimeOffset.UtcNow);
                        return Task.FromResult(0);
                    },
                    AuthenticationFailed = notification => {
                        notification.HandleResponse();
                        // Avoid reflecting protocol errors, credentials or tokens to the browser.
                        notification.Response.Redirect("/Account/Failure");
                        return Task.FromResult(0);
                    }
                }
            };
            app.Use(typeof(MsalOpenIdConnectMiddleware), app, options, msal);
        }
    }

    public class WebApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            RouteTable.Routes.IgnoreRoute("{resource}.axd/{*pathInfo}");
            RouteTable.Routes.MapRoute("default", "{controller}/{action}", new { controller = "Home", action = "Index" });
            MvcHandler.DisableMvcResponseHeader = true;
            GlobalFilters.Filters.Add(new AntiforgeryFailureFilter());
        }
    }
}
