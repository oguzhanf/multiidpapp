using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using MultiIdpApp.Identity;
using static MultiIdpApp.Identity.AuthSchemes;

var builder = WebApplication.CreateBuilder(args);
IdentityConfiguration.Validate(builder.Configuration);
var proxy = builder.Configuration.GetSection("ReverseProxy").Get<ReverseProxyOptions>() ?? new();
proxy.Validate();
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    foreach (var address in proxy.KnownProxies)
    {
        options.KnownProxies.Add(IPAddress.Parse(address));
    }
    foreach (var network in proxy.KnownNetworks)
    {
        options.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(network));
    }
});

var authentication = builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = AppSession;
    options.DefaultAuthenticateScheme = AppSession;
    options.DefaultChallengeScheme = ChooserCookie;
});

authentication.AddPolicyScheme(AppSession, "Application session", options =>
{
    options.ForwardDefaultSelector = context =>
        context.Request.Cookies.ContainsKey(ExternalCookieName) ? ExternalCookie : WorkforceCookie;
});

authentication.AddCookie(ChooserCookie, options =>
{
    options.Cookie.Name = ".MultiIdpApp.Chooser";
    options.LoginPath = "/SignIn";
});

// Each configuration section has its own OIDC handler, tenant/client and session cookie.
authentication.AddMicrosoftIdentityWebApp(
    builder.Configuration.GetSection("AzureAd"),
    WorkforceOidc,
    WorkforceCookie,
    displayName: "Workforce account");

authentication.AddMicrosoftIdentityWebApp(
    builder.Configuration.GetSection("ExternalId"),
    ExternalOidc,
    ExternalCookie,
    displayName: "External ID customer");

ConfigureCookie(builder.Services, WorkforceCookie, WorkforceCookieName, ExternalCookieName);
ConfigureCookie(builder.Services, ExternalCookie, ExternalCookieName, WorkforceCookieName);
ConfigureOidc(builder.Services, WorkforceOidc, WorkforceSource, builder.Configuration["AzureAd:TenantId"]!);
ConfigureOidc(builder.Services, ExternalOidc, ExternalSource, builder.Configuration["ExternalId:TenantId"]!);

builder.Services.AddAuthorization(options =>
{
    options.DefaultPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .RequireClaim("identity_source", WorkforceSource, ExternalSource)
        .Build();
});

builder.Services.AddOptions<IdentityRoutingOptions>()
    .Bind(builder.Configuration.GetSection("IdentityRouting"))
    .Validate(
        options => options.WorkforceDomains.Any(domain => !string.IsNullOrWhiteSpace(domain)),
        "IdentityRouting:WorkforceDomains must contain at least one Workforce email domain.")
    .ValidateOnStart();
builder.Services.AddSingleton<IdentityRouter>();
builder.Services.AddRazorPages()
    .AddMvcOptions(options => options.Filters.Add<SignInAntiforgeryFilter>());

var app = builder.Build();
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}
if (proxy.Enabled)
{
    app.UseForwardedHeaders();
}
app.UseHttpsRedirection();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapStaticAssets();
app.MapRazorPages().WithStaticAssets();
app.Run();

static void ConfigureCookie(
    IServiceCollection services, string scheme, string cookieName, string oppositeCookieName)
{
    services.PostConfigure<CookieAuthenticationOptions>(scheme, options =>
    {
        options.Cookie.Name = cookieName;
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.ExpireTimeSpan = TimeSpan.FromHours(1);
        options.SlidingExpiration = false;
        options.Events.OnSigningIn = context =>
        {
            context.Response.Cookies.Delete(oppositeCookieName, new CookieOptions { Path = "/" });
            return Task.CompletedTask;
        };
    });
}

static void ConfigureOidc(
    IServiceCollection services, string scheme, string identitySource, string expectedTenantId)
{
    services.PostConfigure<OpenIdConnectOptions>(scheme, options =>
    {
        options.ResponseType = OpenIdConnectResponseType.Code;
        options.UsePkce = true;
        options.SaveTokens = true;
        options.MapInboundClaims = false;
        options.TokenValidationParameters.NameClaimType = "name";
        options.TokenValidationParameters.RoleClaimType = "roles";

        var existingRedirect = options.Events.OnRedirectToIdentityProvider;
        options.Events.OnRedirectToIdentityProvider = async context =>
        {
            if (existingRedirect is not null)
            {
                await existingRedirect(context);
            }
            if (string.IsNullOrEmpty(context.ProtocolMessage.LoginHint))
            {
                context.ProtocolMessage.Prompt = "select_account";
            }
        };

        var existingValidation = options.Events.OnTokenValidated;
        options.Events.OnTokenValidated = async context =>
        {
            if (existingValidation is not null)
            {
                await existingValidation(context);
            }
            if (context.Result?.Failure is not null)
            {
                return;
            }
            if (!PrincipalNormalizer.TryNormalize(
                    context.Principal, expectedTenantId, identitySource, out var error))
            {
                context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>()
                    .CreateLogger("MultiIdpApp.Identity")
                    .LogWarning("Rejected {Scheme} principal: {Reason}", scheme, error);
                context.Fail(error!);
            }
        };
    });
}
