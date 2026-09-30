using System.Security.Claims;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using MultiIdpApp.Identity;

var passed = 0;
var router = new IdentityRouter(Options.Create(new IdentityRoutingOptions
{
    WorkforceDomains = ["workforce.example"]
}));

Check("Normalizes email whitespace and domain case", () =>
{
    Assert(router.TryNormalize("  User@WORKFORCE.EXAMPLE  ", out var email));
    Assert(email == "User@workforce.example");
});
foreach (var input in new string?[] { null, "", "invalid", "Name <user@workforce.example>", new('a', 255) })
{
    Check("Rejects invalid email input", () => Assert(!router.TryNormalize(input, out _)));
}
Check("Routes the Workforce domain", () =>
    Assert(router.SelectScheme("user@workforce.example") == AuthSchemes.WorkforceOidc));
Check("Routes a Workforce subdomain", () =>
    Assert(router.SelectScheme("user@sub.workforce.example") == AuthSchemes.WorkforceOidc));
Check("Does not confuse a lookalike domain", () =>
    Assert(router.SelectScheme("user@notworkforce.example") == AuthSchemes.ExternalOidc));
Check("Routes a personal domain externally", () =>
    Assert(router.SelectScheme("user@personal.example") == AuthSchemes.ExternalOidc));

var expectedTenant = Guid.NewGuid().ToString();
Check("Normalizes only a validated expected-tenant identity", () =>
{
    var principal = Principal(expectedTenant, "subject");
    Assert(PrincipalNormalizer.TryNormalize(
        principal, expectedTenant, AuthSchemes.WorkforceSource, out _));
    Assert(principal.FindFirstValue("identity_source") == AuthSchemes.WorkforceSource);
    Assert(principal.FindFirstValue("app_tenant_id") == expectedTenant);
    Assert(principal.FindFirstValue("app_subject") == "subject");
});
Check("Replaces injected application claims", () =>
{
    var principal = Principal(expectedTenant, "subject");
    var identity = (ClaimsIdentity)principal.Identity!;
    identity.AddClaim(new Claim("identity_source", "untrusted"));
    identity.AddClaim(new Claim("app_tenant_id", "untrusted"));
    identity.AddClaim(new Claim("app_subject", "untrusted"));
    identity.AddClaim(new Claim("app_email", "untrusted"));
    Assert(PrincipalNormalizer.TryNormalize(
        principal, expectedTenant, AuthSchemes.ExternalSource, out _));
    Assert(principal.FindAll("identity_source").Single().Value == AuthSchemes.ExternalSource);
    Assert(principal.FindFirstValue("app_email") == "user@personal.example");
});
Check("Rejects a different tenant", () =>
    Assert(!PrincipalNormalizer.TryNormalize(
        Principal(Guid.NewGuid().ToString(), "subject"), expectedTenant, AuthSchemes.ExternalSource, out _)));
Check("Rejects a missing tenant", () =>
    Assert(!PrincipalNormalizer.TryNormalize(
        Principal("", "subject"), expectedTenant, AuthSchemes.ExternalSource, out _)));
Check("Rejects a missing subject", () =>
    Assert(!PrincipalNormalizer.TryNormalize(
        Principal(expectedTenant, ""), expectedTenant, AuthSchemes.ExternalSource, out _)));
Check("Rejects an unauthenticated principal", () =>
    Assert(!PrincipalNormalizer.TryNormalize(
        new ClaimsPrincipal(new ClaimsIdentity()), expectedTenant, AuthSchemes.ExternalSource, out _)));
Check("Rejects an unknown identity source", () =>
    Assert(!PrincipalNormalizer.TryNormalize(
        Principal(expectedTenant, "subject"), expectedTenant, "unknown", out _)));
Check("Uses sub when oid is absent", () =>
{
    var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [new Claim("tid", expectedTenant), new Claim("sub", "subject")], "test"));
    Assert(PrincipalNormalizer.TryNormalize(
        principal, expectedTenant, AuthSchemes.ExternalSource, out _));
    Assert(principal.FindFirstValue("app_subject") == "subject");
});

Check("Accepts complete separate-tenant configuration", () =>
    IdentityConfiguration.Validate(Configuration()));
Check("Rejects a missing credential", () =>
{
    var configuration = Configuration();
    configuration["ExternalId:ClientSecret"] = "";
    ExpectFailure(() => IdentityConfiguration.Validate(configuration));
});
Check("Rejects an unresolved secret reference", () =>
{
    var configuration = Configuration();
    configuration["ExternalId:ClientSecret"] =
        "@Microsoft.KeyVault(SecretUri=<SECRET_URI>)";
    ExpectFailure(() => IdentityConfiguration.Validate(configuration));
});
Check("Rejects shared tenant configuration", () =>
{
    var configuration = Configuration();
    configuration["ExternalId:TenantId"] = configuration["AzureAd:TenantId"];
    ExpectFailure(() => IdentityConfiguration.Validate(configuration));
});
Check("Rejects a non-CIAM external authority", () =>
{
    var configuration = Configuration();
    configuration["ExternalId:Authority"] = "https://login.microsoftonline.com/common/v2.0";
    ExpectFailure(() => IdentityConfiguration.Validate(configuration));
});
Check("Leaves proxy processing disabled by default", () =>
    new ReverseProxyOptions().Validate());
Check("Requires explicit proxy trust when enabled", () =>
    ExpectFailure(() => new ReverseProxyOptions { Enabled = true }.Validate()));
Check("Rejects trust-all networks", () =>
    ExpectFailure(() => new ReverseProxyOptions { Enabled = true, KnownNetworks = ["0.0.0.0/0"] }.Validate()));
Check("Accepts an explicitly trusted loopback proxy", () =>
    new ReverseProxyOptions { Enabled = true, KnownProxies = ["127.0.0.1"] }.Validate());

Console.WriteLine($"PASS: {passed} focused tests.");

void Check(string name, Action test)
{
    test();
    passed++;
    Console.WriteLine($"PASS: {name}");
}
static void Assert(bool condition)
{
    if (!condition) throw new InvalidOperationException("Assertion failed.");
}
static void ExpectFailure(Action action)
{
    try { action(); }
    catch (InvalidOperationException) { return; }
    throw new InvalidOperationException("Expected explicit validation failure.");
}
static ClaimsPrincipal Principal(string tenant, string subject) =>
    new(new ClaimsIdentity(
        [new Claim("tid", tenant), new Claim("oid", subject),
         new Claim("email", "user@personal.example")], "test"));
static IConfigurationRoot Configuration()
{
    var external = Guid.NewGuid().ToString();
    return new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
    {
        ["AzureAd:TenantId"] = Guid.NewGuid().ToString(),
        ["AzureAd:ClientId"] = Guid.NewGuid().ToString(),
        ["AzureAd:ClientSecret"] = Guid.NewGuid().ToString(),
        ["ExternalId:TenantId"] = external,
        ["ExternalId:ClientId"] = Guid.NewGuid().ToString(),
        ["ExternalId:ClientSecret"] = Guid.NewGuid().ToString(),
        ["ExternalId:Authority"] = $"https://example.ciamlogin.com/{external}/v2.0"
    }).Build();
}
