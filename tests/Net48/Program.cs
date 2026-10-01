using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using Newtonsoft.Json;
using MultiIdp.Net48;

internal static class Program
{
    private static readonly string Workforce = "11111111-1111-1111-1111-111111111111";
    private static readonly string External = "22222222-2222-2222-2222-222222222222";
    private static readonly string ObjectId = "33333333-3333-3333-3333-333333333333";
    private static readonly string EmployeeObjectId = "88888888-8888-8888-8888-888888888888";
    private static readonly DateTimeOffset Now = new DateTimeOffset(2026, 9, 30, 12, 0, 0, TimeSpan.Zero);
    private static int failures;
    private static int total;

    private static int Main()
    {
        Check("employee uses exact configured domain", () => Route(" Alice@EMPLOYEE.test ", "sampleapp01") == IdentitySource.Workforce);
        Check("employee subdomain is external", () => Route("alice@sub.employee.test", "sampleapp01") == IdentitySource.External);
        Check("domain suffix attack is external", () => Route("alice@employee.test.attacker.test", "sampleapp01") == IdentitySource.External);
        Check("unknown email uses external", () => Route("alice@gmail.test", "sampleapp01") == IdentitySource.External);
        Check("approved partner route only in app02", () => Route("alice@partner.test", "sampleapp02") == IdentitySource.Workforce && Route("alice@partner.test", "sampleapp01") == IdentitySource.External);
        Check("invalid email is rejected", () => Throws<ArgumentException>(() => Route("not-email", "sampleapp01")));
        Check("display-name email is rejected", () => Throws<ArgumentException>(() => Route("Alice <alice@employee.test>", "sampleapp01")));
        Check("approved employee admitted", () => Admit(Record("employee", "workforce"), Principal(Workforce), "sampleapp01"));
        Check("external employee denied", () => !Admit(Record("employee", "external", External), Principal(External), "sampleapp01"));
        Check("approved retiree requires sponsor", () => Admit(Record("retiree", "external", External), Principal(External), "sampleapp01") && !Admit(Change(Record("retiree", "external", External), e => e.Sponsor = ""), Principal(External), "sampleapp01"));
        Check("dependent relationship and benefit verified", () => Admit(Change(Record("dependent", "external", External), e => { e.RelationshipVerified = true; e.BenefitEligible = true; }), Principal(External, role: "Dependent"), "sampleapp01"));
        Check("dependent unverified relationship denied", () => !Admit(Change(Record("dependent", "external", External), e => e.BenefitEligible = true), Principal(External, role: "Dependent"), "sampleapp01"));
        Check("dependent no benefit eligibility denied", () => !Admit(Change(Record("dependent", "external", External), e => e.RelationshipVerified = true), Principal(External, role: "Dependent"), "sampleapp01"));
        Check("cross app denied", () => !Admit(Record("employee", "workforce"), Principal(Workforce), "sampleapp02"));
        Check("cross tenant denied", () => !Admit(Record("employee", "workforce"), Principal(External), "sampleapp01"));
        Check("wrong object id denied", () => !Admit(Record("employee", "workforce"), Principal(Workforce, "44444444-4444-4444-4444-444444444444"), "sampleapp01"));
        Check("expiry boundary denied", () => !Admit(Change(Record("employee", "workforce"), e => e.ExpiresUtc = Now), Principal(Workforce), "sampleapp01"));
        Check("disabled entitlement denied", () => !Admit(Change(Record("employee", "workforce"), e => e.Status = "disabled"), Principal(Workforce), "sampleapp01"));
        Check("unknown persona denied", () => !Admit(Record("administrator", "workforce"), Principal(Workforce), "sampleapp01"));
        Check("email alone cannot establish identity", () => !Admit(Record("employee", "workforce"), new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("email", "alice@employee.test") }, "cookie")), "sampleapp01"));
        Check("unauthenticated principal denied", () => !Admit(Record("employee", "workforce"), new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("tid", Workforce), new Claim("oid", ObjectId) })), "sampleapp01"));
        Check("duplicate stable identity claims denied", () => !Admit(Record("employee", "workforce"), Principal(Workforce, ObjectId, new Claim("tid", External)), "sampleapp01"));
        Check("issuer mismatch denied", () => !Admit(Record("employee", "workforce"), Principal(Workforce, ObjectId, null, "https://attacker.test/v2.0"), "sampleapp01"));
        Check("audience mismatch denied", () => !Admit(Record("employee", "workforce"), Principal(Workforce, ObjectId, null, null, "44444444-4444-4444-4444-444444444444"), "sampleapp01"));
        Check("forged source denied", () => !Admit(Record("employee", "workforce"), Principal(Workforce, ObjectId, null, null, null, "external"), "sampleapp01"));
        Check("partner denied in app01", () => !Admit(VerifiedPartner("sampleapp01"), PartnerPrincipal(), "sampleapp01"));
        Check("verified partner admitted in app02", () => Admit(VerifiedPartner("sampleapp02"), PartnerPrincipal(), "sampleapp02"));
        Check("partner organizational verification required", () => !Admit(Change(VerifiedPartner("sampleapp02"), e => e.OrganizationVerifiedUtc = null), PartnerPrincipal(), "sampleapp02"));
        Check("partner home organization required", () => !Admit(Change(VerifiedPartner("sampleapp02"), e => e.HomeTenantId = null), PartnerPrincipal(), "sampleapp02"));
        Check("duplicate entitlements fail closed", () => !AdmissionPolicy.Evaluate(Config("sampleapp01"), Principal(Workforce), new[] { Record("employee", "workforce"), Record("employee", "workforce") }, Now).Allowed);
        Check("revocation file reloaded each request", FileRevocation);
        Check("configuration requires HTTPS callback", () => Throws<ConfigurationException>(() => ConfigurationLoader.ValidateTenant(new TenantConfiguration { TenantId = Workforce, ClientId = ObjectId, Issuer = "https://login.microsoftonline.com/" + Workforce + "/v2.0", RedirectUri = "http://localhost/signin-workforce", ClientSecretEnvironmentVariable = "NET48_TEST_SECRET" }, false)));
        Check("configuration rejects common workforce authority", () => Throws<ConfigurationException>(() => ConfigurationLoader.ValidateTenant(new TenantConfiguration { TenantId = "common", ClientId = ObjectId, RedirectUri = "https://localhost/signin-workforce" }, false)));
        Check("configuration rejects foreign CIAM domain", () => Throws<ConfigurationException>(() => ConfigurationLoader.ValidateTenant(new TenantConfiguration { TenantId = External, ClientId = ObjectId, Issuer = "https://" + External + ".ciamlogin.com/" + External + "/v2.0", RedirectUri = "https://localhost/signin-external", CiamDomain = "attacker.test", ClientSecretEnvironmentVariable = "NET48_TEST_SECRET" }, true)));
        Check("signed persona role required", () => !Admit(Record("employee", "workforce"), Principal(Workforce, role: "External"), "sampleapp01"));
        Check("missing signed role denied", () => !Admit(Record("employee", "workforce"), Principal(Workforce, role: ""), "sampleapp01"));
        Check("partner missing signed home issuer denied", () => !Admit(VerifiedPartner("sampleapp02"), Principal(Workforce, role: "Partner"), "sampleapp02"));
        Check("partner foreign signed home issuer denied", () => !Admit(VerifiedPartner("sampleapp02"), Principal(Workforce, additional: new Claim("idp", "https://sts.windows.net/77777777-7777-7777-7777-777777777777/"), role: "Partner"), "sampleapp02"));
        Check("partner consumer signed issuer denied", () => !Admit(VerifiedPartner("sampleapp02"), Principal(Workforce, additional: new Claim("idp", "live.com"), role: "Partner"), "sampleapp02"));
        Check("partner duplicate signed home issuer denied", () => { var p = PartnerPrincipal(); ((ClaimsIdentity)p.Identity).AddClaim(new Claim("idp", "live.com")); return !Admit(VerifiedPartner("sampleapp02"), p, "sampleapp02"); });
        Check("approved other external persona admitted", () => Admit(Record("external", "external", External), Principal(External, role: "External"), "sampleapp01"));
        Check("other external persona requires sponsor", () => !Admit(Change(Record("external", "external", External), e => e.Sponsor = null), Principal(External, role: "External"), "sampleapp01"));
        Check("other external persona cannot use workforce source", () => !Admit(Record("external", "workforce"), Principal(Workforce, role: "External"), "sampleapp01"));
        Check("MSAL sends protected PKCE in real code redemption", MsalTransportTests.RedemptionUsesPkce);
        Check("MSAL rejects missing protected PKCE before network", MsalTransportTests.MissingVerifierRejected);
        Check("dependent stable linked employee required", () => !Admit(Change(EligibleDependent(), e => e.LinkedEmployeeObjectId = null), Principal(External, role: "Dependent"), "sampleapp01"));
        Check("dependent missing linked employee record denied", () => !AdmissionPolicy.Evaluate(Config("sampleapp01"), Principal(External, role: "Dependent"), new[] { EligibleDependent() }, Now).Allowed);
        Check("dependent disabled parent denied", () => !AdmitWithParent(EligibleDependent(), Change(EmployeeParent(), e => e.Status = "disabled")));
        Check("dependent expired parent denied", () => !AdmitWithParent(EligibleDependent(), Change(EmployeeParent(), e => e.ExpiresUtc = Now)));
        Check("dependent parent without benefit denied", () => !AdmitWithParent(EligibleDependent(), Change(EmployeeParent(), e => e.BenefitEligible = false)));
        Check("dependent cross app parent denied", () => !AdmitWithParent(EligibleDependent(), Change(EmployeeParent(), e => e.AppId = "sampleapp02")));
        Check("dependent cross tenant link denied", () => !AdmitWithParent(Change(EligibleDependent(), e => e.LinkedEmployeeTenantId = External), EmployeeParent()));
        Check("dependent duplicate parent records denied", () => !AdmissionPolicy.Evaluate(Config("sampleapp01"), Principal(External, role: "Dependent"), new[] { EligibleDependent(), EmployeeParent(), EmployeeParent() }, Now).Allowed);
        Check("dependent linked person must be employee", () => !AdmitWithParent(EligibleDependent(), Change(EmployeeParent(), e => e.Persona = "partner")));
        Check("partner future verification denied", () => !Admit(Change(VerifiedPartner("sampleapp02"), e => e.OrganizationVerifiedUtc = Now.AddDays(1)), PartnerPrincipal(), "sampleapp02"));
        Check("partner sponsor required", () => !Admit(Change(VerifiedPartner("sampleapp02"), e => e.Sponsor = ""), PartnerPrincipal(), "sampleapp02"));
        Check("missing application config fails closed with existing cookie", () => !AdmissionPolicy.Evaluate(null, Principal(Workforce), new[] { Record("employee", "workforce") }, Now).Allowed);
        Check("unsigned ID token rejected even when Katana disables signed requirement", TokenValidationTests.UnsignedRejected);
        Check("properly signed ID token retains issuer audience lifetime validation", TokenValidationTests.SignedAccepted);
        Check("signed ID token wrong issuer denied", TokenValidationTests.WrongIssuerRejected);
        Check("signed ID token wrong audience denied", TokenValidationTests.WrongAudienceRejected);
        Check("signed ID token expiry denied", TokenValidationTests.ExpiredRejected);
        Check("signed ID token foreign signing key denied", TokenValidationTests.ForeignKeyRejected);
        RegistrationTests.Run(Check);
        RegistrationFlowTests.Run(Check);
        PasswordSetupTests.Run(Check);
        Console.WriteLine("Net48 policy: " + (total - failures) + "/" + total + " passed");
        return failures == 0 ? 0 : 1;
    }

    private static void Check(string name, Func<bool> test)
    {
        total++;
        try { if (!test()) throw new Exception("expected policy behavior"); Console.WriteLine("PASS " + name); }
        catch (Exception ex) { failures++; Console.WriteLine("FAIL " + name + ": " + ex.Message); }
    }
    private static IdentitySource Route(string email, string app) => IdentityRouter.Route(Config(app), email);
    private static bool Admit(Entitlement entry, ClaimsPrincipal principal, string app) => AdmissionPolicy.Evaluate(Config(app), principal, entry.Persona == "dependent" ? new[] { entry, EmployeeParent() } : new[] { entry }, Now).Allowed;
    private static bool AdmitWithParent(Entitlement entry, Entitlement parent) => AdmissionPolicy.Evaluate(Config("sampleapp01"), Principal(External, role: "Dependent"), new[] { entry, parent }, Now).Allowed;
    private static bool Throws<T>(Action action) where T : Exception { try { action(); return false; } catch (T) { return true; } }
    private static Entitlement Change(Entitlement entry, Action<Entitlement> action) { action(entry); return entry; }
    private static Entitlement Record(string persona, string source, string tenant = null) => new Entitlement { AppId = "sampleapp01", TenantId = tenant ?? Workforce, ObjectId = ObjectId, Source = source, Persona = persona, Sponsor = "sponsor-record-001", Status = "approved", ExpiresUtc = Now.AddDays(1), LinkedEmployeeTenantId = persona == "dependent" ? Workforce : null, LinkedEmployeeObjectId = persona == "dependent" ? EmployeeObjectId : null };
    private static Entitlement EmployeeParent() => Change(Record("employee", "workforce"), e => { e.ObjectId = EmployeeObjectId; e.BenefitEligible = true; });
    private static Entitlement EligibleDependent() => Change(Record("dependent", "external", External), e => { e.RelationshipVerified = true; e.BenefitEligible = true; });
    private static Entitlement VerifiedPartner(string app) => Change(Record("partner", "workforce"), e => { e.AppId = app; e.HomeTenantId = "55555555-5555-5555-5555-555555555555"; e.OrganizationVerifiedUtc = Now.AddDays(-1); });
    private static ClaimsPrincipal PartnerPrincipal() => Principal(Workforce, additional: new Claim("idp", "https://sts.windows.net/55555555-5555-5555-5555-555555555555/"), role: "Partner");
    private static ClaimsPrincipal Principal(string tenant, string oid = null, Claim additional = null, string issuer = null, string audience = null, string source = null, string role = null)
    {
        var claims = new List<Claim> { new Claim("tid", tenant), new Claim("oid", oid ?? ObjectId), new Claim("iss", issuer ?? "https://issuer.test/" + tenant + "/v2.0"), new Claim("aud", audience ?? "66666666-6666-6666-6666-666666666666"), new Claim("identity_source", source ?? (tenant == Workforce ? "workforce" : "external")) };
        if (additional != null) claims.Add(additional);
        role = role ?? (tenant == Workforce ? "Employee" : "Retiree");
        if (!string.IsNullOrEmpty(role)) claims.Add(new Claim("roles", role));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "cookie"));
    }
    private static AppConfiguration Config(string app) => new AppConfiguration { AppId = app, EmployeeDomains = new[] { "employee.test" }, ApprovedPartnerDomains = new[] { "partner.test" }, Workforce = new TenantConfiguration { TenantId = Workforce, ClientId = "66666666-6666-6666-6666-666666666666", Issuer = "https://issuer.test/" + Workforce + "/v2.0" }, External = new TenantConfiguration { TenantId = External, ClientId = "66666666-6666-6666-6666-666666666666", Issuer = "https://issuer.test/" + External + "/v2.0" } };
    private static bool FileRevocation()
    {
        var path = Path.Combine(Path.GetTempPath(), "net48-policy-" + Guid.NewGuid() + ".json");
        try
        {
            var config = Config("sampleapp01"); config.EntitlementFile = path;
            var entitlement = Record("employee", "workforce");
            File.WriteAllText(path, JsonConvert.SerializeObject(new[] { entitlement }));
            var store = new JsonEntitlementStore(path);
            var before = AdmissionPolicy.Evaluate(config, Principal(Workforce), store.Read(), Now).Allowed;
            entitlement.Status = "disabled";
            File.WriteAllText(path, JsonConvert.SerializeObject(new[] { entitlement }));
            return before && !AdmissionPolicy.Evaluate(config, Principal(Workforce), store.Read(), Now).Allowed;
        }
        finally { File.Delete(path); }
    }
}
