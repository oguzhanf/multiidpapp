using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Mvc;
using Microsoft.Owin.Security;
using MultiIdp.Net48;

internal static class RegistrationFlowTests
{
    private const string Workforce = "11111111-1111-1111-1111-111111111111";
    private const string External = "22222222-2222-2222-2222-222222222222";
    private const string SponsorId = "33333333-3333-3333-3333-333333333333";
    private const string RecipientId = "44444444-4444-4444-4444-444444444444";
    private static readonly DateTimeOffset Now = new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero);

    internal static void Run(Action<string, Func<bool>> check)
    {
        check("registration callback denies pending recipient without protected invite", () => {
            using (var f = new Fixture()) return Denied(() => RegistrationSignInPolicy.Validate(f.Config, f.Recipient(), new AuthenticationProperties(), "external", new[] { f.Parent }, f.Store, Now));
        });
        check("registration callback valid invitation allows narrowly scoped cookie", () => {
            using (var f = new Fixture()) {
                var identity = f.Recipient(); var properties = f.Properties(); RegistrationSignInPolicy.Validate(f.Config, identity, properties, "external", new[] { f.Parent }, f.Store, Now);
                return RegistrationSignInPolicy.IsRegistrationOnly(new ClaimsPrincipal(identity)) && properties.RedirectUri == "/Registration/Complete" && properties.ExpiresUtc <= Now.AddMinutes(20) && f.Store.ReadApprovedEntitlements().Length == 0;
            }
        });
        check("registration callback exact signed persona still required", () => {
            using (var f = new Fixture()) { var identity = f.Recipient(); identity.RemoveClaim(identity.FindFirst("roles")); identity.AddClaim(new Claim("roles", "External")); return Denied(() => RegistrationSignInPolicy.Validate(f.Config, identity, f.Properties(), "external", new[] { f.Parent }, f.Store, Now)); }
        });
        check("registration callback wrong bound account rejected", () => {
            using (var f = new Fixture()) { var identity = f.Recipient(); identity.RemoveClaim(identity.FindFirst("oid")); identity.AddClaim(new Claim("oid", SponsorId)); return Denied(() => RegistrationSignInPolicy.Validate(f.Config, identity, f.Properties(), "external", new[] { f.Parent }, f.Store, Now)); }
        });
        check("registration JWT-supplied pending flag cannot authorize cookie", () => {
            using (var f = new Fixture()) { var identity = f.Recipient(); identity.AddClaim(new Claim("registration_only", "true")); identity.AddClaim(new Claim("registration_token", f.Issue.Token)); return Denied(() => RegistrationSignInPolicy.Validate(f.Config, identity, new AuthenticationProperties(), "external", new[] { f.Parent }, f.Store, Now)); }
        });
        check("registration callback removes incoming owned flags from normal employee", () => {
            using (var f = new Fixture()) { var identity = f.Employee(); identity.AddClaim(new Claim("registration_only", "true")); identity.AddClaim(new Claim("identity_source", "external"));
                RegistrationSignInPolicy.Validate(f.Config, identity, new AuthenticationProperties(), "workforce", new[] { f.Parent }, f.Store, Now);
                return !RegistrationSignInPolicy.IsRegistrationOnly(new ClaimsPrincipal(identity)) && identity.FindAll("identity_source").Single().Value == "workforce" && identity.FindAll("subject_key").Single().Value == Workforce + ":" + SponsorId;
            }
        });
        check("registration-only cookie never authorizes benefit admission", () => {
            using (var f = new Fixture()) { var identity = f.Recipient(); RegistrationSignInPolicy.Validate(f.Config, identity, f.Properties(), "external", new[] { f.Parent }, f.Store, Now);
                var principal = new ClaimsPrincipal(identity);
                var approval = f.Store.Redeem(f.Config, f.Issue.Token, principal, new[] { f.Parent }, new[] { "Employee" }, Now);
                return AdmissionPolicy.Evaluate(f.Config, principal, new[] { f.Parent, approval }, Now).Allowed && !RegistrationSignInPolicy.EvaluateApplicationAccess(f.Config, principal, new[] { f.Parent, approval }, Now).Allowed; }
        });
        check("registration fresh normal sign-in permits committed approval", () => {
            using (var f = new Fixture()) { var pending = f.Recipient(); RegistrationSignInPolicy.Validate(f.Config, pending, f.Properties(), "external", new[] { f.Parent }, f.Store, Now);
                var approval = f.Store.Redeem(f.Config, f.Issue.Token, new ClaimsPrincipal(pending), new[] { f.Parent }, new[] { "Employee" }, Now);
                var normal = f.Recipient(); RegistrationSignInPolicy.Validate(f.Config, normal, new AuthenticationProperties(), "external", new[] { f.Parent, approval }, f.Store, Now);
                return !RegistrationSignInPolicy.IsRegistrationOnly(new ClaimsPrincipal(normal)) && RegistrationSignInPolicy.EvaluateApplicationAccess(f.Config, new ClaimsPrincipal(normal), new[] { f.Parent, approval }, Now).Allowed; }
        });
        check("registration callback expired invitation cannot issue pending cookie", () => {
            using (var f = new Fixture()) return Denied(() => RegistrationSignInPolicy.Validate(f.Config, f.Recipient(), f.Properties(), "external", new[] { f.Parent }, f.Store, Now.AddHours(24)));
        });
        check("registration callback retains issuer audience binding", () => {
            using (var f = new Fixture()) { var identity = f.Recipient(); identity.RemoveClaim(identity.FindFirst("aud")); identity.AddClaim(new Claim("aud", f.Config.Workforce.ClientId)); return Denied(() => RegistrationSignInPolicy.Validate(f.Config, identity, f.Properties(), "external", new[] { f.Parent }, f.Store, Now)); }
        });
        check("registration mutation endpoints require POST and antiforgery", () => {
            return new[] { "Begin", "Invite", "CompletePost", "CancelUnsent" }.All(name => {
                var method = typeof(RegistrationController).GetMethods().Single(m => m.Name == name);
                return method.GetCustomAttributes(typeof(HttpPostAttribute), true).Length == 1 && method.GetCustomAttributes(typeof(ValidateAntiForgeryTokenAttribute), true).Length == 1;
            });
        });
    }
    private static bool Denied(Action action) { try { action(); return false; } catch (Microsoft.IdentityModel.Tokens.SecurityTokenValidationException) { return true; } }
    private sealed class Fixture : IDisposable
    {
        private readonly string directory = Path.Combine(Path.GetTempPath(), "net48-registration-flow-" + Guid.NewGuid());
        internal readonly AppConfiguration Config = new AppConfiguration {
            AppId = "sampleapp01", EmployeeDomains = new[] { "employee.test" }, ApprovedPartnerDomains = new string[0],
            Workforce = new TenantConfiguration { TenantId = Workforce, ClientId = "66666666-6666-6666-6666-666666666666", Issuer = "https://login.microsoftonline.com/" + Workforce + "/v2.0" },
            External = new TenantConfiguration { TenantId = External, ClientId = "77777777-7777-7777-7777-777777777777", Issuer = "https://example.ciamlogin.com/" + External + "/v2.0" }
        };
        internal readonly Entitlement Parent = new Entitlement { AppId = "sampleapp01", TenantId = Workforce, ObjectId = SponsorId, Persona = "employee", Source = "workforce", Status = "approved", BenefitEligible = true, ExpiresUtc = Now.AddDays(5) };
        internal readonly JsonInvitationStore Store;
        internal readonly IssuedInvitation Issue;
        internal Fixture()
        {
            Directory.CreateDirectory(directory); Store = new JsonInvitationStore(Path.Combine(directory, "state.json"));
            Issue = Store.Create(Config, new ClaimsPrincipal(Employee()), new[] { Parent }, RegistrationKind.Dependent, "child@personal.test", Now, Now.AddDays(5));
            Store.BindIdentity(Config, Issue.Invitation.Id, new InvitationIdentityBinding { TenantId = External, ObjectId = RecipientId }, Now);
        }
        internal AuthenticationProperties Properties() { var properties = new AuthenticationProperties(); properties.Dictionary["registration_token"] = Issue.Token; return properties; }
        internal ClaimsIdentity Recipient() => Identity(External, RecipientId, Config.External, "Dependent");
        internal ClaimsIdentity Employee() { var identity = Identity(Workforce, SponsorId, Config.Workforce, "Employee"); identity.AddClaim(new Claim("identity_source", "workforce")); return identity; }
        private static ClaimsIdentity Identity(string tenant, string oid, TenantConfiguration config, string role) => new ClaimsIdentity(new[] { new Claim("tid", tenant), new Claim("oid", oid), new Claim("iss", config.Issuer), new Claim("aud", config.ClientId), new Claim("roles", role) }, "validated-token");
        public void Dispose() => Directory.Delete(directory, true);
    }
}
