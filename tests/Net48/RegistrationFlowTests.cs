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
        check("registration callback denies unsent pending recipient without protected invite", () => {
            using (var f = new Fixture()) return Denied(() => RegistrationSignInPolicy.Validate(f.Config, f.Recipient(), new AuthenticationProperties(), "external", new[] { f.Parent }, f.Store, Now));
        });
        check("ordinary dependent sign-in resumes only restricted sent registration", () => {
            using (var f = new Fixture()) {
                f.Deliver(); var identity = f.Recipient(); var properties = new AuthenticationProperties();
                RegistrationSignInPolicy.Validate(f.Config, identity, properties, "external", new[] { f.Parent }, f.Store, Now);
                string invitationId;
                return properties.Dictionary.TryGetValue(RegistrationSignInPolicy.InvitationIdProperty, out invitationId) && invitationId == f.Issue.Invitation.Id
                    && !properties.Dictionary.ContainsKey(RegistrationSignInPolicy.TokenProperty)
                    && RegistrationSignInPolicy.IsRegistrationOnly(new ClaimsPrincipal(identity)) && properties.RedirectUri == "/Registration/Complete"
                    && properties.IsPersistent == false && properties.AllowRefresh == false && properties.ExpiresUtc <= Now.AddMinutes(20)
                    && f.Store.ReadApprovedEntitlements().Length == 0
                    && !RegistrationSignInPolicy.EvaluateApplicationAccess(f.Config, new ClaimsPrincipal(identity), new[] { f.Parent }, Now).Allowed;
            }
        });
        check("ordinary dependent resume confirms once then requires fresh normal sign-in", () => {
            using (var f = new Fixture()) {
                f.Deliver(); var pending = f.Recipient(); var properties = new AuthenticationProperties();
                RegistrationSignInPolicy.Validate(f.Config, pending, properties, "external", new[] { f.Parent }, f.Store, Now);
                var approval = f.Store.RedeemForRecipient(f.Config, properties.Dictionary[RegistrationSignInPolicy.InvitationIdProperty], new ClaimsPrincipal(pending), new[] { f.Parent }, new[] { "Employee" }, Now);
                var approved = new[] { f.Parent, approval };
                if (RegistrationSignInPolicy.EvaluateApplicationAccess(f.Config, new ClaimsPrincipal(pending), approved, Now).Allowed || !StoreDenied(() => f.Store.Preview(f.Config, f.Issue.Token, Now))
                    || !StoreDenied(() => f.Store.RedeemForRecipient(f.Config, f.Issue.Invitation.Id, new ClaimsPrincipal(pending), approved, new[] { "Employee" }, Now))) return false;
                var normal = f.Recipient(); RegistrationSignInPolicy.Validate(f.Config, normal, new AuthenticationProperties(), "external", approved, f.Store, Now);
                return !RegistrationSignInPolicy.IsRegistrationOnly(new ClaimsPrincipal(normal))
                    && RegistrationSignInPolicy.EvaluateApplicationAccess(f.Config, new ClaimsPrincipal(normal), approved, Now).Allowed && f.Store.ReadApprovedEntitlements().Length == 1;
            }
        });
        check("ordinary resume never substitutes for an invalid original invitation token", () => {
            using (var f = new Fixture()) {
                f.Deliver(); var properties = f.Properties(); properties.Dictionary[RegistrationSignInPolicy.TokenProperty] = new string('A', 43);
                return Denied(() => RegistrationSignInPolicy.Validate(f.Config, f.Recipient(), properties, "external", new[] { f.Parent }, f.Store, Now)) && f.Store.ReadApprovedEntitlements().Length == 0;
            }
        });
        foreach (var claim in new[] { "oid", "tid", "iss", "aud", "roles" }) {
            var changedClaim = claim;
            check("ordinary resume rejects wrong signed " + changedClaim, () => {
                using (var f = new Fixture()) {
                    f.Deliver(); var identity = f.Recipient(); ReplaceClaim(identity, changedClaim, changedClaim == "roles" ? "External" : changedClaim == "iss" ? "https://attacker.test/v2.0" : SponsorId);
                    return Denied(() => RegistrationSignInPolicy.Validate(f.Config, identity, new AuthenticationProperties(), "external", new[] { f.Parent }, f.Store, Now)) && f.Store.ReadApprovedEntitlements().Length == 0;
                }
            });
        }
        check("ordinary resume cannot authenticate external invite through workforce provider", () => {
            using (var f = new Fixture()) { f.Deliver(); return Denied(() => RegistrationSignInPolicy.Validate(f.Config, f.Recipient(), new AuthenticationProperties(), "workforce", new[] { f.Parent }, f.Store, Now)); }
        });
        check("ordinary resume does not cross application boundaries", () => {
            using (var f = new Fixture()) { f.Deliver(); f.Config.AppId = "sampleapp02"; return Denied(() => RegistrationSignInPolicy.Validate(f.Config, f.Recipient(), new AuthenticationProperties(), "external", new[] { f.Parent }, f.Store, Now)); }
        });
        foreach (var status in new[] { "queued", "pending", "failed" }) {
            var deliveryStatus = status;
            check("ordinary resume rejects " + deliveryStatus + " invitation delivery", () => {
                using (var f = new Fixture()) {
                    f.Store.RecordDelivery(f.Config, f.Issue.Invitation.Id, deliveryStatus, SponsorId, Now);
                    return Denied(() => RegistrationSignInPolicy.Validate(f.Config, f.Recipient(), new AuthenticationProperties(), "external", new[] { f.Parent }, f.Store, Now));
                }
            });
        }
        check("ordinary resume rejects canceled invitation", () => {
            using (var f = new Fixture()) { f.Store.CancelBeforeDelivery(f.Config, f.Issue.Invitation.Id, Now); return Denied(() => RegistrationSignInPolicy.Validate(f.Config, f.Recipient(), new AuthenticationProperties(), "external", new[] { f.Parent }, f.Store, Now)); }
        });
        check("ordinary resume rejects expired sent invitation", () => {
            using (var f = new Fixture()) { f.Deliver(); return Denied(() => RegistrationSignInPolicy.Validate(f.Config, f.Recipient(), new AuthenticationProperties(), "external", new[] { f.Parent }, f.Store, Now.AddHours(24))); }
        });
        check("ordinary resume rejects ambiguous sent invitations bound to one identity", () => {
            using (var f = new Fixture()) {
                f.Deliver(); var second = f.Store.Create(f.Config, new ClaimsPrincipal(f.Employee()), new[] { f.Parent }, RegistrationKind.Dependent, "other@personal.test", Now, Now.AddDays(5));
                f.Store.BindIdentity(f.Config, second.Invitation.Id, new InvitationIdentityBinding { TenantId = External, ObjectId = RecipientId }, Now);
                f.Store.RecordDelivery(f.Config, second.Invitation.Id, "sent", RecipientId, Now);
                return Denied(() => RegistrationSignInPolicy.Validate(f.Config, f.Recipient(), new AuthenticationProperties(), "external", new[] { f.Parent }, f.Store, Now)) && f.Store.ReadApprovedEntitlements().Length == 0;
            }
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
    private static bool StoreDenied(Action action) { try { action(); return false; } catch (RegistrationException) { return true; } }
    private static void ReplaceClaim(ClaimsIdentity identity, string type, string value) { foreach (var claim in identity.FindAll(type).ToArray()) identity.RemoveClaim(claim); identity.AddClaim(new Claim(type, value)); }
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
        internal void Deliver() => Store.RecordDelivery(Config, Issue.Invitation.Id, "sent", SponsorId, Now);
        internal ClaimsIdentity Recipient() => Identity(External, RecipientId, Config.External, "Dependent");
        internal ClaimsIdentity Employee() { var identity = Identity(Workforce, SponsorId, Config.Workforce, "Employee"); identity.AddClaim(new Claim("identity_source", "workforce")); return identity; }
        private static ClaimsIdentity Identity(string tenant, string oid, TenantConfiguration config, string role) => new ClaimsIdentity(new[] { new Claim("tid", tenant), new Claim("oid", oid), new Claim("iss", config.Issuer), new Claim("aud", config.ClientId), new Claim("roles", role) }, "validated-token");
        public void Dispose() => Directory.Delete(directory, true);
    }
}
