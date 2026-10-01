using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Reflection;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using MultiIdp.Net48;

internal static class RegistrationTests
{
    private const string Workforce = "11111111-1111-1111-1111-111111111111";
    private const string External = "22222222-2222-2222-2222-222222222222";
    private const string SponsorId = "33333333-3333-3333-3333-333333333333";
    private const string RecipientId = "44444444-4444-4444-4444-444444444444";
    private const string OtherId = "55555555-5555-5555-5555-555555555555";
    private const string HomeTenant = "88888888-8888-8888-8888-888888888888";
    private static readonly DateTimeOffset Now = new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero);

    internal static void Run(Action<string, Func<bool>> check)
    {
        check("registration app01 current employee can invite dependent", () => Authorized("sampleapp01", RegistrationKind.Dependent, new[] { "Employee" }));
        check("registration app01 cannot create business invitations", () => !Authorized("sampleapp01", RegistrationKind.ExternalBusiness, new[] { "Employee", "admin" }));
        check("registration app02 Employee alone cannot invite dependent", () => !Authorized("sampleapp02", RegistrationKind.Dependent, new[] { "Employee" }));
        check("registration app02 dependentRegistrant can invite dependent", () => Authorized("sampleapp02", RegistrationKind.Dependent, new[] { "Employee", "dependentRegistrant" }));
        check("registration app02 admin can invite dependent", () => Authorized("sampleapp02", RegistrationKind.Dependent, new[] { "Employee", "admin" }));
        check("registration role names are case sensitive", () => !Authorized("sampleapp02", RegistrationKind.Dependent, new[] { "Employee", "Admin" }));
        check("registration dependentRegistrant cannot invite business", () => !Authorized("sampleapp02", RegistrationKind.ExternalBusiness, new[] { "Employee", "dependentRegistrant" }));
        check("registration app02 admin employee can invite business", () => Authorized("sampleapp02", RegistrationKind.ExternalBusiness, new[] { "Employee", "admin" }));
        check("registration unsigned or absent Employee role denies", () => !Authorized("sampleapp01", RegistrationKind.Dependent, new[] { "admin" }));
        check("registration revoked employee cannot sponsor", () => !Authorized("sampleapp01", RegistrationKind.Dependent, new[] { "Employee" }, e => e.Status = "disabled"));
        check("registration employee needs benefit approval for dependent", () => !Authorized("sampleapp01", RegistrationKind.Dependent, new[] { "Employee" }, e => e.BenefitEligible = false));
        check("registration external employee identity cannot sponsor", () => {
            var config = Config("sampleapp01"); var parent = Parent(config); parent.Source = "external"; parent.TenantId = External;
            return !RegistrationPolicy.Authorize(config, Principal(config, External, SponsorId, "external", "Employee"), new[] { parent }, RegistrationKind.Dependent, Now).Allowed;
        });
        check("registration partner with admin cannot sponsor dependent", () => {
            var config = Config("sampleapp02"); var partner = Parent(config); partner.Persona = "partner"; partner.HomeTenantId = HomeTenant; partner.OrganizationVerifiedUtc = Now.AddDays(-1);
            var principal = Principal(config, Workforce, SponsorId, "workforce", "Partner", "Employee", "admin"); principal.Identities.First().AddClaim(new Claim("idp", "https://sts.windows.net/" + HomeTenant + "/"));
            return !RegistrationPolicy.Authorize(config, principal, new[] { partner }, RegistrationKind.Dependent, Now).Allowed;
        });
        check("registration duplicate sponsor governance denies", () => {
            var config = Config("sampleapp01"); var parent = Parent(config);
            return !RegistrationPolicy.Authorize(config, Sponsor(config), new[] { parent, Parent(config) }, RegistrationKind.Dependent, Now).Allowed;
        });
        check("registration normalizes recipient and retains no raw invitation token", () => {
            using (var fixture = new Fixture()) {
                var issue = fixture.Create("  Child@Personal.test  ");
                var json = File.ReadAllText(fixture.Path);
                return issue.Invitation.RecipientEmail == "child@personal.test" && issue.Token.Length == 43 && !json.Contains(issue.Token) && json.Contains("tokenHash");
            }
        });
        check("registration display name and malformed recipient rejected", () => {
            using (var fixture = new Fixture()) return Denied(() => fixture.Create("Child <child@personal.test>")) && Denied(() => fixture.Create("invalid"));
        });
        check("registration empty recipient gives controlled denial", () => {
            using (var fixture = new Fixture()) return Denied(() => fixture.Create(""));
        });
        check("registration recipient cannot inject email headers", () => {
            using (var fixture = new Fixture()) return Denied(() => fixture.Create("child@personal.test\r\n"));
        });
        check("registration employee address cannot become personal dependent invite", () => {
            using (var fixture = new Fixture()) return Denied(() => fixture.Create("child@employee.test"));
        });
        check("registration link cannot be previewed before trusted identity binding", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Create(); return Denied(() => fixture.Store.Preview(fixture.Config, issue.Token, Now)); }
        });
        check("registration identity binding is immutable with exact idempotent retry", () => {
            using (var fixture = new Fixture()) {
                var issue = fixture.Ready(); fixture.Store.BindIdentity(fixture.Config, issue.Invitation.Id, fixture.Binding(), Now);
                var changed = fixture.Binding(); changed.ObjectId = OtherId;
                return Denied(() => fixture.Store.BindIdentity(fixture.Config, issue.Invitation.Id, changed, Now));
            }
        });
        check("registration binding to wrong tenant rejected", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Create(); var binding = fixture.Binding(); binding.TenantId = Workforce;
                return Denied(() => fixture.Store.BindIdentity(fixture.Config, issue.Invitation.Id, binding, Now)); }
        });
        check("registration GET preview does not consume or create approval", () => {
            using (var fixture = new Fixture()) {
                var issue = fixture.Ready(); fixture.Store.Preview(fixture.Config, issue.Token, Now); fixture.Store.Preview(fixture.Config, issue.Token, Now);
                if (fixture.Store.ReadApprovedEntitlements().Length != 0) return false;
                var entitlement = fixture.Redeem(issue.Token);
                return entitlement.Persona == "dependent" && fixture.Store.ReadApprovedEntitlements().Length == 1;
            }
        });
        check("recipient preview matches signed identity without exposing invitation token", () => {
            using (var fixture = new Fixture()) {
                var issue = fixture.Sent(); var before = File.ReadAllText(fixture.Path);
                var preview = fixture.Store.PreviewForRecipient(fixture.Config, fixture.Recipient(), Now);
                preview.RecipientEmail = "changed@attacker.test";
                var bound = fixture.Store.PreviewForRecipient(fixture.Config, fixture.Recipient(), Now, issue.Invitation.Id);
                return bound.Id == issue.Invitation.Id && bound.RecipientEmail == "child@personal.test"
                    && fixture.Store.ReadApprovedEntitlements().Length == 0 && File.ReadAllText(fixture.Path) == before && !before.Contains(issue.Token);
            }
        });
        check("recipient preview rejects absent wrong app and unknown invitation id", () => {
            using (var fixture = new Fixture()) {
                var issue = fixture.Sent();
                return Denied(() => fixture.Store.PreviewForRecipient(fixture.Config, Principal(fixture.Config, External, OtherId, "external", "Dependent"), Now))
                    && Denied(() => fixture.Store.PreviewForRecipient(Config("sampleapp02"), fixture.Recipient(), Now))
                    && Denied(() => fixture.Store.PreviewForRecipient(fixture.Config, fixture.Recipient(), Now, OtherId))
                    && Denied(() => fixture.Store.PreviewForRecipient(fixture.Config, fixture.Recipient(), Now.AddHours(24), issue.Invitation.Id));
            }
        });
        foreach (var claim in new[] { "tid", "oid", "identity_source", "iss", "aud", "roles" }) {
            var changedClaim = claim;
            check("recipient preview and redemption reject wrong signed " + changedClaim, () => {
                using (var fixture = new Fixture()) {
                    var issue = fixture.Sent(); var recipient = fixture.Recipient();
                    ReplaceClaim(recipient, changedClaim, changedClaim == "identity_source" ? "workforce" : changedClaim == "roles" ? "External" : changedClaim == "iss" ? "https://attacker.test/v2.0" : OtherId);
                    return Denied(() => fixture.Store.PreviewForRecipient(fixture.Config, recipient, Now, issue.Invitation.Id))
                        && Denied(() => fixture.Store.RedeemForRecipient(fixture.Config, issue.Invitation.Id, recipient, new[] { fixture.Parent }, new[] { "Employee" }, Now))
                        && fixture.Store.ReadApprovedEntitlements().Length == 0 && fixture.Store.Preview(fixture.Config, issue.Token, Now).Status == "ready";
                }
            });
        }
        check("recipient preview rejects duplicate signed identity claims", () => {
            using (var fixture = new Fixture()) {
                fixture.Sent(); var recipient = fixture.Recipient(); recipient.Identities.First().AddClaim(new Claim("oid", RecipientId));
                return Denied(() => fixture.Store.PreviewForRecipient(fixture.Config, recipient, Now));
            }
        });
        check("recipient preview denies unsigned identity and email-only identity match", () => {
            using (var fixture = new Fixture()) {
                var issue = fixture.Sent(); var wrong = Principal(fixture.Config, External, OtherId, "external", "Dependent"); wrong.Identities.First().AddClaim(new Claim("email", issue.Invitation.RecipientEmail));
                return Denied(() => fixture.Store.PreviewForRecipient(fixture.Config, wrong, Now))
                    && Denied(() => fixture.Store.PreviewForRecipient(fixture.Config, new ClaimsPrincipal(new ClaimsIdentity(fixture.Recipient().Claims)), Now));
            }
        });
        check("recipient preview refuses ambiguous current invitations for one directory identity", () => {
            using (var fixture = new Fixture()) {
                fixture.Sent(); fixture.Sent("another@personal.test");
                return Denied(() => fixture.Store.PreviewForRecipient(fixture.Config, fixture.Recipient(), Now)) && fixture.Store.ReadApprovedEntitlements().Length == 0;
            }
        });
        foreach (var status in new[] { "not_sent", "queued", "pending", "failed" }) {
            var deliveryStatus = status;
            check("recipient preview and redemption reject " + deliveryStatus + " invitation delivery", () => {
                using (var fixture = new Fixture()) {
                    var issue = fixture.Ready();
                    if (deliveryStatus != "not_sent") fixture.Store.RecordDelivery(fixture.Config, issue.Invitation.Id, deliveryStatus, OtherId, Now);
                    return Denied(() => fixture.Store.PreviewForRecipient(fixture.Config, fixture.Recipient(), Now, issue.Invitation.Id))
                        && Denied(() => fixture.Store.RedeemForRecipient(fixture.Config, issue.Invitation.Id, fixture.Recipient(), new[] { fixture.Parent }, new[] { "Employee" }, Now))
                        && fixture.Store.ReadApprovedEntitlements().Length == 0;
                }
            });
        }
        check("recipient preview ignores canceled invitation rather than reactivating it", () => {
            using (var fixture = new Fixture()) {
                var issue = fixture.Ready(); fixture.Store.CancelBeforeDelivery(fixture.Config, issue.Invitation.Id, Now);
                return Denied(() => fixture.Store.PreviewForRecipient(fixture.Config, fixture.Recipient(), Now, issue.Invitation.Id));
            }
        });
        check("recipient redemption is exact app scoped and cannot select another invitation id", () => {
            using (var fixture = new Fixture()) {
                var issue = fixture.Sent();
                return Denied(() => fixture.Store.RedeemForRecipient(fixture.Config, OtherId, fixture.Recipient(), new[] { fixture.Parent }, new[] { "Employee" }, Now))
                    && Denied(() => fixture.Store.RedeemForRecipient(Config("sampleapp02"), issue.Invitation.Id, fixture.Recipient(), new[] { fixture.Parent }, new[] { "Employee", "admin" }, Now))
                    && fixture.Store.ReadApprovedEntitlements().Length == 0;
            }
        });
        check("recipient redemption does not overwrite a revoked application approval", () => {
            using (var fixture = new Fixture()) {
                var issue = fixture.Sent(); var revoked = new Entitlement { AppId = fixture.Config.AppId, TenantId = External, ObjectId = RecipientId, Source = "external", Persona = "dependent", Status = "disabled" };
                return Denied(() => fixture.Store.RedeemForRecipient(fixture.Config, issue.Invitation.Id, fixture.Recipient(), new[] { fixture.Parent, revoked }, new[] { "Employee" }, Now))
                    && fixture.Store.ReadApprovedEntitlements().Length == 0;
            }
        });
        check("recipient redemption rechecks current sponsor approval and directory roles", () => {
            using (var fixture = new Fixture()) {
                var issue = fixture.Sent(); fixture.Parent.Status = "disabled";
                if (!Denied(() => fixture.Store.RedeemForRecipient(fixture.Config, issue.Invitation.Id, fixture.Recipient(), new[] { fixture.Parent }, new[] { "Employee" }, Now))) return false;
                fixture.Parent.Status = "approved";
                return Denied(() => fixture.Store.RedeemForRecipient(fixture.Config, issue.Invitation.Id, fixture.Recipient(), new[] { fixture.Parent }, new[] { "admin" }, Now))
                    && fixture.Store.ReadApprovedEntitlements().Length == 0;
            }
        });
        check("recipient app02 redemption requires current registration privilege", () => {
            using (var fixture = new Fixture("sampleapp02")) {
                var issue = fixture.Sent();
                return Denied(() => fixture.Store.RedeemForRecipient(fixture.Config, issue.Invitation.Id, fixture.Recipient(), new[] { fixture.Parent }, new[] { "Employee" }, Now))
                    && fixture.Store.ReadApprovedEntitlements().Length == 0;
            }
        });
        check("recipient app02 personal business registration retains External persona", () => {
            using (var fixture = new Fixture("sampleapp02", RegistrationKind.ExternalBusiness)) {
                var issue = fixture.Sent(); var recipient = fixture.Recipient();
                var preview = fixture.Store.PreviewForRecipient(fixture.Config, recipient, Now);
                var approval = fixture.Store.RedeemForRecipient(fixture.Config, issue.Invitation.Id, recipient, new[] { fixture.Parent }, new[] { "Employee", "admin" }, Now);
                return preview.Persona == "external" && approval.Persona == "external" && approval.Source == "external"
                    && AdmissionPolicy.Evaluate(fixture.Config, recipient, new[] { fixture.Parent, approval }, Now).Allowed;
            }
        });
        check("recipient organizational resume retains signed verified home issuer check", () => {
            using (var fixture = new Fixture("sampleapp02", RegistrationKind.OrganizationalPartner)) {
                var issue = fixture.Sent(); var recipient = fixture.Recipient();
                if (!Denied(() => fixture.Store.PreviewForRecipient(fixture.Config, recipient, Now))) return false;
                recipient.Identities.First().AddClaim(new Claim("idp", "live.com"));
                if (!Denied(() => fixture.Store.RedeemForRecipient(fixture.Config, issue.Invitation.Id, recipient, new[] { fixture.Parent }, new[] { "Employee", "admin" }, Now))) return false;
                ReplaceClaim(recipient, "idp", "https://sts.windows.net/" + HomeTenant + "/");
                var preview = fixture.Store.PreviewForRecipient(fixture.Config, recipient, Now);
                var approval = fixture.Store.RedeemForRecipient(fixture.Config, issue.Invitation.Id, recipient, new[] { fixture.Parent }, new[] { "Employee", "admin" }, Now);
                return preview.Persona == "partner" && approval.HomeTenantId == HomeTenant
                    && AdmissionPolicy.Evaluate(fixture.Config, recipient, new[] { fixture.Parent, approval }, Now).Allowed;
            }
        });
        check("recipient redemption and original bearer link share one-use approval commit", () => {
            using (var fixture = new Fixture()) {
                var issue = fixture.Sent(); var child = fixture.Store.RedeemForRecipient(fixture.Config, issue.Invitation.Id, fixture.Recipient(), new[] { fixture.Parent }, new[] { "Employee" }, Now);
                return child.LinkedEmployeeTenantId == Workforce && child.LinkedEmployeeObjectId == SponsorId && child.RelationshipVerified && child.BenefitEligible
                    && Denied(() => fixture.Redeem(issue.Token))
                    && Denied(() => fixture.Store.PreviewForRecipient(fixture.Config, fixture.Recipient(), Now, issue.Invitation.Id))
                    && Denied(() => fixture.Store.RedeemForRecipient(fixture.Config, issue.Invitation.Id, fixture.Recipient(), new[] { fixture.Parent }, new[] { "Employee" }, Now))
                    && fixture.Store.ReadApprovedEntitlements().Length == 1;
            }
        });
        check("concurrent recipient redemption creates exactly one application approval", () => {
            using (var fixture = new Fixture()) {
                var issue = fixture.Sent();
                var attempts = Enumerable.Range(0, 8).Select(_ => Task.Run(() => {
                    try { fixture.Store.RedeemForRecipient(fixture.Config, issue.Invitation.Id, fixture.Recipient(), new[] { fixture.Parent }, new[] { "Employee" }, Now); return true; }
                    catch (RegistrationException) { return false; }
                })).ToArray();
                Task.WaitAll(attempts);
                return attempts.Count(t => t.Result) == 1 && fixture.Store.ReadApprovedEntitlements().Length == 1;
            }
        });
        check("registration invitation token tampering rejected", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); var altered = (issue.Token[0] == 'A' ? "B" : "A") + issue.Token.Substring(1); return Denied(() => fixture.Redeem(altered)); }
        });
        check("registration wrong app link cannot be previewed or redeemed", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); var other = Config("sampleapp02");
                return Denied(() => fixture.Store.Preview(other, issue.Token, Now)) && Denied(() => fixture.Store.Redeem(other, issue.Token, fixture.Recipient(), new[] { fixture.Parent }, new[] { "Employee", "admin" }, Now)); }
        });
        check("registration invitation expires exactly at 24 hour boundary", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); return Denied(() => fixture.Store.Preview(fixture.Config, issue.Token, Now.AddHours(24))); }
        });
        check("registration authenticated wrong recipient object rejected", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); return Denied(() => fixture.Redeem(issue.Token, Principal(fixture.Config, External, OtherId, "external", "Dependent"))); }
        });
        check("registration authenticated wrong recipient tenant rejected", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); return Denied(() => fixture.Redeem(issue.Token, Principal(fixture.Config, Workforce, RecipientId, "workforce", "Dependent"))); }
        });
        check("registration pending recipient must retain persona role", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); return Denied(() => fixture.Redeem(issue.Token, Principal(fixture.Config, External, RecipientId, "external", "External"))); }
        });
        check("registration receiver issuer and audience validation retained", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); var principal = fixture.Recipient(); var identity = principal.Identities.First(); identity.RemoveClaim(identity.FindFirst("iss")); identity.AddClaim(new Claim("iss", "https://attacker.test/" + External + "/v2.0"));
                if (!Denied(() => fixture.Redeem(issue.Token, principal))) return false;
                principal = fixture.Recipient(); identity = principal.Identities.First(); identity.RemoveClaim(identity.FindFirst("aud")); identity.AddClaim(new Claim("aud", OtherId)); return Denied(() => fixture.Redeem(issue.Token, principal)); }
        });
        check("registration duplicate signed identity claims denied", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); var principal = fixture.Recipient(); principal.Identities.First().AddClaim(new Claim("oid", RecipientId)); return Denied(() => fixture.Redeem(issue.Token, principal)); }
        });
        check("registration email match cannot substitute for bound directory identity", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); var principal = Principal(fixture.Config, External, OtherId, "external", "Dependent"); principal.Identities.First().AddClaim(new Claim("email", issue.Invitation.RecipientEmail)); return Denied(() => fixture.Redeem(issue.Token, principal)); }
        });
        check("registration sponsor revocation before redemption denies", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); fixture.Parent.Status = "disabled"; return Denied(() => fixture.Redeem(issue.Token)); }
        });
        check("registration sponsor expiry before redemption denies", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); fixture.Parent.ExpiresUtc = Now; return Denied(() => fixture.Redeem(issue.Token)); }
        });
        check("registration benefit approval removed before redemption denies", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); fixture.Parent.BenefitEligible = false; return Denied(() => fixture.Redeem(issue.Token)); }
        });
        check("registration app02 sponsor privileged role removal denies", () => {
            using (var fixture = new Fixture("sampleapp02")) { var issue = fixture.Ready(); return Denied(() => fixture.Store.Redeem(fixture.Config, issue.Token, fixture.Recipient(), new[] { fixture.Parent }, new[] { "Employee" }, Now)); }
        });
        check("registration current sponsor Employee role removal denies", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); return Denied(() => fixture.Store.Redeem(fixture.Config, issue.Token, fixture.Recipient(), new[] { fixture.Parent }, new[] { "admin" }, Now)); }
        });
        check("registration replay rejected after approved entitlement commit", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); fixture.Redeem(issue.Token); return Denied(() => fixture.Redeem(issue.Token)) && fixture.Store.ReadApprovedEntitlements().Length == 1; }
        });
        check("registration dependent approval links exact eligible sponsor", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); var child = fixture.Redeem(issue.Token);
                return child.LinkedEmployeeTenantId == Workforce && child.LinkedEmployeeObjectId == SponsorId && child.RelationshipVerified && child.BenefitEligible && AdmissionPolicy.Evaluate(fixture.Config, fixture.Recipient(), new[] { fixture.Parent, child }, Now).Allowed; }
        });
        check("registration never overwrites preexisting recipient revocation", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); var revoked = new Entitlement { AppId = fixture.Config.AppId, TenantId = External, ObjectId = RecipientId, Source = "external", Persona = "dependent", Status = "disabled" };
                return Denied(() => fixture.Store.Redeem(fixture.Config, issue.Token, fixture.Recipient(), new[] { fixture.Parent, revoked }, new[] { "Employee", "admin" }, Now)); }
        });
        check("registration generated approval expiry respects sponsor and PoC end", () => {
            using (var fixture = new Fixture()) { fixture.Parent.ExpiresUtc = Now.AddDays(3); var issue = fixture.Create(limit: Now.AddDays(2)); fixture.Store.BindIdentity(fixture.Config, issue.Invitation.Id, fixture.Binding(), Now);
                return fixture.Redeem(issue.Token).ExpiresUtc == Now.AddDays(2); }
        });
        check("registration shorter sponsor approval clamps generated entitlement", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); fixture.Parent.ExpiresUtc = Now.AddHours(2); return fixture.Redeem(issue.Token).ExpiresUtc == Now.AddHours(2); }
        });
        check("registration invite expires when shorter sponsor approval ends", () => {
            using (var fixture = new Fixture()) { fixture.Parent.ExpiresUtc = Now.AddHours(2); var issue = fixture.Ready(); return Denied(() => fixture.Store.Preview(fixture.Config, issue.Token, Now.AddHours(2))); }
        });
        check("registration configured PoC end prevents new invitation", () => {
            using (var fixture = new Fixture()) return Denied(() => fixture.Create(limit: Now));
        });
        check("registration concurrent redemption produces one approved entitlement", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); var attempts = Enumerable.Range(0, 8).Select(_ => Task.Run(() => { try { fixture.Redeem(issue.Token); return true; } catch (RegistrationException) { return false; } })).ToArray(); Task.WaitAll(attempts);
                return attempts.Count(t => t.Result) == 1 && fixture.Store.ReadApprovedEntitlements().Length == 1; }
        });
        check("registration two links for same object cannot duplicate approval", () => {
            using (var fixture = new Fixture()) { var first = fixture.Ready(); var second = fixture.Ready("another@personal.test"); fixture.Redeem(first.Token); return Denied(() => fixture.Redeem(second.Token)) && fixture.Store.ReadApprovedEntitlements().Length == 1; }
        });
        check("registration state cannot be stored in public application folder", () => Denied(() => new JsonInvitationStore(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "registration-public.json"))));
        check("registration organizational partner requires verified home binding", () => {
            using (var fixture = new Fixture("sampleapp02", RegistrationKind.OrganizationalPartner)) { var issue = fixture.Create(); var invalid = fixture.Binding(); invalid.HomeTenantId = null; return Denied(() => fixture.Store.BindIdentity(fixture.Config, issue.Invitation.Id, invalid, Now)); }
        });
        check("registration organizational partner rejects absent or foreign signed idp", () => {
            using (var fixture = new Fixture("sampleapp02", RegistrationKind.OrganizationalPartner)) { var issue = fixture.Ready(); var principal = fixture.Recipient();
                return Denied(() => fixture.Redeem(issue.Token, principal)) && Denied(() => { principal.Identities.First().AddClaim(new Claim("idp", "https://sts.windows.net/" + OtherId + "/")); fixture.Redeem(issue.Token, principal); }); }
        });
        check("registration organizational partner commits only matching signed home idp", () => {
            using (var fixture = new Fixture("sampleapp02", RegistrationKind.OrganizationalPartner)) { var issue = fixture.Ready(); var principal = fixture.Recipient(); principal.Identities.First().AddClaim(new Claim("idp", "https://sts.windows.net/" + HomeTenant + "/")); var partner = fixture.Redeem(issue.Token, principal);
                return partner.Source == "workforce" && partner.Persona == "partner" && partner.HomeTenantId == HomeTenant && AdmissionPolicy.Evaluate(fixture.Config, principal, new[] { fixture.Parent, partner }, Now).Allowed; }
        });
        check("registration personal business approval uses External persona", () => {
            using (var fixture = new Fixture("sampleapp02", RegistrationKind.ExternalBusiness)) { var issue = fixture.Ready(); var entry = fixture.Redeem(issue.Token); return entry.Source == "external" && entry.Persona == "external" && AdmissionPolicy.Evaluate(fixture.Config, fixture.Recipient(), new[] { fixture.Parent, entry }, Now).Allowed; }
        });
        check("registration partner domain is not routed from pending invitation", () => {
            using (var fixture = new Fixture("sampleapp02", RegistrationKind.OrganizationalPartner)) { fixture.Ready(); return !fixture.Store.HasApprovedPartnerDomain(fixture.Config, "partner.test", Now); }
        });
        check("registration unsuccessful signed home proof cannot promote domain", () => {
            using (var fixture = new Fixture("sampleapp02", RegistrationKind.OrganizationalPartner)) { var issue = fixture.Ready(); if (!Denied(() => fixture.Redeem(issue.Token))) return false; return !fixture.Store.HasApprovedPartnerDomain(fixture.Config, "partner.test", Now); }
        });
        check("registration redeemed verified partner domain is routed only in app02", () => {
            using (var fixture = new Fixture("sampleapp02", RegistrationKind.OrganizationalPartner)) { ApprovePartner(fixture);
                return fixture.Store.HasApprovedPartnerDomain(fixture.Config, "PARTNER.test", Now) && !fixture.Store.HasApprovedPartnerDomain(Config("sampleapp01"), "partner.test", Now) && !fixture.Store.HasApprovedPartnerDomain(fixture.Config, "sub.partner.test", Now) && !fixture.Store.HasApprovedPartnerDomain(fixture.Config, "partner.test.attacker.test", Now); }
        });
        check("registration expired partner approval cannot promote domain", () => {
            using (var fixture = new Fixture("sampleapp02", RegistrationKind.OrganizationalPartner)) { ApprovePartner(fixture); return !fixture.Store.HasApprovedPartnerDomain(fixture.Config, "partner.test", Now.AddDays(20)); }
        });
        check("registration disabled partner approval cannot promote domain", () => {
            using (var fixture = new Fixture("sampleapp02", RegistrationKind.OrganizationalPartner)) { ApprovePartner(fixture); var state = JObject.Parse(File.ReadAllText(fixture.Path)); state["approvals"][0]["status"] = "disabled"; File.WriteAllText(fixture.Path, state.ToString()); return !fixture.Store.HasApprovedPartnerDomain(fixture.Config, "partner.test", Now); }
        });
        check("registration removed partner approval cannot promote domain", () => {
            using (var fixture = new Fixture("sampleapp02", RegistrationKind.OrganizationalPartner)) { ApprovePartner(fixture); var state = JObject.Parse(File.ReadAllText(fixture.Path)); ((JArray)state["approvals"]).Clear(); File.WriteAllText(fixture.Path, state.ToString()); return !fixture.Store.HasApprovedPartnerDomain(fixture.Config, "partner.test", Now); }
        });
        check("registration inconsistent partner identity binding cannot promote domain", () => {
            using (var fixture = new Fixture("sampleapp02", RegistrationKind.OrganizationalPartner)) { ApprovePartner(fixture); var state = JObject.Parse(File.ReadAllText(fixture.Path)); state["invitations"][0]["invitation"]["homeTenantId"] = OtherId; File.WriteAllText(fixture.Path, state.ToString()); return !fixture.Store.HasApprovedPartnerDomain(fixture.Config, "partner.test", Now); }
        });
        check("registration mail send stays HTTPS on the configured ACS origin", () => {
            var root = new Uri("https://poc.communication.azure.com/");
            var target = (Uri)typeof(RegistrationRuntime).GetMethod("EmailSendUri", BindingFlags.NonPublic | BindingFlags.Static).Invoke(null, new object[] { root });
            return target.Scheme == "https" && target.Host == root.Host && target.AbsolutePath == "/emails:send" && target.Query == "?api-version=2025-09-01";
        });
        check("registration duplicate active invitation blocks repeated email send", () => {
            using (var fixture = new Fixture()) { fixture.Ready(); return Denied(() => fixture.Create("CHILD@PERSONAL.TEST")); }
        });
        check("password setup reserves a persistent cooldown without granting approval", () => {
            using (var fixture = new Fixture()) {
                var issue = fixture.Ready(); fixture.Store.ReservePasswordSetup(fixture.Config, issue.Token, Now);
                var blocked = Denied(() => fixture.Store.ReservePasswordSetup(fixture.Config, issue.Token, Now.AddSeconds(299)));
                fixture.Store.ReservePasswordSetup(fixture.Config, issue.Token, Now.AddMinutes(5));
                return blocked && fixture.Store.ReadApprovedEntitlements().Length == 0 && fixture.Store.Preview(fixture.Config, issue.Token, Now).Status == "ready";
            }
        });
        check("registration expired invitation permits a fresh secure link", () => {
            using (var fixture = new Fixture()) { var original = fixture.Ready(); var replacement = fixture.Store.Create(fixture.Config, Sponsor(fixture.Config), new[] { fixture.Parent }, RegistrationKind.Dependent, "child@personal.test", Now.AddHours(24), Now.AddDays(20)); return replacement.Token != original.Token; }
        });
        check("registration duplicate email scope is separate per application", () => {
            using (var fixture = new Fixture()) { fixture.Ready(); var config = Config("sampleapp02"); var issue = fixture.Store.Create(config, Sponsor(config), new[] { Parent(config) }, RegistrationKind.Dependent, "child@personal.test", Now, Now.AddDays(20)); return issue.Invitation.AppId == "sampleapp02"; }
        });
        check("registration concurrent issuance sends only one active recipient link", () => {
            using (var fixture = new Fixture()) { var attempts = Enumerable.Range(0, 8).Select(_ => Task.Run(() => { try { fixture.Create(); return true; } catch (RegistrationException) { return false; } })).ToArray(); Task.WaitAll(attempts); return attempts.Count(t => t.Result) == 1; }
        });
        check("registration already approved identity cannot bind another invitation", () => {
            using (var fixture = new Fixture()) { var first = fixture.Ready(); fixture.Redeem(first.Token); var second = fixture.Create("another@personal.test"); return Denied(() => fixture.Store.BindIdentity(fixture.Config, second.Invitation.Id, fixture.Binding(), Now)); }
        });
        check("registration delivery audit contains no secret bearer URL", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); fixture.Store.RecordDelivery(fixture.Config, issue.Invitation.Id, "queued", OtherId, Now); fixture.Store.RecordDelivery(fixture.Config, issue.Invitation.Id, "sent", OtherId, Now.AddMinutes(1)); var record = fixture.Store.Preview(fixture.Config, issue.Token, Now.AddMinutes(1));
                return record.EmailStatus == "sent" && record.EmailOperationId == OtherId && record.EmailRecordedUtc == Now.AddMinutes(1) && !File.ReadAllText(fixture.Path).Contains(issue.Token) && fixture.Store.ReadApprovedEntitlements().Length == 0; }
        });
        check("registration delivery audit rejects URL and arbitrary status inputs", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); return Denied(() => fixture.Store.RecordDelivery(fixture.Config, issue.Invitation.Id, "sent", "https://example.test/?token=" + issue.Token, Now)) && Denied(() => fixture.Store.RecordDelivery(fixture.Config, issue.Invitation.Id, "redeemed", OtherId, Now)); }
        });
        check("registration delivery audit cannot mutate another app invitation", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); return Denied(() => fixture.Store.RecordDelivery(Config("sampleapp02"), issue.Invitation.Id, "sent", OtherId, Now)); }
        });
        check("registration Gmail aliases are personal email domains", () => RegistrationRuntime.IsPersonalEmailDomain("gmail.com") && RegistrationRuntime.IsPersonalEmailDomain("googlemail.com") && RegistrationRuntime.IsPersonalEmailDomain("GMAIL.COM"));
        check("registration Microsoft consumer email does not assert an organization", () => new[] { "outlook.com", "hotmail.com", "live.com", "msn.com" }.All(RegistrationRuntime.IsPersonalEmailDomain));
        check("registration supported personal providers stay personal", () => new[] { "yahoo.com", "ymail.com", "aol.com", "icloud.com", "me.com", "proton.me", "protonmail.com" }.All(RegistrationRuntime.IsPersonalEmailDomain));
        check("registration consumer domain recognition rejects suffix and subdomain attacks", () => new[] { "sub.gmail.com", "gmail.com.attacker.test", "notgmail.com", "gmail.com@attacker.test", "gmail.com." }.All(domain => !RegistrationRuntime.IsPersonalEmailDomain(domain)));
        check("registration Caldova and custom organizational domains need discovery", () => !RegistrationRuntime.IsPersonalEmailDomain("caldova.onmicrosoft.com") && !RegistrationRuntime.IsPersonalEmailDomain("organization.example") && !RegistrationRuntime.IsPersonalEmailDomain(null) && !RegistrationRuntime.IsPersonalEmailDomain(""));
        check("registration Gmail resolver completes without organization discovery", () => ConsumerResolutionCompleted("gmail.com") && ConsumerResolutionCompleted("googlemail.com"));
        check("registration Gmail dependent invitation remains External source", () => {
            if (!ConsumerResolutionCompleted("gmail.com")) return false;
            using (var fixture = new Fixture()) { var issue = fixture.Create("child@gmail.com"); return issue.Invitation.Source == "external" && issue.Invitation.Persona == "dependent" && issue.Invitation.RecipientEmail == "child@gmail.com"; }
        });
        check("registration pre-email failure cancellation preserves hash and permits retry", () => {
            using (var fixture = new Fixture()) { var failed = fixture.Create(); var originalHash = (string)JObject.Parse(File.ReadAllText(fixture.Path))["invitations"][0]["tokenHash"]; fixture.Store.CancelBeforeDelivery(fixture.Config, failed.Invitation.Id, Now); var state = JObject.Parse(File.ReadAllText(fixture.Path)); var replacement = fixture.Create();
                return (string)state["invitations"][0]["invitation"]["status"] == "canceled" && (string)state["invitations"][0]["tokenHash"] == originalHash && (DateTimeOffset)state["invitations"][0]["invitation"]["canceledUtc"] == Now && (DateTimeOffset)state["invitations"][0]["invitation"]["expiresUtc"] == Now && !File.ReadAllText(fixture.Path).Contains(failed.Token) && replacement.Token != failed.Token && fixture.Store.ReadApprovedEntitlements().Length == 0 && Denied(() => fixture.Store.Preview(fixture.Config, failed.Token, Now.AddMinutes(1))); }
        });
        check("registration pre-email bound invitation can be safely canceled", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); fixture.Store.CancelBeforeDelivery(fixture.Config, issue.Invitation.Id, Now); return Denied(() => fixture.Store.Preview(fixture.Config, issue.Token, Now)) && fixture.Store.ReadApprovedEntitlements().Length == 0; }
        });
        foreach (var deliveryStatus in new[] { "queued", "sent", "pending", "failed" }) {
            var status = deliveryStatus;
            check("registration cancellation rejects email " + status + " state", () => {
                using (var fixture = new Fixture()) { var issue = fixture.Ready(); fixture.Store.RecordDelivery(fixture.Config, issue.Invitation.Id, status, status == "failed" ? null : OtherId, Now); return Denied(() => fixture.Store.CancelBeforeDelivery(fixture.Config, issue.Invitation.Id, Now)); }
            });
        }
        check("registration cancellation cannot alter a foreign app invitation", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); return Denied(() => fixture.Store.CancelBeforeDelivery(Config("sampleapp02"), issue.Invitation.Id, Now)) && fixture.Store.Preview(fixture.Config, issue.Token, Now).Status == "ready"; }
        });
        check("registration redeemed invitation cannot be canceled", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); fixture.Redeem(issue.Token); return Denied(() => fixture.Store.CancelBeforeDelivery(fixture.Config, issue.Invitation.Id, Now)) && fixture.Store.ReadApprovedEntitlements().Length == 1; }
        });
        check("registration cancellation rejects unexpected recorded email operation", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); var state = JObject.Parse(File.ReadAllText(fixture.Path)); state["invitations"][0]["invitation"]["emailOperationId"] = OtherId; File.WriteAllText(fixture.Path, state.ToString()); return Denied(() => fixture.Store.CancelBeforeDelivery(fixture.Config, issue.Invitation.Id, Now)); }
        });
        check("registration cancellation cannot remove an existing matching approval", () => {
            using (var fixture = new Fixture()) { var first = fixture.Ready(); var second = fixture.Ready("another@personal.test"); fixture.Redeem(first.Token); return Denied(() => fixture.Store.CancelBeforeDelivery(fixture.Config, second.Invitation.Id, Now)) && fixture.Store.ReadApprovedEntitlements().Length == 1; }
        });
        check("registration concurrent cancellation has one durable winner", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); var attempts = Enumerable.Range(0, 8).Select(_ => Task.Run(() => { try { fixture.Store.CancelBeforeDelivery(fixture.Config, issue.Invitation.Id, Now); return true; } catch (RegistrationException) { return false; } })).ToArray(); Task.WaitAll(attempts); return attempts.Count(t => t.Result) == 1 && fixture.Store.ReadApprovedEntitlements().Length == 0; }
        });
        check("registration cancellation racing redemption cannot contradict approval", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); var cancel = Task.Run(() => { try { fixture.Store.CancelBeforeDelivery(fixture.Config, issue.Invitation.Id, Now); return true; } catch (RegistrationException) { return false; } }); var redeem = Task.Run(() => { try { fixture.Redeem(issue.Token); return true; } catch (RegistrationException) { return false; } }); Task.WaitAll(cancel, redeem);
                var state = JObject.Parse(File.ReadAllText(fixture.Path)); return cancel.Result != redeem.Result && (string)state["invitations"][0]["invitation"]["status"] == (redeem.Result ? "redeemed" : "canceled") && fixture.Store.ReadApprovedEntitlements().Length == (redeem.Result ? 1 : 0); }
        });
        check("registration sponsor inventory cannot reveal another owner or app", () => {
            using (var fixture = new Fixture()) { fixture.Create(); var other = Principal(fixture.Config, Workforce, OtherId, "workforce", "Employee"); return fixture.Store.ReadForSponsor(fixture.Config, Sponsor(fixture.Config)).Length == 1 && fixture.Store.ReadForSponsor(fixture.Config, other).Length == 0 && fixture.Store.ReadForSponsor(Config("sampleapp02"), Sponsor(Config("sampleapp02"))).Length == 0; }
        });
        check("registration sponsor inventory rejects external or ambiguous identity", () => {
            using (var fixture = new Fixture()) { fixture.Create(); var duplicate = Sponsor(fixture.Config); duplicate.Identities.First().AddClaim(new Claim("oid", SponsorId)); return Denied(() => fixture.Store.ReadForSponsor(fixture.Config, duplicate)) && Denied(() => fixture.Store.ReadForSponsor(fixture.Config, Principal(fixture.Config, External, SponsorId, "external", "Employee"))); }
        });
        check("registration sponsor inventory clones exclude token and hash", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Create(); var rows = fixture.Store.ReadForSponsor(fixture.Config, Sponsor(fixture.Config)); var json = Newtonsoft.Json.JsonConvert.SerializeObject(rows); rows[0].RecipientEmail = "changed@attacker.test"; return !json.Contains(issue.Token) && !json.Contains("TokenHash") && fixture.Store.ReadForSponsor(fixture.Config, Sponsor(fixture.Config))[0].RecipientEmail == "child@personal.test"; }
        });
        check("registration UI cancellation cannot race into a bound invitation", () => {
            using (var fixture = new Fixture()) { var issue = fixture.Ready(); return Denied(() => fixture.Store.CancelBeforeDelivery(fixture.Config, issue.Invitation.Id, Now, true)) && fixture.Store.Preview(fixture.Config, issue.Token, Now).Status == "ready"; }
        });
        check("registration failed atomic commit preserves old state and reports no secrets", () => {
            using (var fixture = new Fixture()) {
                var issue = fixture.Create(); var original = File.ReadAllText(fixture.Path);
                using (var reader = new FileStream(fixture.Path, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                    try { fixture.Store.CancelBeforeDelivery(fixture.Config, issue.Invitation.Id, Now, true); return false; }
                    catch (RegistrationException ex) { return ex.Message.Contains("commit_replace") && ex.Message.Contains("HRESULT 0x") && !ex.Message.Contains(fixture.Path) && !ex.Message.Contains(issue.Invitation.RecipientEmail) && !ex.Message.Contains(issue.Token) && File.ReadAllText(fixture.Path) == original; }
                }
            }
        });
    }

    private static bool ConsumerResolutionCompleted(string domain)
    {
        // Only recognized consumer domains are invoked: the adapter must return before
        // its first HTTP await. Do not invoke discovery for unknown organizational domains.
        if (!RegistrationRuntime.IsPersonalEmailDomain(domain)) return false;
        var resolver = typeof(RegistrationRuntime).GetMethod("ResolveOrganizationAsync", BindingFlags.NonPublic | BindingFlags.Static);
        var resolution = (Task<string>)resolver.Invoke(null, new object[] { domain });
        return resolution.IsCompleted && resolution.GetAwaiter().GetResult() == null;
    }

    private static void ApprovePartner(Fixture fixture)
    {
        var issue = fixture.Ready(); var principal = fixture.Recipient(); principal.Identities.First().AddClaim(new Claim("idp", "https://sts.windows.net/" + HomeTenant + "/")); fixture.Redeem(issue.Token, principal);
    }

    private static bool Authorized(string app, RegistrationKind kind, string[] roles, Action<Entitlement> change = null)
    {
        var config = Config(app); var parent = Parent(config); change?.Invoke(parent);
        return RegistrationPolicy.Authorize(config, Sponsor(config, roles), new[] { parent }, kind, Now).Allowed;
    }
    private static bool Denied(Action action) { try { action(); return false; } catch (RegistrationException) { return true; } }
    private static void ReplaceClaim(ClaimsPrincipal principal, string type, string value) { var identity = principal.Identities.First(); foreach (var claim in identity.FindAll(type).ToArray()) identity.RemoveClaim(claim); identity.AddClaim(new Claim(type, value)); }
    private static AppConfiguration Config(string app) => new AppConfiguration {
        AppId = app, EmployeeDomains = new[] { "employee.test" }, ApprovedPartnerDomains = new[] { "partner.test" },
        Workforce = new TenantConfiguration { TenantId = Workforce, ClientId = "66666666-6666-6666-6666-666666666666", Issuer = "https://login.microsoftonline.com/" + Workforce + "/v2.0" },
        External = new TenantConfiguration { TenantId = External, ClientId = "77777777-7777-7777-7777-777777777777", Issuer = "https://example.ciamlogin.com/" + External + "/v2.0" }
    };
    private static Entitlement Parent(AppConfiguration config) => new Entitlement { AppId = config.AppId, TenantId = Workforce, ObjectId = SponsorId, Source = "workforce", Persona = "employee", Status = "approved", BenefitEligible = true, ExpiresUtc = Now.AddDays(30) };
    private static ClaimsPrincipal Sponsor(AppConfiguration config, string[] roles = null) => Principal(config, Workforce, SponsorId, "workforce", roles ?? new[] { "Employee", "admin" });
    private static ClaimsPrincipal Principal(AppConfiguration config, string tid, string oid, string source, params string[] roles)
    {
        var tenant = source == "workforce" ? config.Workforce : config.External;
        var claims = new List<Claim> { new Claim("tid", tid), new Claim("oid", oid), new Claim("identity_source", source), new Claim("iss", tenant.Issuer), new Claim("aud", tenant.ClientId) };
        claims.AddRange(roles.Select(role => new Claim("roles", role)));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "validated-cookie"));
    }
    private sealed class Fixture : IDisposable
    {
        private readonly string directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "net48-registration-" + Guid.NewGuid());
        internal readonly string Path;
        internal readonly AppConfiguration Config;
        internal readonly Entitlement Parent;
        internal readonly JsonInvitationStore Store;
        internal readonly RegistrationKind Kind;
        internal Fixture(string app = "sampleapp01", RegistrationKind kind = RegistrationKind.Dependent)
        {
            Directory.CreateDirectory(directory); Path = System.IO.Path.Combine(directory, "registration.json"); Config = RegistrationTests.Config(app); Parent = RegistrationTests.Parent(Config); Store = new JsonInvitationStore(Path); Kind = kind;
        }
        internal IssuedInvitation Create(string email = null, DateTimeOffset? limit = null) => Store.Create(Config, Sponsor(Config), new[] { Parent }, Kind, email ?? (Kind == RegistrationKind.OrganizationalPartner ? "user@partner.test" : "child@personal.test"), Now, limit ?? Now.AddDays(20));
        internal InvitationIdentityBinding Binding() => new InvitationIdentityBinding { TenantId = Kind == RegistrationKind.OrganizationalPartner ? Workforce : External, ObjectId = RecipientId, HomeTenantId = Kind == RegistrationKind.OrganizationalPartner ? HomeTenant : null, OrganizationVerifiedUtc = Kind == RegistrationKind.OrganizationalPartner ? (DateTimeOffset?)Now.AddMinutes(-1) : null };
        internal IssuedInvitation Ready(string email = null) { var issue = Create(email); Store.BindIdentity(Config, issue.Invitation.Id, Binding(), Now); return issue; }
        internal IssuedInvitation Sent(string email = null) { var issue = Ready(email); Store.RecordDelivery(Config, issue.Invitation.Id, "sent", OtherId, Now); return issue; }
        internal ClaimsPrincipal Recipient() => Principal(Config, Kind == RegistrationKind.OrganizationalPartner ? Workforce : External, RecipientId, Kind == RegistrationKind.OrganizationalPartner ? "workforce" : "external", Kind == RegistrationKind.Dependent ? "Dependent" : Kind == RegistrationKind.ExternalBusiness ? "External" : "Partner");
        internal Entitlement Redeem(string token, ClaimsPrincipal recipient = null) => Store.Redeem(Config, token, recipient ?? Recipient(), new[] { Parent }, new[] { "Employee", "admin" }, Now);
        public void Dispose() => Directory.Delete(directory, true);
    }
}
