using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Mail;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;

namespace MultiIdp.Net48
{
    [JsonConverter(typeof(StringEnumConverter))]
    public enum RegistrationKind { Dependent, ExternalBusiness, OrganizationalPartner }
    public sealed class RegistrationException : Exception { public RegistrationException(string message) : base(message) { } public RegistrationException(string message, Exception inner) : base(message, inner) { } }
    public sealed class RegistrationDecision { public bool Allowed { get; set; } public string Reason { get; set; } public Entitlement SponsorEntitlement { get; set; } }
    public sealed class InvitationIdentityBinding
    {
        public string TenantId { get; set; }
        public string ObjectId { get; set; }
        public string HomeTenantId { get; set; }
        public DateTimeOffset? OrganizationVerifiedUtc { get; set; }
    }
    public sealed class InvitationRecord
    {
        public string Id { get; set; }
        public string AppId { get; set; }
        public RegistrationKind Kind { get; set; }
        public string RecipientEmail { get; set; }
        public string Source { get; set; }
        public string Persona { get; set; }
        public string SponsorTenantId { get; set; }
        public string SponsorObjectId { get; set; }
        public string TenantId { get; set; }
        public string ObjectId { get; set; }
        public string HomeTenantId { get; set; }
        public DateTimeOffset? OrganizationVerifiedUtc { get; set; }
        public DateTimeOffset CreatedUtc { get; set; }
        public DateTimeOffset ExpiresUtc { get; set; }
        public DateTimeOffset ApprovalExpiresUtc { get; set; }
        public string Status { get; set; }
        public DateTimeOffset? RedeemedUtc { get; set; }
        public DateTimeOffset? CanceledUtc { get; set; }
        public string EmailStatus { get; set; }
        public string EmailOperationId { get; set; }
        public DateTimeOffset? EmailRecordedUtc { get; set; }
        public DateTimeOffset? PasswordSetupStartedUtc { get; set; }
    }
    public sealed class IssuedInvitation { public InvitationRecord Invitation { get; set; } public string Token { get; set; } }
    public static class RegistrationPolicy
    {
        // Call only with the authenticated principal from the validated application cookie.
        public static RegistrationDecision Authorize(AppConfiguration config, ClaimsPrincipal sponsor, IEnumerable<Entitlement> entries, RegistrationKind kind, DateTimeOffset now)
        {
            if (!KnownApp(config)) return Deny("Registration is unavailable for this application.");
            var admission = AdmissionPolicy.Evaluate(config, sponsor, entries, now);
            if (!admission.Allowed) return Deny("A current employee application approval is required.");
            var employee = admission.Entitlement;
            if (employee.Persona != "employee" || employee.Source != "workforce" || !SameGuid(employee.TenantId, config.Workforce.TenantId))
                return Deny("Only an approved workforce employee can sponsor registration.");
            return Gate(config, kind, employee, sponsor.FindAll("roles").Select(c => c.Value));
        }

        // Roles must be refreshed by the server's directory adapter for THIS sponsor and app.
        // A recipient's claims or an invitation-time role snapshot are not role evidence here.
        public static RegistrationDecision RecheckSponsor(AppConfiguration config, InvitationRecord invitation, IEnumerable<Entitlement> entries, IEnumerable<string> currentSponsorRoles, DateTimeOffset now)
        {
            if (!KnownApp(config) || invitation == null || invitation.AppId != config.AppId || !SameGuid(invitation.SponsorTenantId, config.Workforce.TenantId))
                return Deny("The invitation sponsor does not belong to this application.");
            var matching = (entries ?? new Entitlement[0]).Where(e => e != null && e.AppId == config.AppId && SameGuid(e.TenantId, invitation.SponsorTenantId) && SameGuid(e.ObjectId, invitation.SponsorObjectId)).ToArray();
            if (matching.Length != 1 || matching[0].Persona != "employee" || matching[0].Source != "workforce" || matching[0].Status != "approved" || matching[0].ExpiresUtc <= now)
                return Deny("The sponsor's employee approval is no longer current.");
            return Gate(config, invitation.Kind, matching[0], currentSponsorRoles);
        }

        private static RegistrationDecision Gate(AppConfiguration config, RegistrationKind kind, Entitlement employee, IEnumerable<string> roles)
        {
            var current = (roles ?? new string[0]).ToArray();
            if (!current.Contains("Employee", StringComparer.Ordinal)) return Deny("The employee directory role is required.");
            if (kind == RegistrationKind.Dependent)
            {
                if (!employee.BenefitEligible) return Deny("Current employee benefit eligibility is required.");
                if (config.AppId == "sampleapp02" && !current.Contains("admin", StringComparer.Ordinal) && !current.Contains("dependentRegistrant", StringComparer.Ordinal))
                    return Deny("Dependent registration requires the admin or dependentRegistrant directory role.");
            }
            else if (kind == RegistrationKind.ExternalBusiness || kind == RegistrationKind.OrganizationalPartner)
            {
                if (config.AppId != "sampleapp02" || !current.Contains("admin", StringComparer.Ordinal)) return Deny("Business registration requires a sampleapp02 employee administrator.");
            }
            else return Deny("This registration purpose is not supported.");
            return new RegistrationDecision { Allowed = true, SponsorEntitlement = employee, Reason = "Registration is permitted." };
        }
        internal static bool KnownApp(AppConfiguration config) => config?.Workforce != null && config.External != null && (config.AppId == "sampleapp01" || config.AppId == "sampleapp02");
        internal static bool SameGuid(string left, string right) { Guid a, b; return Guid.TryParse(left, out a) && Guid.TryParse(right, out b) && a != Guid.Empty && a == b; }
        internal static string GuidValue(string value)
        {
            Guid parsed;
            if (!Guid.TryParse(value, out parsed) || parsed == Guid.Empty) throw new RegistrationException("A stable directory identity is required.");
            return parsed.ToString();
        }
        private static RegistrationDecision Deny(string reason) => new RegistrationDecision { Allowed = false, Reason = reason };
    }
    public sealed class JsonInvitationStore
    {
        private readonly string path;
        private static readonly JsonSerializerSettings JsonSettings = new JsonSerializerSettings { ContractResolver = new CamelCasePropertyNamesContractResolver(), Formatting = Formatting.Indented };

        public JsonInvitationStore(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !Path.IsPathRooted(path)) throw new RegistrationException("Set an absolute, protected registration state path.");
            this.path = Path.GetFullPath(path);
            var webRoot = Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            var appData = Path.Combine(webRoot, "App_Data") + Path.DirectorySeparatorChar;
            if (this.path.StartsWith(webRoot, StringComparison.OrdinalIgnoreCase) && !this.path.StartsWith(appData, StringComparison.OrdinalIgnoreCase))
                throw new RegistrationException("Registration state must be outside the public web folder or in IIS-protected App_Data.");
        }

        public IssuedInvitation Create(AppConfiguration config, ClaimsPrincipal sponsor, IEnumerable<Entitlement> entries, RegistrationKind kind, string recipientEmail, DateTimeOffset now, DateTimeOffset approvalLimitUtc)
        {
            var authorization = RegistrationPolicy.Authorize(config, sponsor, entries, kind, now);
            if (!authorization.Allowed) throw new RegistrationException(authorization.Reason);
            var email = NormalizeEmail(recipientEmail);
            if (kind != RegistrationKind.OrganizationalPartner && IdentityRouter.Route(config, email) != IdentitySource.External)
                throw new RegistrationException("Use a personal external address for this registration purpose.");
            if (kind == RegistrationKind.OrganizationalPartner && (config.EmployeeDomains ?? new string[0]).Contains(new MailAddress(email).Host, StringComparer.OrdinalIgnoreCase))
                throw new RegistrationException("A business partner must belong to a separate, verified organization.");
            var approvalExpiry = Min(approvalLimitUtc, authorization.SponsorEntitlement.ExpiresUtc);
            if (approvalExpiry <= now) throw new RegistrationException("The configured registration approval period has ended.");
            var random = new byte[32];
            using (var generator = RandomNumberGenerator.Create()) generator.GetBytes(random);
            var token = Base64Url(random);
            var invitation = new InvitationRecord {
                Id = Guid.NewGuid().ToString(), AppId = config.AppId, Kind = kind, RecipientEmail = email,
                Source = kind == RegistrationKind.OrganizationalPartner ? "workforce" : "external",
                Persona = Persona(kind), SponsorTenantId = RegistrationPolicy.GuidValue(authorization.SponsorEntitlement.TenantId), SponsorObjectId = RegistrationPolicy.GuidValue(authorization.SponsorEntitlement.ObjectId),
                CreatedUtc = now, ExpiresUtc = Min(now.AddHours(24), approvalExpiry), ApprovalExpiresUtc = approvalExpiry, Status = "pending_identity", EmailStatus = "not_sent"
            };
            Transaction(state => {
                if (state.Invitations.Any(i => i.Invitation.AppId == config.AppId && string.Equals(i.Invitation.RecipientEmail, email, StringComparison.OrdinalIgnoreCase) && i.Invitation.ExpiresUtc > now && (i.Invitation.Status == "pending_identity" || i.Invitation.Status == "ready")))
                    throw new RegistrationException("An active invitation already exists for this address. Check its email status or ask an administrator; do not repeatedly resend.");
                state.Invitations.Add(new StoredInvitation { Invitation = invitation, TokenHash = Hash(token) }); return 0;
            }, true);
            // Never persist or subsequently expose this bearer token. Send it only through the email adapter.
            return new IssuedInvitation { Invitation = Copy(invitation), Token = token };
        }

        // Trusted server adapter only: persist the directory object returned by Graph BEFORE emailing.
        public void BindIdentity(AppConfiguration config, string invitationId, InvitationIdentityBinding binding, DateTimeOffset now)
        {
            Transaction(state => {
                var matches = state.Invitations.Where(i => i.Invitation.Id == invitationId).ToArray();
                if (matches.Length != 1) throw new RegistrationException("The invitation is unavailable.");
                var invitation = matches[0].Invitation;
                RequireCurrent(config, invitation, now, false);
                if (binding == null) throw new RegistrationException("The provisioned directory identity is required.");
                var expectedTenant = invitation.Source == "external" ? config.External.TenantId : config.Workforce.TenantId;
                if (!RegistrationPolicy.SameGuid(binding.TenantId, expectedTenant)) throw new RegistrationException("The provisioned identity belongs to the wrong directory.");
                var tenantId = RegistrationPolicy.GuidValue(binding.TenantId); var objectId = RegistrationPolicy.GuidValue(binding.ObjectId);
                if (state.Approvals.Any(e => e.AppId == config.AppId && RegistrationPolicy.SameGuid(e.TenantId, tenantId) && RegistrationPolicy.SameGuid(e.ObjectId, objectId)))
                    throw new RegistrationException("This directory identity already has an application approval. Ask an administrator to review it.");
                string homeTenantId = null;
                if (invitation.Kind == RegistrationKind.OrganizationalPartner)
                {
                    homeTenantId = RegistrationPolicy.GuidValue(binding.HomeTenantId);
                    if (RegistrationPolicy.SameGuid(homeTenantId, config.Workforce.TenantId) || RegistrationPolicy.SameGuid(homeTenantId, config.External.TenantId) || binding.OrganizationVerifiedUtc == null || binding.OrganizationVerifiedUtc > now)
                        throw new RegistrationException("The partner's separate home organization must be verified by the provisioning adapter.");
                }
                else if (binding.HomeTenantId != null || binding.OrganizationVerifiedUtc != null) throw new RegistrationException("External personal registrations cannot carry an organizational partner binding.");
                if (invitation.Status == "ready")
                {
                    if (invitation.TenantId != tenantId || invitation.ObjectId != objectId || invitation.HomeTenantId != homeTenantId || invitation.OrganizationVerifiedUtc != binding.OrganizationVerifiedUtc)
                        throw new RegistrationException("The invitation's directory identity cannot be changed.");
                    return 0;
                }
                invitation.TenantId = tenantId; invitation.ObjectId = objectId; invitation.HomeTenantId = homeTenantId; invitation.OrganizationVerifiedUtc = binding.OrganizationVerifiedUtc; invitation.Status = "ready";
                return 0;
            }, true);
        }

        // GET preview is read-only. It neither grants a role nor consumes the link.
        public void ReservePasswordSetup(AppConfiguration config, string token, DateTimeOffset now)
        {
            Transaction(state => {
                var invitation = Find(state, token).Invitation;
                RequireCurrent(config, invitation, now, true);
                if (invitation.Source != "external" || (invitation.PasswordSetupStartedUtc != null && invitation.PasswordSetupStartedUtc.Value.AddMinutes(5) > now))
                    throw new RegistrationException("Wait five minutes before requesting another verification email. Use the code already sent if available.");
                invitation.PasswordSetupStartedUtc = now;
                return 0;
            }, true);
        }

        public InvitationRecord Preview(AppConfiguration config, string token, DateTimeOffset now) => Transaction(state => {
            var invitation = Find(state, token).Invitation; RequireCurrent(config, invitation, now, true); return Copy(invitation);
        }, false);

        // Resume only a delivered invitation for the exact validated directory identity.
        // Email addresses and the invitation ID alone are never identity proof.
        public InvitationRecord PreviewForRecipient(AppConfiguration config, ClaimsPrincipal recipient, DateTimeOffset now, string invitationId = null) => Transaction(state => {
            var invitation = FindForRecipient(state, config, recipient, now, invitationId);
            return Copy(invitation);
        }, false);

        // Caller must expose this only as an authenticated, CSRF-protected POST.
        public Entitlement Redeem(AppConfiguration config, string token, ClaimsPrincipal recipient, IEnumerable<Entitlement> entries, IEnumerable<string> currentSponsorRoles, DateTimeOffset now)
        {
            var governance = (entries ?? new Entitlement[0]).Where(e => e != null).ToArray();
            return Transaction(state => RedeemBound(state, config, Find(state, token).Invitation, recipient, governance, currentSponsorRoles, now), true);
        }

        // Used only with the invitation ID held in a protected registration-only cookie.
        public Entitlement RedeemForRecipient(AppConfiguration config, string invitationId, ClaimsPrincipal recipient, IEnumerable<Entitlement> entries, IEnumerable<string> currentSponsorRoles, DateTimeOffset now)
        {
            if (string.IsNullOrEmpty(invitationId)) throw new RegistrationException("An authenticated invitation session is required.");
            var governance = (entries ?? new Entitlement[0]).Where(e => e != null).ToArray();
            return Transaction(state => RedeemBound(state, config, FindForRecipient(state, config, recipient, now, invitationId), recipient, governance, currentSponsorRoles, now), true);
        }

        private static Entitlement RedeemBound(RegistrationState state, AppConfiguration config, InvitationRecord invitation, ClaimsPrincipal recipient, Entitlement[] governance, IEnumerable<string> currentSponsorRoles, DateTimeOffset now)
        {
                RequireCurrent(config, invitation, now, true);
                if (!RegistrationSignInPolicy.MatchesBoundIdentity(config, invitation, recipient, now))
                    throw new RegistrationException("Sign in with the directory identity bound to this invitation.");
                var sponsor = RegistrationPolicy.RecheckSponsor(config, invitation, governance, currentSponsorRoles, now);
                if (!sponsor.Allowed) throw new RegistrationException(sponsor.Reason);
                if (governance.Concat(state.Approvals).Any(e => e.AppId == config.AppId && RegistrationPolicy.SameGuid(e.TenantId, invitation.TenantId) && RegistrationPolicy.SameGuid(e.ObjectId, invitation.ObjectId)))
                    throw new RegistrationException("An existing application approval must be reviewed by an administrator.");
                var approval = new Entitlement {
                    AppId = invitation.AppId, TenantId = invitation.TenantId, ObjectId = invitation.ObjectId, Source = invitation.Source, Persona = invitation.Persona,
                    Sponsor = invitation.SponsorTenantId + ":" + invitation.SponsorObjectId, Status = "approved", ExpiresUtc = Min(invitation.ApprovalExpiresUtc, sponsor.SponsorEntitlement.ExpiresUtc),
                    RelationshipVerified = invitation.Kind == RegistrationKind.Dependent, BenefitEligible = invitation.Kind == RegistrationKind.Dependent,
                    LinkedEmployeeTenantId = invitation.Kind == RegistrationKind.Dependent ? invitation.SponsorTenantId : null, LinkedEmployeeObjectId = invitation.Kind == RegistrationKind.Dependent ? invitation.SponsorObjectId : null,
                    HomeTenantId = invitation.HomeTenantId, OrganizationVerifiedUtc = invitation.OrganizationVerifiedUtc
                };
                var admission = AdmissionPolicy.Evaluate(config, recipient, governance.Concat(new[] { approval }), now);
                if (!admission.Allowed) throw new RegistrationException(admission.Reason);
                // One JSON replacement commits both state transitions. No approval is written before proof.
                state.Approvals.Add(approval); invitation.Status = "redeemed"; invitation.RedeemedUtc = now;
                return Copy(approval);
        }

        // Include disabled records too: removal/disable/expiry must remain effective during admission.
        public Entitlement[] ReadApprovedEntitlements() => Transaction(state => state.Approvals.Select(Copy).ToArray(), false);

        public InvitationRecord[] ReadForSponsor(AppConfiguration config, ClaimsPrincipal caller)
        {
            var tid = caller == null ? null : AdmissionPolicy.Single(caller, "tid"); var oid = caller == null ? null : AdmissionPolicy.Single(caller, "oid");
            if (!RegistrationPolicy.KnownApp(config) || caller?.Identity?.IsAuthenticated != true || !RegistrationPolicy.SameGuid(tid, config.Workforce.TenantId) || AdmissionPolicy.Single(caller, "identity_source") != "workforce" || AdmissionPolicy.Single(caller, "iss") != config.Workforce.Issuer || !RegistrationPolicy.SameGuid(AdmissionPolicy.Single(caller, "aud"), config.Workforce.ClientId) || !caller.FindAll("roles").Any(c => c.Value == "Employee"))
                throw new RegistrationException("An authenticated workforce employee is required.");
            RegistrationPolicy.GuidValue(oid);
            return Transaction(state => state.Invitations.Where(i => i.Invitation.AppId == config.AppId && RegistrationPolicy.SameGuid(i.Invitation.SponsorTenantId, tid) && RegistrationPolicy.SameGuid(i.Invitation.SponsorObjectId, oid)).Select(i => Copy(i.Invitation)).ToArray(), false);
        }

        // Trusted pre-send DIRECTORY-failure recovery only. A send timeout or an
        // uncertain provider response is not evidence that an email was never accepted.
        public void CancelBeforeDelivery(AppConfiguration config, string invitationId, DateTimeOffset now, bool requirePendingIdentity = false)
        {
            Transaction(state => {
                var matches = state.Invitations.Where(i => i.Invitation.Id == invitationId).ToArray();
                if (!RegistrationPolicy.KnownApp(config) || matches.Length != 1) throw new RegistrationException("The invitation cannot be canceled.");
                var invitation = matches[0].Invitation;
                if (invitation.AppId != config.AppId || invitation.CreatedUtc > now || (invitation.Status != "pending_identity" && invitation.Status != "ready") || (requirePendingIdentity && invitation.Status != "pending_identity") || invitation.EmailStatus != "not_sent" || invitation.EmailOperationId != null || invitation.RedeemedUtc != null || state.Approvals.Any(e => e.AppId == config.AppId && RegistrationPolicy.SameGuid(e.TenantId, invitation.TenantId) && RegistrationPolicy.SameGuid(e.ObjectId, invitation.ObjectId)))
                    throw new RegistrationException("Only an unapproved invitation that failed before email delivery began can be canceled.");
                invitation.Status = "canceled"; invitation.ExpiresUtc = Min(invitation.ExpiresUtc, now); invitation.CanceledUtc = now;
                return 0;
            }, true);
        }

        // Trusted email adapter only. This audit never changes identity state or grants approval.
        public void RecordDelivery(AppConfiguration config, string invitationId, string status, string operationId, DateTimeOffset now)
        {
            if (!new[] { "queued", "sent", "pending", "failed" }.Contains(status, StringComparer.Ordinal)) throw new RegistrationException("The email audit status is invalid.");
            var normalizedOperation = operationId == null ? null : RegistrationPolicy.GuidValue(operationId);
            if (normalizedOperation == null && status != "failed") throw new RegistrationException("An email operation identifier is required.");
            Transaction(state => {
                var matches = state.Invitations.Where(i => i.Invitation.Id == invitationId).ToArray();
                if (!RegistrationPolicy.KnownApp(config) || matches.Length != 1) throw new RegistrationException("The email audit invitation is unavailable.");
                var invitation = matches[0].Invitation;
                if (invitation.AppId != config.AppId || invitation.CreatedUtc > now || (invitation.Status != "ready" && invitation.Status != "redeemed") || !RegistrationPolicy.SameGuid(invitation.TenantId, invitation.Source == "external" ? config.External.TenantId : invitation.Source == "workforce" ? config.Workforce.TenantId : null))
                    throw new RegistrationException("The email audit does not match a bound application invitation.");
                RegistrationPolicy.GuidValue(invitation.ObjectId);
                if ((invitation.EmailOperationId != null && normalizedOperation != null && invitation.EmailOperationId != normalizedOperation) || (invitation.EmailStatus == "sent" && status != "sent") || (invitation.EmailRecordedUtc != null && invitation.EmailRecordedUtc > now))
                    throw new RegistrationException("The email audit cannot replace an existing operation or completed send.");
                invitation.EmailStatus = status; invitation.EmailOperationId = normalizedOperation ?? invitation.EmailOperationId; invitation.EmailRecordedUtc = now;
                return 0;
            }, true);
        }

        // A domain becomes a routing hint only after signed organizational identity proof
        // completed redemption. Routing still grants no entitlement to other addresses.
        public bool HasApprovedPartnerDomain(AppConfiguration config, string domain, DateTimeOffset now)
        {
            if (!RegistrationPolicy.KnownApp(config) || config.AppId != "sampleapp02" || string.IsNullOrWhiteSpace(domain) || domain != domain.Trim() || Uri.CheckHostName(domain) != UriHostNameType.Dns || !domain.Contains(".")) return false;
            return Transaction(state => state.Invitations.Any(stored => {
                var invitation = stored.Invitation;
                Guid home, sponsorObject;
                if (invitation.AppId != config.AppId || invitation.Kind != RegistrationKind.OrganizationalPartner || invitation.Status != "redeemed" || invitation.Source != "workforce" || invitation.Persona != "partner" || invitation.RedeemedUtc == null || invitation.RedeemedUtc > now || invitation.RedeemedUtc < invitation.CreatedUtc || invitation.RedeemedUtc >= invitation.ExpiresUtc || !RegistrationPolicy.SameGuid(invitation.TenantId, config.Workforce.TenantId) || !RegistrationPolicy.SameGuid(invitation.SponsorTenantId, config.Workforce.TenantId) || !Guid.TryParse(invitation.SponsorObjectId, out sponsorObject) || sponsorObject == Guid.Empty || !Guid.TryParse(invitation.HomeTenantId, out home) || home == Guid.Empty || RegistrationPolicy.SameGuid(invitation.HomeTenantId, config.Workforce.TenantId) || RegistrationPolicy.SameGuid(invitation.HomeTenantId, config.External.TenantId) || invitation.OrganizationVerifiedUtc == null || invitation.OrganizationVerifiedUtc > invitation.RedeemedUtc)
                    return false;
                MailAddress address;
                try { address = new MailAddress(invitation.RecipientEmail ?? ""); }
                catch (Exception ex) when (ex is FormatException || ex is ArgumentException) { return false; }
                if (!string.Equals(address.Address, invitation.RecipientEmail, StringComparison.OrdinalIgnoreCase) || !string.Equals(address.Host, domain, StringComparison.OrdinalIgnoreCase)) return false;
                var approvals = state.Approvals.Where(e => e.AppId == config.AppId && RegistrationPolicy.SameGuid(e.TenantId, invitation.TenantId) && RegistrationPolicy.SameGuid(e.ObjectId, invitation.ObjectId)).ToArray();
                return approvals.Length == 1 && approvals[0].Source == "workforce" && approvals[0].Persona == "partner" && approvals[0].Status == "approved" && approvals[0].ExpiresUtc > now && approvals[0].ExpiresUtc <= invitation.ApprovalExpiresUtc && RegistrationPolicy.SameGuid(approvals[0].HomeTenantId, invitation.HomeTenantId) && approvals[0].OrganizationVerifiedUtc == invitation.OrganizationVerifiedUtc && approvals[0].Sponsor == invitation.SponsorTenantId + ":" + invitation.SponsorObjectId;
            }), false);
        }

        private static void RequireCurrent(AppConfiguration config, InvitationRecord invitation, DateTimeOffset now, bool requireBinding)
        {
            if (!RegistrationPolicy.KnownApp(config) || invitation.AppId != config.AppId || invitation.CreatedUtc > now || invitation.ExpiresUtc <= now || invitation.ApprovalExpiresUtc <= now || invitation.ExpiresUtc > invitation.CreatedUtc.AddHours(24) || invitation.ExpiresUtc > invitation.ApprovalExpiresUtc)
                throw new RegistrationException("The invitation is unavailable for this application or has expired.");
            if (invitation.Status != "pending_identity" && invitation.Status != "ready") throw new RegistrationException("The invitation has already been used or disabled.");
            if (invitation.Persona != Persona(invitation.Kind) || invitation.Source != (invitation.Kind == RegistrationKind.OrganizationalPartner ? "workforce" : "external") || !RegistrationPolicy.SameGuid(invitation.SponsorTenantId, config.Workforce.TenantId))
                throw new RegistrationException("The invitation does not match this application's registration policy.");
            RegistrationPolicy.GuidValue(invitation.SponsorObjectId);
            if (requireBinding)
            {
                if (invitation.Status != "ready" || !RegistrationPolicy.SameGuid(invitation.TenantId, invitation.Source == "external" ? config.External.TenantId : config.Workforce.TenantId))
                    throw new RegistrationException("The invitation's directory identity is not ready.");
                RegistrationPolicy.GuidValue(invitation.ObjectId);
            }
        }
        private static string Persona(RegistrationKind kind)
        {
            if (kind == RegistrationKind.Dependent) return "dependent";
            if (kind == RegistrationKind.ExternalBusiness) return "external";
            if (kind == RegistrationKind.OrganizationalPartner) return "partner";
            throw new RegistrationException("This registration purpose is not supported.");
        }
        private static string NormalizeEmail(string value)
        {
            var normalized = (value ?? "").Trim();
            MailAddress address;
            try { address = new MailAddress(normalized); }
            catch (Exception ex) when (ex is FormatException || ex is ArgumentException) { throw new RegistrationException("Enter a complete recipient email address."); }
            if (normalized.Length > 254 || !string.Equals(address.Address, normalized, StringComparison.OrdinalIgnoreCase) || !address.Host.Contains(".") || (value ?? "").IndexOfAny(new[] { '\r', '\n' }) >= 0)
                throw new RegistrationException("Enter a recipient email address without a display name.");
            return address.Address.ToLowerInvariant();
        }
        private static StoredInvitation Find(RegistrationState state, string token)
        {
            if (token == null || !Regex.IsMatch(token, "\\A[A-Za-z0-9_-]{43}\\z") || Base64Url(Convert.FromBase64String(token.Replace('-', '+').Replace('_', '/') + "=")) != token)
                throw new RegistrationException("The invitation link is invalid.");
            var hash = Hash(token); var matches = state.Invitations.Where(i => EqualHash(i.TokenHash, hash)).ToArray();
            if (matches.Length != 1) throw new RegistrationException("The invitation link is invalid.");
            return matches[0];
        }
        private static InvitationRecord FindForRecipient(RegistrationState state, AppConfiguration config, ClaimsPrincipal recipient, DateTimeOffset now, string invitationId)
        {
            Guid id;
            if (invitationId != null && (!Guid.TryParse(invitationId, out id) || id == Guid.Empty))
                throw new RegistrationException("The registration invitation is unavailable.");
            var matches = state.Invitations.Select(i => i.Invitation).Where(i =>
                (invitationId == null || i.Id == invitationId) && i.EmailStatus == "sent" &&
                RegistrationSignInPolicy.MatchesBoundIdentity(config, i, recipient, now)).ToArray();
            if (matches.Length != 1) throw new RegistrationException("A unique current invitation for this directory identity is required.");
            RequireCurrent(config, matches[0], now, true);
            return matches[0];
        }
        private static string Hash(string token) { using (var digest = SHA256.Create()) return Convert.ToBase64String(digest.ComputeHash(Encoding.UTF8.GetBytes(token))); }
        private static string Base64Url(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        private static bool EqualHash(string left, string right)
        {
            if (left == null || right == null || left.Length != right.Length) return false;
            var difference = 0; for (var i = 0; i < left.Length; i++) difference |= left[i] ^ right[i]; return difference == 0;
        }
        private static DateTimeOffset Min(DateTimeOffset left, DateTimeOffset right) => left <= right ? left : right;
        private static T Copy<T>(T value) => JsonConvert.DeserializeObject<T>(JsonConvert.SerializeObject(value, JsonSettings), JsonSettings);
        private T Transaction<T>(Func<RegistrationState, T> action, bool write)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            using (AcquireLock())
            {
                var state = File.Exists(path) ? JsonConvert.DeserializeObject<RegistrationState>(File.ReadAllText(path), JsonSettings) : new RegistrationState();
                if (state == null || state.SchemaVersion != 1 || state.Invitations == null || state.Approvals == null || state.Invitations.Any(i => i?.Invitation == null || string.IsNullOrEmpty(i.TokenHash)) || state.Approvals.Any(e => e == null) || state.Invitations.Select(i => i.Invitation.Id).Distinct(StringComparer.Ordinal).Count() != state.Invitations.Count)
                    throw new RegistrationException("The registration state is invalid. Ask an administrator to review it.");
                var result = action(state);
                if (write) AtomicWrite(state);
                return result;
            }
        }
        private FileStream AcquireLock()
        {
            var wait = Stopwatch.StartNew();
            while (true)
            {
                try { return new FileStream(path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
                catch (IOException) { if (wait.Elapsed > TimeSpan.FromSeconds(5)) throw new RegistrationException("Registration is busy. Try again shortly."); Thread.Sleep(25); }
            }
        }
        private void AtomicWrite(RegistrationState state)
        {
            var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            var retainRecovery = false;
            try
            {
                var bytes = new UTF8Encoding(false).GetBytes(JsonConvert.SerializeObject(state, JsonSettings));
                using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough)) { file.Write(bytes, 0, bytes.Length); file.Flush(true); }
                var replacing = File.Exists(path);
                // Windows/IIS: rename within the same private directory in one operation.
                // MoveFileEx supports Azure's SMB content share without ReplaceFile's
                // metadata-merge step. Never copy across volumes or delete the target first.
                try {
                    if (replacing) {
                        if (!MoveFileEx(temporary, path, 0x1 | 0x8)) {
                            var error = Marshal.GetLastWin32Error();
                            throw new IOException("Atomic state rename failed.", unchecked((int)0x80070000) | (error & 0xffff));
                        }
                    } else File.Move(temporary, path);
                }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
                {
                    retainRecovery = true;
                    // Report only an operation stage and numeric code, never a state path,
                    // recipient, exception message or bearer token. Keep the old state intact.
                    throw new RegistrationException("Registration storage " + (replacing ? "commit_replace" : "commit_create") + " failed (HRESULT 0x" + ex.HResult.ToString("X8", System.Globalization.CultureInfo.InvariantCulture) + "). Ask the application administrator to check storage.", ex);
                }
            }
            finally { if (!retainRecovery && File.Exists(temporary)) File.Delete(temporary); }
        }
        [DllImport("kernel32.dll", EntryPoint = "MoveFileExW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool MoveFileEx(string source, string destination, int flags);
        private sealed class StoredInvitation { public InvitationRecord Invitation { get; set; } public string TokenHash { get; set; } }
        private sealed class RegistrationState { public int SchemaVersion { get; set; } = 1; public List<StoredInvitation> Invitations { get; set; } = new List<StoredInvitation>(); public List<Entitlement> Approvals { get; set; } = new List<Entitlement>(); }
    }
}
