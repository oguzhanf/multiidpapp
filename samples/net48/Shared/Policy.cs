using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Mail;
using System.Security.Claims;
using Newtonsoft.Json;

namespace MultiIdp.Net48
{
    public enum IdentitySource { Workforce, External }
    public sealed class TenantConfiguration
    {
        public string TenantId { get; set; }
        public string ClientId { get; set; }
        public string Issuer { get; set; }
        public string RedirectUri { get; set; }
        public string ClientSecretEnvironmentVariable { get; set; }
        public string CiamDomain { get; set; }
    }
    public sealed class AppConfiguration { public string AppId { get; set; } public string[] EmployeeDomains { get; set; } public string[] ApprovedPartnerDomains { get; set; } public TenantConfiguration Workforce { get; set; } public TenantConfiguration External { get; set; } public string EntitlementFile { get; set; } }
    public sealed class Entitlement { public string AppId { get; set; } public string TenantId { get; set; } public string ObjectId { get; set; } public string Source { get; set; } public string Persona { get; set; } public string Sponsor { get; set; } public string Status { get; set; } public DateTimeOffset ExpiresUtc { get; set; } public bool RelationshipVerified { get; set; } public bool BenefitEligible { get; set; } public string LinkedEmployeeTenantId { get; set; } public string LinkedEmployeeObjectId { get; set; } public string HomeTenantId { get; set; } public DateTimeOffset? OrganizationVerifiedUtc { get; set; } }
    public static class IdentityRouter
    {
        public static IdentitySource Route(AppConfiguration config, string email)
        {
            var normalized = (email ?? "").Trim();
            MailAddress address;
            try { address = new MailAddress(normalized); }
            catch (FormatException) { throw new ArgumentException("Enter a complete email address."); }
            if (!string.Equals(address.Address, normalized, StringComparison.OrdinalIgnoreCase) || normalized.Length > 254 || !address.Host.Contains("."))
                throw new ArgumentException("Enter an email address without a display name.");
            var employee = (config.EmployeeDomains ?? new string[0]).Contains(address.Host, StringComparer.OrdinalIgnoreCase);
            var partner = config.AppId == "sampleapp02" && (config.ApprovedPartnerDomains ?? new string[0]).Contains(address.Host, StringComparer.OrdinalIgnoreCase);
            return employee || partner ? IdentitySource.Workforce : IdentitySource.External;
        }
    }
    public sealed class AdmissionDecision { public bool Allowed { get; set; } public string Reason { get; set; } public Entitlement Entitlement { get; set; } }
    public static class AdmissionPolicy
    {
        public static AdmissionDecision Evaluate(AppConfiguration config, ClaimsPrincipal principal, IEnumerable<Entitlement> entries, DateTimeOffset now)
        {
            if (config?.Workforce == null || config.External == null) return Deny("Application identity configuration is unavailable.");
            if (principal?.Identity?.IsAuthenticated != true) return Deny("Sign in first.");
            var tid = Single(principal, "tid"); var oid = Single(principal, "oid");
            Guid tenantGuid, objectGuid;
            if (!Guid.TryParse(tid, out tenantGuid) || !Guid.TryParse(oid, out objectGuid)) return Deny("Stable directory identity is missing or ambiguous.");
            var source = Single(principal, "identity_source");
            var tenant = source == "workforce" ? config.Workforce : source == "external" ? config.External : null;
            if (tenant == null || !SameGuid(tid, tenant.TenantId) || Single(principal, "iss") != tenant.Issuer || !SameGuid(Single(principal, "aud"), tenant.ClientId)) return Deny("Identity tenant, issuer, audience or source does not match this application.");
            var records = (entries ?? new Entitlement[0]).Where(e => e != null).ToArray();
            var matched = records.Where(e => e.AppId == config.AppId && SameGuid(e.TenantId, tid) && SameGuid(e.ObjectId, oid)).ToArray();
            if (matched.Length != 1) return Deny("A unique application entitlement is required.");
            var entry = matched[0];
            if (entry.Source != source || entry.Status != "approved" || entry.ExpiresUtc <= now) return Deny("Approval is disabled, expired or belongs to another identity source.");
            var requiredRole = entry.Persona == "employee" ? "Employee" : entry.Persona == "retiree" ? "Retiree" : entry.Persona == "dependent" ? "Dependent" : entry.Persona == "partner" ? "Partner" : entry.Persona == "external" ? "External" : null;
            if (requiredRole == null || !principal.FindAll("roles").Any(c => c.Value == requiredRole)) return Deny("A signed directory application role matching the approved persona is required.");
            if (entry.Persona == "employee")
            {
                if (source != "workforce") return Deny("Employees use the workforce directory.");
            }
            else if (entry.Persona == "retiree" || entry.Persona == "dependent" || entry.Persona == "external")
            {
                if (source != "external" || string.IsNullOrWhiteSpace(entry.Sponsor)) return Deny("External benefits require an accountable sponsor.");
                if (entry.Persona == "dependent" && (!entry.RelationshipVerified || !entry.BenefitEligible)) return Deny("Dependent relationship and benefit eligibility require approval.");
                if (entry.Persona == "dependent")
                {
                    if (!SameGuid(entry.LinkedEmployeeTenantId, config.Workforce.TenantId)) return Deny("The dependent must link to a workforce employee.");
                    var parents = records.Where(e => e.AppId == config.AppId && SameGuid(e.TenantId, entry.LinkedEmployeeTenantId) && SameGuid(e.ObjectId, entry.LinkedEmployeeObjectId)).ToArray();
                    if (parents.Length != 1 || parents[0].Persona != "employee" || parents[0].Source != "workforce" || parents[0].Status != "approved" || parents[0].ExpiresUtc <= now || !parents[0].BenefitEligible) return Deny("The linked employee's application and benefit approval must be current.");
                }
            }
            else if (entry.Persona == "partner")
            {
                Guid homeTenant;
                if (config.AppId != "sampleapp02" || source != "workforce" || string.IsNullOrWhiteSpace(entry.Sponsor) || !Guid.TryParse(entry.HomeTenantId, out homeTenant) || homeTenant == Guid.Empty || entry.OrganizationVerifiedUtc == null || entry.OrganizationVerifiedUtc > now)
                    return Deny("Partners require verified organizational B2B onboarding and approval for sampleapp02.");
                var idp = Single(principal, "idp");
                if (idp != "https://sts.windows.net/" + homeTenant.ToString() + "/" && idp != "https://login.microsoftonline.com/" + homeTenant.ToString() + "/v2.0") return Deny("The signed B2B identity provider must match the verified home organization.");
            }
            else return Deny("This persona is not approved for the application.");
            return new AdmissionDecision { Allowed = true, Entitlement = entry, Reason = "Approved " + entry.Persona + "." };
        }
        internal static string Single(ClaimsPrincipal principal, string type)
        {
            var claims = principal.FindAll(type).Select(c => c.Value).ToArray();
            return claims.Length == 1 ? claims[0] : null;
        }
        private static bool SameGuid(string left, string right) { Guid a, b; return Guid.TryParse(left, out a) && Guid.TryParse(right, out b) && a != Guid.Empty && a == b; }
        private static AdmissionDecision Deny(string reason) => new AdmissionDecision { Allowed = false, Reason = reason };
    }
    public sealed class JsonEntitlementStore
    {
        private readonly string path;
        public JsonEntitlementStore(string path) { this.path = path; }
        public Entitlement[] Read()
        {
            // Intentionally reload: changing status or expiry revokes admission on the next request.
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return new Entitlement[0];
            return JsonConvert.DeserializeObject<Entitlement[]>(File.ReadAllText(path)) ?? new Entitlement[0];
        }
    }
}
