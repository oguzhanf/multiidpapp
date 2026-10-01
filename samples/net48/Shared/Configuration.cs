using System;
using System.IO;
using System.Linq;
using Newtonsoft.Json;

namespace MultiIdp.Net48
{
    public sealed class ConfigurationException : Exception { public ConfigurationException(string message) : base(message) { } }
    public static class ConfigurationLoader
    {
        public static AppConfiguration Load(string appId)
        {
            var variable = "MULTIIDP_" + appId.ToUpperInvariant() + "_CONFIG";
            var path = Environment.GetEnvironmentVariable(variable);
            if (string.IsNullOrWhiteSpace(path) || !Path.IsPathRooted(path) || !File.Exists(path)) throw new ConfigurationException("Set " + variable + " to an absolute, server-only JSON configuration file.");
            RequireOutsideWebRoot(path, "Configuration");
            AppConfiguration config;
            try { config = JsonConvert.DeserializeObject<AppConfiguration>(File.ReadAllText(path)); }
            catch (Exception ex) when (ex is IOException || ex is JsonException || ex is UnauthorizedAccessException) { throw new ConfigurationException("The application configuration could not be read. Check JSON and file permissions."); }
            if (config == null || config.AppId != appId) throw new ConfigurationException("appId must match " + appId + ".");
            if (config.AppId == "sampleapp01" && config.EmployeeDomains == null) config.EmployeeDomains = new string[0];
            if (config.EmployeeDomains == null || (config.AppId != "sampleapp01" && config.EmployeeDomains.Length == 0) || config.EmployeeDomains.Any(d => !ValidDomain(d))) throw new ConfigurationException("employeeDomains must contain exact DNS domains for sampleapp02.");
            if ((config.ApprovedPartnerDomains ?? new string[0]).Any(d => !ValidDomain(d))) throw new ConfigurationException("approvedPartnerDomains must contain exact onboarded DNS domains.");
            ValidateTenant(config.Workforce, false); ValidateTenant(config.External, true);
            if (config.Workforce.TenantId == config.External.TenantId || config.Workforce.ClientId == config.External.ClientId) throw new ConfigurationException("Workforce and External ID require separate tenants and client registrations.");
            if (new Uri(config.Workforce.RedirectUri).AbsolutePath != "/signin-workforce" || new Uri(config.External.RedirectUri).AbsolutePath != "/signin-external" || new Uri(config.Workforce.RedirectUri).GetLeftPart(UriPartial.Authority) != new Uri(config.External.RedirectUri).GetLeftPart(UriPartial.Authority)) throw new ConfigurationException("Set same-origin HTTPS callbacks /signin-workforce and /signin-external.");
            if (string.IsNullOrWhiteSpace(config.EntitlementFile) || !Path.IsPathRooted(config.EntitlementFile)) throw new ConfigurationException("Set entitlementFile to an absolute server-only JSON file.");
            RequireOutsideWebRoot(config.EntitlementFile, "Entitlements");
            return config;
        }
        public static void ValidateTenant(TenantConfiguration tenant, bool external)
        {
            Guid id, client;
            if (tenant == null || !Guid.TryParse(tenant.TenantId, out id) || id == Guid.Empty || !Guid.TryParse(tenant.ClientId, out client) || client == Guid.Empty) throw new ConfigurationException("Each tenantId and clientId must be an explicit nonempty GUID.");
            Uri redirect;
            if (!Uri.TryCreate(tenant.RedirectUri, UriKind.Absolute, out redirect) || redirect.Scheme != "https" || !string.IsNullOrEmpty(redirect.Query) || !string.IsNullOrEmpty(redirect.Fragment)) throw new ConfigurationException("Each redirectUri must be an absolute HTTPS callback.");
            Uri issuer;
            if (!Uri.TryCreate(tenant.Issuer, UriKind.Absolute, out issuer) || issuer.Scheme != "https" || issuer.AbsolutePath != "/" + id.ToString() + "/v2.0" || !string.IsNullOrEmpty(issuer.Query) || !string.IsNullOrEmpty(issuer.Fragment)) throw new ConfigurationException("Set issuer to the exact tenant-specific v2.0 discovery issuer.");
            if (!external && issuer.Host != "login.microsoftonline.com") throw new ConfigurationException("Workforce issuer must be tenant-specific login.microsoftonline.com.");
            if (external && (!ValidDomain(tenant.CiamDomain) || !tenant.CiamDomain.EndsWith(".ciamlogin.com", StringComparison.OrdinalIgnoreCase) || (issuer.Host != tenant.CiamDomain.ToLowerInvariant() && issuer.Host != id.ToString() + ".ciamlogin.com"))) throw new ConfigurationException("External ID ciamDomain must be the tenant's ciamlogin.com hostname and issuer must match its discovery metadata.");
            if (string.IsNullOrWhiteSpace(tenant.ClientSecretEnvironmentVariable)) throw new ConfigurationException("Set clientSecretEnvironmentVariable for each separate application credential.");
        }
        public static string ReadSecret(TenantConfiguration tenant)
        {
            var secret = Environment.GetEnvironmentVariable(tenant.ClientSecretEnvironmentVariable);
            if (string.IsNullOrWhiteSpace(secret)) throw new ConfigurationException("Set server-side secret environment variable " + tenant.ClientSecretEnvironmentVariable + ".");
            return secret;
        }
        private static bool ValidDomain(string domain) => !string.IsNullOrWhiteSpace(domain) && domain == domain.Trim() && domain.Contains(".") && Uri.CheckHostName(domain) == UriHostNameType.Dns;
        private static void RequireOutsideWebRoot(string path, string label)
        {
            var root = Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            var fullPath = Path.GetFullPath(path);
            // IIS protects App_Data as a hidden segment; web.config explicitly retains this.
            var appData = Path.Combine(root, "App_Data") + Path.DirectorySeparatorChar;
            if (fullPath.StartsWith(root, StringComparison.OrdinalIgnoreCase) && !fullPath.StartsWith(appData, StringComparison.OrdinalIgnoreCase)) throw new ConfigurationException(label + " must be outside the public web folder or inside IIS-protected App_Data.");
        }
    }
}
