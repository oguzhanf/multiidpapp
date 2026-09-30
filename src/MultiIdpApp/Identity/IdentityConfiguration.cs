using System.Net;
using Microsoft.Extensions.Configuration;

namespace MultiIdpApp.Identity;

public static class IdentityConfiguration
{
    public static void Validate(IConfiguration configuration)
    {
        foreach (var section in new[] { "AzureAd", "ExternalId" })
        {
            foreach (var key in new[] { "TenantId", "ClientId" })
            {
                if (!Guid.TryParse(configuration[$"{section}:{key}"], out var id) ||
                    id == Guid.Empty)
                {
                    throw new InvalidOperationException(
                        $"{section}:{key} must contain a non-empty tenant-specific GUID.");
                }
            }

            var secret = configuration[$"{section}:ClientSecret"];
            if (string.IsNullOrWhiteSpace(secret) ||
                secret.StartsWith("@Microsoft.KeyVault(", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"{section}:ClientSecret is missing or its Key Vault reference is unresolved.");
            }
        }

        if (string.Equals(
                configuration["AzureAd:TenantId"],
                configuration["ExternalId:TenantId"],
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Workforce and External ID must be configured with separate tenant IDs.");
        }

        if (!Uri.TryCreate(configuration["ExternalId:Authority"], UriKind.Absolute, out var authority) ||
            authority.Scheme != Uri.UriSchemeHttps ||
            !authority.Host.EndsWith(".ciamlogin.com", StringComparison.OrdinalIgnoreCase) ||
            !string.IsNullOrEmpty(authority.UserInfo) ||
            !string.IsNullOrEmpty(authority.Query) ||
            !string.IsNullOrEmpty(authority.Fragment) ||
            !string.Equals(
                authority.AbsolutePath.TrimEnd('/'),
                $"/{configuration["ExternalId:TenantId"]}/v2.0",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "ExternalId:Authority must be a tenant-specific HTTPS ciamlogin.com v2.0 authority.");
        }
    }
}

public sealed class ReverseProxyOptions
{
    public bool Enabled { get; set; }
    public string[] KnownProxies { get; set; } = [];
    public string[] KnownNetworks { get; set; } = [];

    public void Validate()
    {
        if (Enabled && KnownProxies.Length == 0 && KnownNetworks.Length == 0)
        {
            throw new InvalidOperationException(
                "ReverseProxy requires at least one explicit trusted proxy IP or network.");
        }

        if (KnownProxies.Any(proxy => !IPAddress.TryParse(proxy, out _)) ||
            KnownNetworks.Any(network =>
                !IPNetwork.TryParse(network, out var parsed) || parsed.PrefixLength == 0))
        {
            throw new InvalidOperationException(
                "ReverseProxy addresses must be IPs or explicit non-wildcard CIDR networks.");
        }
    }
}
