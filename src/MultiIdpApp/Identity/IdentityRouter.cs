using System.Net.Mail;
using Microsoft.Extensions.Options;

namespace MultiIdpApp.Identity;

public sealed class IdentityRoutingOptions
{
    public string[] WorkforceDomains { get; set; } = [];
}

// Domain routing chooses an authority; it never looks up whether a user exists.
public sealed class IdentityRouter(IOptions<IdentityRoutingOptions> options)
{
    public const string LoginHintParameter = "login_hint";
    private const int MaxEmailLength = 254;

    private readonly string[] _workforceDomains = options.Value.WorkforceDomains
        .Where(domain => !string.IsNullOrWhiteSpace(domain))
        .Select(domain => domain.Trim().TrimStart('.').ToLowerInvariant())
        .ToArray();

    public bool TryNormalize(string? input, out string email)
    {
        email = string.Empty;
        var candidate = input?.Trim();
        if (string.IsNullOrEmpty(candidate) || candidate.Length > MaxEmailLength)
        {
            return false;
        }

        if (!MailAddress.TryCreate(candidate, out var address) ||
            !string.Equals(address.Address, candidate, StringComparison.OrdinalIgnoreCase) ||
            !address.Host.Contains('.'))
        {
            return false;
        }

        email = $"{address.User}@{address.Host.ToLowerInvariant()}";
        return true;
    }

    public string SelectScheme(string normalizedEmail)
    {
        var host = normalizedEmail[(normalizedEmail.LastIndexOf('@') + 1)..];
        var workforce = _workforceDomains.Any(domain =>
            host == domain || host.EndsWith("." + domain, StringComparison.Ordinal));
        return workforce ? AuthSchemes.WorkforceOidc : AuthSchemes.ExternalOidc;
    }
}
