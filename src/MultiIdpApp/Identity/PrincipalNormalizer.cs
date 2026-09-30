using System.Security.Claims;

namespace MultiIdpApp.Identity;

// Only call after the OIDC middleware has validated signature, issuer, audience and lifetime.
public static class PrincipalNormalizer
{
    public static bool TryNormalize(
        ClaimsPrincipal? principal,
        string expectedTenantId,
        string identitySource,
        out string? error)
    {
        error = null;
        if (principal?.Identity is not ClaimsIdentity identity || !identity.IsAuthenticated)
        {
            error = "The authenticated principal does not contain an authenticated claims identity.";
            return false;
        }

        var tenant = ReadClaim(
            principal, "tid", "http://schemas.microsoft.com/identity/claims/tenantid");
        if (string.IsNullOrWhiteSpace(expectedTenantId) ||
            !string.Equals(tenant, expectedTenantId, StringComparison.OrdinalIgnoreCase))
        {
            error = "The token was issued by an unexpected tenant.";
            return false;
        }

        if (identitySource is not (AuthSchemes.WorkforceSource or AuthSchemes.ExternalSource))
        {
            error = "The authentication scheme has an unsupported identity source.";
            return false;
        }

        var subject = ReadClaim(
            principal, "oid", "http://schemas.microsoft.com/identity/claims/objectidentifier",
            "sub", ClaimTypes.NameIdentifier);
        if (string.IsNullOrWhiteSpace(subject))
        {
            error = "The validated token does not contain a stable subject identifier.";
            return false;
        }

        var email = ReadClaim(principal, "email", ClaimTypes.Email, "preferred_username");
        foreach (var type in new[] { "identity_source", "app_tenant_id", "app_subject", "app_email" })
        {
            foreach (var claim in identity.FindAll(type).ToList())
            {
                identity.RemoveClaim(claim);
            }
        }

        identity.AddClaim(new Claim("identity_source", identitySource));
        identity.AddClaim(new Claim("app_tenant_id", expectedTenantId));
        identity.AddClaim(new Claim("app_subject", subject));
        if (!string.IsNullOrWhiteSpace(email))
        {
            identity.AddClaim(new Claim("app_email", email));
        }
        return true;
    }

    private static string? ReadClaim(ClaimsPrincipal principal, params string[] types) =>
        types.Select(principal.FindFirstValue).FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
}
