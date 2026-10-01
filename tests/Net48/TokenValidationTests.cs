using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using MultiIdp.Net48;

internal static class TokenValidationTests
{
    private const string Issuer = "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0";
    private const string Audience = "66666666-6666-6666-6666-666666666666";
    public static bool UnsignedRejected()
    {
        var token = new JwtSecurityToken(Issuer, Audience, new[] { new Claim("oid", "33333333-3333-3333-3333-333333333333") }, DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddMinutes(10));
        SecurityToken validated;
        try { new StrictJwtSecurityTokenHandler().ValidateToken(new JwtSecurityTokenHandler().WriteToken(token), Parameters(null), out validated); return false; }
        catch (SecurityTokenException) { return true; }
    }
    public static bool SignedAccepted()
    {
        using (var rsa = RSA.Create())
        {
            rsa.KeySize = 2048;
            var key = new RsaSecurityKey(rsa) { KeyId = "synthetic-signing-key" };
            var token = new JwtSecurityToken(Issuer, Audience, new[] { new Claim("oid", "33333333-3333-3333-3333-333333333333") }, DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddMinutes(10), new SigningCredentials(key, SecurityAlgorithms.RsaSha256));
            SecurityToken validated;
            var principal = new StrictJwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(new JwtSecurityTokenHandler().WriteToken(token), Parameters(key), out validated);
            return principal.FindFirst("oid")?.Value == "33333333-3333-3333-3333-333333333333";
        }
    }
    public static bool WrongIssuerRejected() => InvalidSignedRejected("https://attacker.test/v2.0", Audience, DateTime.UtcNow.AddMinutes(10), false);
    public static bool WrongAudienceRejected() => InvalidSignedRejected(Issuer, "77777777-7777-7777-7777-777777777777", DateTime.UtcNow.AddMinutes(10), false);
    public static bool ExpiredRejected() => InvalidSignedRejected(Issuer, Audience, DateTime.UtcNow.AddMinutes(-10), false);
    public static bool ForeignKeyRejected() => InvalidSignedRejected(Issuer, Audience, DateTime.UtcNow.AddMinutes(10), true);
    private static bool InvalidSignedRejected(string issuer, string audience, DateTime expires, bool useForeignKey)
    {
        using (var rsa = RSA.Create())
        using (var foreign = RSA.Create())
        {
            rsa.KeySize = 2048; foreign.KeySize = 2048;
            var key = new RsaSecurityKey(rsa) { KeyId = "synthetic-signing-key" };
            var token = new JwtSecurityToken(issuer, audience, new[] { new Claim("oid", "33333333-3333-3333-3333-333333333333") }, expires.AddMinutes(-1), expires, new SigningCredentials(key, SecurityAlgorithms.RsaSha256));
            SecurityToken validated;
            try { new StrictJwtSecurityTokenHandler().ValidateToken(new JwtSecurityTokenHandler().WriteToken(token), Parameters(useForeignKey ? new RsaSecurityKey(foreign) : key), out validated); return false; }
            catch (SecurityTokenException) { return true; }
        }
    }
    private static TokenValidationParameters Parameters(SecurityKey key) => new TokenValidationParameters {
        // Reproduce Katana 4.2.3 changing the value for authorization-code ID tokens.
        RequireSignedTokens = false, ValidateIssuerSigningKey = false, IssuerSigningKey = key,
        ValidateIssuer = true, ValidIssuer = Issuer, ValidateAudience = true, ValidAudience = Audience,
        ValidateLifetime = true, RequireExpirationTime = true
    };
}
