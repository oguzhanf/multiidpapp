using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace MultiIdp.Net48
{
    public sealed class StrictJwtSecurityTokenHandler : JwtSecurityTokenHandler
    {
        public override ClaimsPrincipal ValidateToken(string token, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            // Katana 4.2.3 changes RequireSignedTokens=false for code-flow ID tokens.
            // Enforce it at the validation boundary while keeping standard validation.
            var strict = validationParameters.Clone();
            strict.RequireSignedTokens = true;
            strict.ValidateIssuerSigningKey = true;
            return base.ValidateToken(token, strict, out validatedToken);
        }
    }
}
