using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using static MultiIdpApp.Identity.AuthSchemes;

namespace MultiIdpApp.Pages;

[AllowAnonymous]
public sealed class SignOutModel : PageModel
{
    public async Task<IActionResult> OnPostAsync()
    {
        var external = User.FindFirstValue("identity_source") == ExternalSource;
        var cookie = external ? ExternalCookie : WorkforceCookie;
        var oidc = external ? ExternalOidc : WorkforceOidc;
        var authentication = await HttpContext.AuthenticateAsync(cookie);
        var properties = new AuthenticationProperties { RedirectUri = "/" };
        var idToken = authentication.Properties?.GetTokenValue("id_token");
        if (!string.IsNullOrWhiteSpace(idToken))
        {
            properties.StoreTokens(
                [new AuthenticationToken { Name = "id_token", Value = idToken }]);
        }
        await HttpContext.SignOutAsync(WorkforceCookie);
        await HttpContext.SignOutAsync(ExternalCookie);
        return authentication.Succeeded
            ? SignOut(properties, oidc)
            : RedirectToPage("/Index");
    }
}
