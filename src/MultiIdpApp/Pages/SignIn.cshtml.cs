using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using MultiIdpApp.Identity;

namespace MultiIdpApp.Pages;

public sealed class SignInModel(IdentityRouter router) : PageModel
{
    [BindProperty]
    public string? Email { get; set; }
    public string? ErrorMessage { get; private set; }

    public IActionResult OnGet() =>
        User.Identity?.IsAuthenticated == true ? RedirectToPage("/Profile") : Page();

    public IActionResult OnPost()
    {
        if (!router.TryNormalize(Email, out var email))
        {
            ErrorMessage = "Enter a valid email address.";
            return Page();
        }

        var properties = new AuthenticationProperties { RedirectUri = "/Profile" };
        properties.SetParameter(IdentityRouter.LoginHintParameter, email);
        return Challenge(properties, router.SelectScheme(email));
    }
}
