using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MultiIdpApp.Pages;

[Authorize]
[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
public sealed class ProfileModel : PageModel
{
    public string DisplayName { get; private set; } = "Authenticated user";
    public string IdentitySource { get; private set; } = string.Empty;
    public string Email { get; private set; } = "Not provided";
    public string TenantId { get; private set; } = string.Empty;
    public string Subject { get; private set; } = string.Empty;

    public void OnGet()
    {
        DisplayName = User.FindFirstValue("name") ?? User.Identity?.Name ?? DisplayName;
        IdentitySource = User.FindFirstValue("identity_source")!;
        TenantId = User.FindFirstValue("app_tenant_id")!;
        Subject = User.FindFirstValue("app_subject")!;
        Email = User.FindFirstValue("app_email") ?? Email;
    }
}
