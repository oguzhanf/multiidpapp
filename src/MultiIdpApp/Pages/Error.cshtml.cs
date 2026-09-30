using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MultiIdpApp.Pages;

[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
[IgnoreAntiforgeryToken]
public sealed class ErrorModel : PageModel
{
    public string RequestId { get; private set; } = string.Empty;
    public void OnGet() => RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier;
}
