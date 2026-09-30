namespace MultiIdpApp.Identity;

public static class AuthSchemes
{
    public const string AppSession = "AppSession";
    public const string ChooserCookie = "ChooserCookie";
    public const string WorkforceCookie = "WorkforceCookie";
    public const string ExternalCookie = "ExternalCookie";
    public const string WorkforceOidc = "WorkforceOidc";
    public const string ExternalOidc = "ExternalOidc";
    public const string WorkforceCookieName = ".MultiIdpApp.Workforce";
    public const string ExternalCookieName = ".MultiIdpApp.External";
    public const string WorkforceSource = "Workforce";
    public const string ExternalSource = "ExternalId";
}
