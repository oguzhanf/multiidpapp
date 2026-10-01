using System;
using System.Net;
using System.Security.Claims;
using System.Web;
using System.Web.Helpers;
using System.Web.Mvc;
using Microsoft.Owin.Security;

namespace MultiIdp.Net48
{
    public sealed class AntiforgeryFailureFilter : FilterAttribute, IExceptionFilter
    {
        public void OnException(ExceptionContext context)
        {
            if (!(context.Exception is HttpAntiForgeryException)) return;
            context.ExceptionHandled = true;
            context.HttpContext.Response.Cache.SetNoStore();
            context.HttpContext.Response.Headers["Referrer-Policy"] = "no-referrer";
            context.Result = new HttpStatusCodeResult(400, "The form verification token is missing or invalid.");
        }
    }
    public sealed class HomeController : Controller
    {
        [HttpGet]
        public ActionResult Index()
        {
            var configured = Startup.ConfigurationError == null && Startup.Config != null;
            var message = configured ? "Choose your email to start. Your email selects a directory; admission requires validated identity and approval." : "Configuration needed: " + Startup.ConfigurationError;
            if (configured && Request.QueryString["registration"] == "complete") message = "Registration completed. Sign in with your invited account to check application access.";
            var form = Request.IsSecureConnection ? "<form method='post' action='/Account/Login'>" + AntiForgery.GetHtml().ToHtmlString() + "<label for='email'>Work or personal email</label><input id='email' name='email' type='email' autocomplete='username' maxlength='254' required><button type='submit'>Sign in</button></form>" : "<p>Open this application over HTTPS to sign in.</p>";
            return Content(Page("Welcome", "<p>" + Encode(message) + "</p>" + form + "<p><a href='/Benefits/Index'>Check my application access</a></p><p class='note'>Employee domains use the workforce directory. Approved partner routes are available in sampleapp02. Other addresses use External ID. A Microsoft 365 partner must complete organizational B2B onboarding.</p>"), "text/html");
        }
        [HttpGet]
        public ActionResult Code()
        {
            var body = @"<p>Browse the source used by this application.</p>
<label for='code-file'>Source file</label>
<div class='code-toolbar'><select id='code-file' disabled><option>Loading samples...</option></select><button id='copy-code' type='button' hidden>Copy code</button></div>
<p id='code-purpose'>Choose a source file.</p>
<p class='note'><span id='code-path'></span><span id='code-language'></span></p>
<pre id='code-view' tabindex='0' aria-label='Selected source code'>Loading source code...</pre>
<p id='code-status' class='note' role='status' aria-live='polite'></p>
<p><a href='" + DriverOrigin + @"/source/net48-source.zip'>Download source ZIP</a> <span class='note'>(Caldova administrator sign-in)</span></p>
<noscript><p>Enable JavaScript to browse these samples, or download the source ZIP.</p></noscript>
<script src='/code-samples.js'></script>
<script>
(function () {
  'use strict';
  const appId = '" + Startup.AppId + @"';
  const select = document.getElementById('code-file');
  const view = document.getElementById('code-view');
  const purpose = document.getElementById('code-purpose');
  const pathLabel = document.getElementById('code-path');
  const language = document.getElementById('code-language');
  const copy = document.getElementById('copy-code');
  const status = document.getElementById('code-status');
  const catalog = window.pocCodeSamples;
  const paths = catalog && catalog.apps && catalog.apps[appId];
  const files = catalog && Array.isArray(catalog.files) && Array.isArray(paths)
    ? paths.map(function (path) { return catalog.files.find(function (file) { return file.path === path; }); })
      .filter(function (file) { return file && typeof file.path === 'string' && typeof file.content === 'string'; })
    : [];
  if (!files.length) {
    select.options[0].textContent = 'Samples unavailable';
    purpose.textContent = 'The source samples are not available here yet.';
    view.textContent = '';
    status.textContent = 'Open the onsite driver source library or download the source ZIP.';
    return;
  }
  select.textContent = '';
  files.forEach(function (file) {
    const option = document.createElement('option');
    option.value = file.path;
    option.textContent = file.path;
    select.appendChild(option);
  });
  select.disabled = false;
  function render() {
    const file = files.find(function (entry) { return entry.path === select.value; });
    if (!file) return;
    purpose.textContent = file.title || file.path;
    pathLabel.textContent = file.path;
    language.textContent = file.language ? ' · ' + file.language : '';
    view.textContent = file.content;
    view.scrollTop = 0;
    view.scrollLeft = 0;
    status.textContent = '';
  }
  select.addEventListener('change', render);
  select.value = files[0].path;
  render();
  if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
    copy.hidden = false;
    copy.addEventListener('click', function () {
      navigator.clipboard.writeText(view.textContent).then(function () {
        status.textContent = 'Code copied.';
      }).catch(function () {
        status.textContent = 'Copy was blocked. Select the code to copy it manually.';
      });
    });
  }
}());
</script>";
            return Content(Page("Code samples", body, true), "text/html");
        }
        private const string DriverOrigin = "https://caldova-pocdriver-07279263.azurewebsites.net";
        internal static string Encode(string text) => HttpUtility.HtmlEncode(text);
        internal static string Page(string title, string content, bool wide = false) => "<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>" + Encode(title) + " · " + Startup.AppId + "</title><style>body{font:17px/1.6 system-ui,sans-serif;margin:0;background:#edf3f7;color:#182a38}main{max-width:680px;margin:7vh auto;padding:32px;background:white;border-radius:14px;box-shadow:0 12px 42px #172a3810}main.code-page{max-width:1100px}h1{line-height:1.2}nav{display:flex;flex-wrap:wrap;gap:10px 20px;padding-bottom:18px;border-bottom:1px solid #e1e8ed;margin-bottom:24px;font-size:14px}nav span{font-size:12px}label,input,button{display:block}input,select{box-sizing:border-box;width:100%;padding:12px;margin:8px 0 16px;border:1px solid #8799a6;border-radius:5px;font:inherit}input[type=checkbox]{display:inline-block;width:auto;margin:0 9px 0 0;padding:0}.check{margin:12px 0 20px}section{margin-top:28px;padding-top:12px;border-top:1px solid #e1e8ed}button{background:#145c70;color:white;border:0;border-radius:5px;padding:11px 22px;font:inherit;cursor:pointer}button[hidden]{display:none}a{color:#145c70}.note{font-size:14px;color:#596977}.brand{font-size:13px;letter-spacing:.08em;text-transform:uppercase}.code-toolbar{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.code-toolbar select{flex:1;min-width:240px;margin:8px 0}.code-toolbar button{white-space:nowrap}pre{box-sizing:border-box;background:#102734;color:#edf5fa;border-radius:8px;padding:20px;max-height:65vh;overflow:auto;white-space:pre;tab-size:4;font:14px/1.6 Consolas,monospace}pre:focus{outline:3px solid #b7dbe5}@media(max-width:720px){main{margin:16px;padding:24px}.code-toolbar select{min-width:100%}}</style></head><body><main" + (wide ? " class='code-page'" : "") + "><p class='brand'>" + Startup.AppId + " · ASP.NET Framework 4.8</p><nav aria-label='Application navigation'><a href='/'>Home</a><a href='/Home/Code'>Code samples</a>" + RegistrationNavigation() + "<a href='" + DriverOrigin + "/#code/" + Startup.AppId + "'>Onsite driver <span>(Caldova administrator sign-in)</span></a></nav><h1>" + Encode(title) + "</h1>" + content + "</main></body></html>";
        private static string RegistrationNavigation()
        {
            var user = System.Web.HttpContext.Current?.User;
            if (user?.Identity?.IsAuthenticated != true || Startup.Config == null || Startup.ConfigurationError != null) return "";
            try
            {
                if (!RegistrationRuntime.Enabled(Startup.Config)) return "";
                var principal = user as ClaimsPrincipal ?? new ClaimsPrincipal(user);
                var entries = RegistrationRuntime.ReadEntitlements(Startup.Config);
                return RegistrationPolicy.Authorize(Startup.Config, principal, entries, RegistrationKind.Dependent, DateTimeOffset.UtcNow).Allowed || RegistrationPolicy.Authorize(Startup.Config, principal, entries, RegistrationKind.ExternalBusiness, DateTimeOffset.UtcNow).Allowed ? "<a href='/Registration/Index'>Invite someone</a>" : "";
            }
            catch (Exception ex) when (ex is RegistrationException || ex is ConfigurationException || ex is System.IO.IOException || ex is UnauthorizedAccessException || ex is Newtonsoft.Json.JsonException) { return ""; }
        }
    }

    public sealed class AccountController : Controller
    {
        [HttpPost, ValidateAntiForgeryToken]
        public ActionResult Login(string email)
        {
            if (!Request.IsSecureConnection) return new HttpStatusCodeResult(400, "HTTPS is required.");
            if (Startup.ConfigurationError != null || Startup.Config == null) return Content(HomeController.Page("Configuration needed", "<p>" + HomeController.Encode(Startup.ConfigurationError) + "</p><a href='/'>Return home</a>"), "text/html");
            IdentitySource source;
            try { source = RegistrationRuntime.Route(Startup.Config, email); }
            catch (ArgumentException ex) { Response.StatusCode = 400; return Content(HomeController.Page("Email required", "<p>" + HomeController.Encode(ex.Message) + "</p><a href='/'>Return home</a>"), "text/html"); }
            catch (Exception ex) when (ex is RegistrationException || ex is ConfigurationException || ex is System.IO.IOException || ex is UnauthorizedAccessException || ex is Newtonsoft.Json.JsonException)
            { Response.StatusCode = 503; return Content(HomeController.Page("Sign-in routing unavailable", "<p>Application approvals are temporarily unavailable. Try again or contact your application administrator.</p><a href='/'>Return home</a>"), "text/html"); }
            var properties = new AuthenticationProperties { RedirectUri = "/Benefits/Index" };
            properties.Dictionary["login_hint"] = email.Trim();
            HttpContext.GetOwinContext().Authentication.Challenge(properties, source == IdentitySource.Workforce ? "workforce" : "external");
            return new HttpUnauthorizedResult();
        }
        [HttpPost, ValidateAntiForgeryToken]
        public ActionResult Logout()
        {
            if (!Request.IsSecureConnection) return new HttpStatusCodeResult(400, "HTTPS is required.");
            HttpContext.GetOwinContext().Authentication.SignOut(Startup.CookieScheme);
            return Redirect("/");
        }
        [HttpGet]
        public ActionResult Failure()
        {
            Response.StatusCode = 403;
            return Content(HomeController.Page("Sign-in was not completed", "<p>The selected directory could not authenticate or approve this account. Check its directory assignment, role, application approval and sign-in policy with your administrator.</p><p>Workforce failures do not switch to External ID.</p><a href='/'>Return home</a>"), "text/html");
        }
    }

    public sealed class BenefitsController : Controller
    {
        [HttpGet]
        public ActionResult Index()
        {
            if (User?.Identity?.IsAuthenticated != true) return Redirect("/");
            if (!Request.IsSecureConnection) return new HttpStatusCodeResult(400, "HTTPS is required.");
            if (Startup.Config == null || Startup.ConfigurationError != null) return new HttpStatusCodeResult(503, "Application identity configuration is unavailable.");
            Response.Cache.SetCacheability(HttpCacheability.NoCache); Response.Cache.SetNoStore();
            if (RegistrationSignInPolicy.IsRegistrationOnly(User as ClaimsPrincipal ?? new ClaimsPrincipal(User)))
            {
                Response.StatusCode = 403;
                return Content(HomeController.Page("Finish registration", "<p>Complete your invitation and sign in again before checking application access.</p><p><a href='/Registration/Complete'>Complete registration</a></p>" + LogoutForm()), "text/html");
            }
            AdmissionDecision admission;
            try { admission = RegistrationSignInPolicy.EvaluateApplicationAccess(Startup.Config, User as ClaimsPrincipal ?? new ClaimsPrincipal(User), RegistrationRuntime.ReadEntitlements(Startup.Config), DateTimeOffset.UtcNow); }
            catch (Exception ex) when (ex is RegistrationException || ex is ConfigurationException || ex is System.IO.IOException || ex is Newtonsoft.Json.JsonException || ex is UnauthorizedAccessException) { admission = new AdmissionDecision { Allowed = false, Reason = "Application approvals are temporarily unavailable." }; }
            if (!admission.Allowed)
            {
                Response.StatusCode = 403;
                return Content(HomeController.Page("Access denied", "<p>" + HomeController.Encode(admission.Reason) + "</p>" + LogoutForm()), "text/html");
            }
            var entry = admission.Entitlement;
            var body = "<p>Your verified identity has current approval as <strong>" + HomeController.Encode(entry.Persona) + "</strong> for " + Startup.AppId + ".</p><p>Identity source: " + HomeController.Encode(entry.Source) + ". Approval expires " + HomeController.Encode(entry.ExpiresUtc.ToString("u")) + ".</p><p>This demonstration grants application access only. Fulfillment of real benefits requires your organization's benefit rules.</p>" + LogoutForm();
            return Content(HomeController.Page("Application access approved", body), "text/html");
        }
        private static string LogoutForm() => "<form method='post' action='/Account/Logout'>" + AntiForgery.GetHtml().ToHtmlString() + "<button type='submit'>Sign out of this app</button></form>";
    }
}
