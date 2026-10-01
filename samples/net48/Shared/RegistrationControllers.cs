using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Helpers;
using System.Web.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security;
using Newtonsoft.Json;

namespace MultiIdp.Net48
{
    public static class RegistrationSignInPolicy
    {
        public const string TokenProperty = "registration_token";
        public const string InvitationIdProperty = "registration_id";
        public const string PendingClaim = "registration_only";

        // The caller has already validated JWT signature, protocol nonce and lifetime.
        // Properties MUST be the Katana ticket properties recovered from protected OIDC state.
        public static void Validate(AppConfiguration config, ClaimsIdentity identity, AuthenticationProperties properties, string source, IEnumerable<Entitlement> entries, JsonInvitationStore invitations, DateTimeOffset now)
        {
            if (!RegistrationPolicy.KnownApp(config) || identity == null || (source != "workforce" && source != "external"))
                throw new SecurityTokenValidationException("Application identity configuration is unavailable.");
            var tenant = source == "external" ? config.External : config.Workforce;
            var principal = new ClaimsPrincipal(identity);
            Guid tid, oid;
            if (!Guid.TryParse(AdmissionPolicy.Single(principal, "tid"), out tid) || !RegistrationPolicy.SameGuid(tid.ToString(), tenant.TenantId) || !Guid.TryParse(AdmissionPolicy.Single(principal, "oid"), out oid) || oid == Guid.Empty)
                throw new SecurityTokenValidationException("Unexpected tenant or missing stable object identifier.");
            foreach (var claim in identity.Claims.Where(c => c.Type == "identity_source" || c.Type == "subject_key" || c.Type == PendingClaim || c.Type == TokenProperty || c.Type == InvitationIdProperty).ToArray()) identity.RemoveClaim(claim);
            identity.AddClaim(new Claim("identity_source", source));
            identity.AddClaim(new Claim("subject_key", tid.ToString() + ":" + oid.ToString()));
            if (AdmissionPolicy.Evaluate(config, principal, entries, now).Allowed) return;
            if (invitations == null || properties == null)
                throw new SecurityTokenValidationException("Application entitlement or signed persona role denied.");
            InvitationRecord invitation;
            try {
                string token;
                // A supplied bearer link must pass its own checks; never fall back from a bad link.
                if (properties.Dictionary.TryGetValue(TokenProperty, out token)) {
                    invitation = invitations.Preview(config, token, now);
                    properties.Dictionary.Remove(InvitationIdProperty);
                } else {
                    invitation = invitations.PreviewForRecipient(config, principal, now);
                    properties.Dictionary[InvitationIdProperty] = invitation.Id;
                }
            }
            catch (Exception ex) when (ex is RegistrationException || ex is IOException || ex is UnauthorizedAccessException || ex is JsonException)
            { throw new SecurityTokenValidationException("The registration invitation is unavailable."); }
            if (!MatchesBoundIdentity(config, invitation, principal, now)) throw new SecurityTokenValidationException("The signed identity does not match this registration invitation.");
            identity.AddClaim(new Claim(PendingClaim, "true"));
            properties.RedirectUri = "/Registration/Complete";
            properties.IsPersistent = false;
            properties.AllowRefresh = false;
            properties.ExpiresUtc = invitation.ExpiresUtc < now.AddMinutes(20) ? invitation.ExpiresUtc : now.AddMinutes(20);
        }
        public static bool IsRegistrationOnly(ClaimsPrincipal principal) => principal?.FindAll(PendingClaim).Any(c => c.Value == "true") == true;

        public static AdmissionDecision EvaluateApplicationAccess(AppConfiguration config, ClaimsPrincipal principal, IEnumerable<Entitlement> entries, DateTimeOffset now)
        {
            return IsRegistrationOnly(principal)
                ? new AdmissionDecision { Allowed = false, Reason = "Complete registration and sign in again before checking application access." }
                : AdmissionPolicy.Evaluate(config, principal, entries, now);
        }

        public static bool MatchesBoundIdentity(AppConfiguration config, InvitationRecord invitation, ClaimsPrincipal principal, DateTimeOffset now)
        {
            if (!RegistrationPolicy.KnownApp(config) || invitation == null || principal?.Identity?.IsAuthenticated != true || invitation.AppId != config.AppId || invitation.Status != "ready" || invitation.ExpiresUtc <= now)
                return false;
            var tenant = invitation.Source == "external" ? config.External : invitation.Source == "workforce" ? config.Workforce : null;
            if (tenant == null || !RegistrationPolicy.SameGuid(invitation.TenantId, tenant.TenantId) || !RegistrationPolicy.SameGuid(AdmissionPolicy.Single(principal, "tid"), invitation.TenantId) || !RegistrationPolicy.SameGuid(AdmissionPolicy.Single(principal, "oid"), invitation.ObjectId) || AdmissionPolicy.Single(principal, "identity_source") != invitation.Source || AdmissionPolicy.Single(principal, "iss") != tenant.Issuer || !RegistrationPolicy.SameGuid(AdmissionPolicy.Single(principal, "aud"), tenant.ClientId))
                return false;
            var expectedPersona = invitation.Kind == RegistrationKind.Dependent ? "dependent" : invitation.Kind == RegistrationKind.ExternalBusiness ? "external" : invitation.Kind == RegistrationKind.OrganizationalPartner ? "partner" : null;
            var role = expectedPersona == "dependent" ? "Dependent" : expectedPersona == "external" ? "External" : expectedPersona == "partner" ? "Partner" : null;
            if (role == null || invitation.Persona != expectedPersona || !principal.FindAll("roles").Any(c => c.Value == role) || invitation.Source != (expectedPersona == "partner" ? "workforce" : "external")) return false;
            if (expectedPersona == "partner")
            {
                Guid home;
                if (!Guid.TryParse(invitation.HomeTenantId, out home) || home == Guid.Empty || invitation.OrganizationVerifiedUtc == null || invitation.OrganizationVerifiedUtc > now) return false;
                var idp = AdmissionPolicy.Single(principal, "idp");
                return idp == "https://sts.windows.net/" + home.ToString() + "/" || idp == "https://login.microsoftonline.com/" + home.ToString() + "/v2.0";
            }
            return true;
        }
    }

    public sealed partial class RegistrationController : Controller
    {
        [HttpGet]
        public ActionResult Index()
        {
            var guard = Guard(); if (guard != null) return guard;
            if (User?.Identity?.IsAuthenticated != true) return Redirect("/");
            try
            {
                var entries = RegistrationRuntime.ReadEntitlements(Startup.Config);
                var principal = CurrentPrincipal();
                var dependent = RegistrationPolicy.Authorize(Startup.Config, principal, entries, RegistrationKind.Dependent, DateTimeOffset.UtcNow).Allowed;
                var business = RegistrationPolicy.Authorize(Startup.Config, principal, entries, RegistrationKind.ExternalBusiness, DateTimeOffset.UtcNow).Allowed;
                if (!dependent && !business) return Error(403, "Registration is not available", "A current employee approval and a permitted directory role are required.");
                var antiForgery = AntiForgery.GetHtml().ToHtmlString();
                var body = "<p>Send a secure invitation. The recipient signs in and completes registration before application access is approved.</p>";
                if (dependent) body += "<section><h2>Invite a dependent</h2><p>Use their personal email address. They verify it and set their own password.</p><form method='post' action='/Registration/Invite'>" + antiForgery + "<input type='hidden' name='purpose' value='dependent'><label for='dependent-email'>Dependent personal email</label><input id='dependent-email' name='recipientEmail' type='email' autocomplete='off' maxlength='254' required><label class='check'><input type='checkbox' name='relationshipAttested' value='true' required>I confirm this person is my dependent and eligible under my employee benefit approval.</label><button type='submit'>Send dependent invitation</button></form></section>";
                if (business) body += "<section><h2>Invite a vendor or business partner</h2><p>Use a personal or Microsoft 365 work email. Verified organizations use their organizational sign-in; personal email accounts use External ID account setup.</p><form method='post' action='/Registration/Invite'>" + antiForgery + "<input type='hidden' name='purpose' value='business'><label for='business-email'>Vendor or business partner email</label><input id='business-email' name='recipientEmail' type='email' autocomplete='off' maxlength='254' required><button type='submit'>Send business invitation</button></form></section>";
                body += "<section><h2>Your invitations</h2><p>Only your invitations are shown. An unsent account-setup failure can be canceled before trying a fresh invitation.</p>";
                foreach (var row in RegistrationRuntime.Store(Startup.Config).ReadForSponsor(Startup.Config, principal).OrderByDescending(r => r.CreatedUtc)) {
                    body += "<p><strong>" + HomeController.Encode(MaskEmail(row.RecipientEmail)) + "</strong> · " + HomeController.Encode(row.Persona) + " · " + HomeController.Encode(row.Status) + " · email: " + HomeController.Encode(row.EmailStatus) + "</p>";
                    if ((row.Status == "pending_identity" || row.Status == "ready") && row.EmailStatus == "not_sent" && row.EmailOperationId == null && RegistrationPolicy.Authorize(Startup.Config, principal, entries, row.Kind, DateTimeOffset.UtcNow).Allowed)
                        body += "<form method='post' action='/Registration/CancelUnsent'>" + antiForgery + "<input type='hidden' name='invitationId' value='" + HomeController.Encode(row.Id) + "'><button type='submit'>Cancel unsent invitation</button></form>";
                }
                body += "</section>";
                return Content(HomeController.Page("Invite someone", body), "text/html");
            }
            catch (Exception ex) when (Expected(ex)) { return Unavailable(ex); }
        }

        [HttpPost, ValidateAntiForgeryToken, AsyncTimeout(120000)]
        public async Task<ActionResult> CancelUnsent(string invitationId)
        {
            var guard = Guard(); if (guard != null) return guard;
            if (User?.Identity?.IsAuthenticated != true) return Error(403, "Employee sign-in required", "Sign in with your approved employee account to manage invitations.");
            try {
                var principal = CurrentPrincipal(); var store = RegistrationRuntime.Store(Startup.Config);
                var row = store.ReadForSponsor(Startup.Config, principal).SingleOrDefault(r => r.Id == invitationId);
                if (row == null || (row.Status != "pending_identity" && row.Status != "ready") || row.EmailStatus != "not_sent" || row.EmailOperationId != null) return Error(403, "Cancellation is not permitted", "Only your invitation that has not reached email submission can be canceled.");
                var allowed = RegistrationPolicy.Authorize(Startup.Config, principal, RegistrationRuntime.ReadEntitlements(Startup.Config), row.Kind, DateTimeOffset.UtcNow);
                if (!allowed.Allowed) return Error(403, "Cancellation is not permitted", allowed.Reason);
                var roles = await RegistrationRuntime.CurrentSponsorRolesAsync(Startup.Config, row);
                var current = RegistrationPolicy.RecheckSponsor(Startup.Config, row, RegistrationRuntime.ReadEntitlements(Startup.Config), roles, DateTimeOffset.UtcNow);
                if (!current.Allowed) return Error(403, "Cancellation is not permitted", current.Reason);
                store.CancelBeforeDelivery(Startup.Config, row.Id, DateTimeOffset.UtcNow);
                return Redirect("/Registration/Index");
            }
            catch (RegistrationException ex) { RecordFailure(ex); return Error(403, "Cancellation is not permitted", "This invitation cannot be safely canceled."); }
            catch (Exception ex) when (Expected(ex)) { return Unavailable(ex); }
        }

        [HttpGet]
        public ActionResult Accept(string token)
        {
            var guard = Guard(); if (guard != null) return guard;
            try
            {
                var invitation = RegistrationRuntime.Store(Startup.Config).Preview(Startup.Config, token, DateTimeOffset.UtcNow);
                var body = "<p>This invitation is for <strong>" + HomeController.Encode(MaskEmail(invitation.RecipientEmail)) + "</strong> in " + Startup.AppId + ".</p>";
                if (invitation.Source == "external") {
                    body += "<p>Verify your email, then create your password. Your password is for your Caldova External ID account.</p>" + InvitationForm("StartPasswordSetup", token, "Verify email and create password")
                        + "<p>Already have an account in this External ID directory?</p>" + InvitationForm("Begin", token, "Sign in with my existing account");
                } else body += "<p>Continue with your invited Microsoft 365 work account.</p>" + InvitationForm("Begin", token, "Continue with my work account");
                return Content(HomeController.Page("Accept your invitation", body), "text/html");
            }
            catch (RegistrationException) { return Error(400, "Invitation unavailable", "This invitation is invalid, expired, already used or belongs to another application."); }
            catch (Exception ex) when (Expected(ex)) { return Unavailable(ex); }
        }

        [HttpPost, ValidateAntiForgeryToken]
        public ActionResult Begin(string token)
        {
            var guard = Guard(); if (guard != null) return guard;
            try
            {
                var invitation = RegistrationRuntime.Store(Startup.Config).Preview(Startup.Config, token, DateTimeOffset.UtcNow);
                var properties = new AuthenticationProperties { RedirectUri = "/Registration/Complete" };
                properties.Dictionary[RegistrationSignInPolicy.TokenProperty] = token;
                properties.Dictionary["login_hint"] = invitation.RecipientEmail;
                var authentication = HttpContext.GetOwinContext().Authentication;
                authentication.SignOut(Startup.CookieScheme);
                authentication.Challenge(properties, invitation.Source);
                return new HttpUnauthorizedResult();
            }
            catch (RegistrationException) { return Error(400, "Invitation unavailable", "This invitation is invalid, expired, already used or belongs to another application."); }
            catch (Exception ex) when (Expected(ex)) { return Unavailable(ex); }
        }

        [HttpPost, ValidateAntiForgeryToken, AsyncTimeout(180000)]
        public async Task<ActionResult> Invite(string purpose, string recipientEmail, bool relationshipAttested = false)
        {
            var guard = Guard(); if (guard != null) return guard;
            if (User?.Identity?.IsAuthenticated != true) return Error(403, "Employee sign-in required", "Sign in with your approved employee account to send an invitation.");
            try
            {
                RegistrationKind kind;
                if (purpose == "dependent") kind = RegistrationKind.Dependent;
                else if (purpose == "business") kind = RegistrationKind.ExternalBusiness;
                else return Error(400, "Choose an invitation purpose", "Choose dependent or business registration.");
                var permitted = RegistrationPolicy.Authorize(Startup.Config, CurrentPrincipal(), RegistrationRuntime.ReadEntitlements(Startup.Config), kind, DateTimeOffset.UtcNow);
                if (!permitted.Allowed) return Error(403, "Registration is not permitted", permitted.Reason);
                if (kind == RegistrationKind.Dependent && !relationshipAttested) return Error(400, "Relationship confirmation required", "Confirm the dependent relationship and benefit eligibility before sending an invitation.");
                await RegistrationRuntime.InviteAsync(Startup.Config, CurrentPrincipal(), kind, recipientEmail, relationshipAttested);
                return Content(HomeController.Page("Invitation email sent", "<p>The secure invitation email was sent. The recipient must finish account setup and confirm registration before application access is approved.</p><p><a href='/Registration/Index'>Send another invitation</a></p>"), "text/html");
            }
            catch (RegistrationException ex) { return Error(400, "Invitation status", ex.Message); }
            catch (Exception ex) when (Expected(ex)) { return Unavailable(ex); }
        }

        [HttpGet]
        public async Task<ActionResult> Complete()
        {
            var guard = Guard(); if (guard != null) return guard;
            try
            {
                await ReadCompletion();
                var body = "<p>Your signed-in account matches this invitation. Confirm below to finish registration and request application access.</p><p>Your sponsor's approval and registration permissions will be checked again.</p><form method='post' action='/Registration/Complete'>" + AntiForgery.GetHtml().ToHtmlString() + "<button type='submit'>Confirm registration</button></form>";
                return Content(HomeController.Page("Complete registration", body), "text/html");
            }
            catch (RegistrationException) { return Error(400, "Registration unavailable", "Use your invitation link and sign in with the invited account. The invitation must still be current."); }
            catch (Exception ex) when (Expected(ex)) { return Unavailable(ex); }
        }

        [HttpPost, ValidateAntiForgeryToken, ActionName("Complete"), AsyncTimeout(120000)]
        public async Task<ActionResult> CompletePost()
        {
            var guard = Guard(); if (guard != null) return guard;
            try
            {
                var completion = await ReadCompletion();
                var currentRoles = await RegistrationRuntime.CurrentSponsorRolesAsync(Startup.Config, completion.Invitation);
                var store = RegistrationRuntime.Store(Startup.Config);
                var entries = RegistrationRuntime.ReadEntitlements(Startup.Config);
                if (completion.Token != null) store.Redeem(Startup.Config, completion.Token, completion.Principal, entries, currentRoles, DateTimeOffset.UtcNow);
                else store.RedeemForRecipient(Startup.Config, completion.Invitation.Id, completion.Principal, entries, currentRoles, DateTimeOffset.UtcNow);
                // A new normal sign-in removes the restricted cookie and its invitation property.
                HttpContext.GetOwinContext().Authentication.SignOut(Startup.CookieScheme);
                return Redirect("/?registration=complete");
            }
            catch (RegistrationException ex) { return Error(400, "Registration was not completed", ex.Message); }
            catch (Exception ex) when (Expected(ex)) { return Unavailable(ex); }
        }

        private async Task<CompletionContext> ReadCompletion()
        {
            var ticket = await HttpContext.GetOwinContext().Authentication.AuthenticateAsync(Startup.CookieScheme);
            if (ticket?.Identity?.IsAuthenticated != true || ticket.Properties == null)
                throw new RegistrationException("An authenticated invitation session is required.");
            var principal = new ClaimsPrincipal(ticket.Identity);
            var store = RegistrationRuntime.Store(Startup.Config);
            string token, invitationId;
            InvitationRecord invitation;
            if (ticket.Properties.Dictionary.TryGetValue(RegistrationSignInPolicy.TokenProperty, out token))
                invitation = store.Preview(Startup.Config, token, DateTimeOffset.UtcNow);
            else if (RegistrationSignInPolicy.IsRegistrationOnly(principal) && ticket.Properties.Dictionary.TryGetValue(RegistrationSignInPolicy.InvitationIdProperty, out invitationId))
                invitation = store.PreviewForRecipient(Startup.Config, principal, DateTimeOffset.UtcNow, invitationId);
            else throw new RegistrationException("An authenticated invitation session is required.");
            if (!RegistrationSignInPolicy.MatchesBoundIdentity(Startup.Config, invitation, principal, DateTimeOffset.UtcNow)) throw new RegistrationException("The signed-in account does not match this invitation.");
            return new CompletionContext { Token = token, Invitation = invitation, Principal = principal };
        }
        private ActionResult Guard()
        {
            SensitiveResponse();
            if (!Request.IsSecureConnection) return new HttpStatusCodeResult(400, "HTTPS is required.");
            if (Startup.Config == null || Startup.ConfigurationError != null) return Unavailable();
            try { return RegistrationRuntime.Enabled(Startup.Config) ? null : Unavailable(); }
            catch (Exception ex) when (Expected(ex)) { return Unavailable(ex); }
        }
        private void SensitiveResponse()
        {
            Response.Cache.SetCacheability(HttpCacheability.NoCache); Response.Cache.SetNoStore();
            Response.Headers["Referrer-Policy"] = "no-referrer";
            Response.Headers["X-Robots-Tag"] = "noindex, nofollow";
        }
        private ClaimsPrincipal CurrentPrincipal() => User as ClaimsPrincipal ?? new ClaimsPrincipal(User);
        private ActionResult Unavailable(Exception failure = null)
        {
            RecordFailure(failure);
            return Error(503, "Registration is temporarily unavailable", "Ask your application administrator to check registration setup, then try again.");
        }
        private void RecordFailure(Exception failure)
        {
            if (failure != null) try {
                var failures = new List<object>(); var current = failure;
                for (var depth = 0; current != null && depth < 2; depth++, current = current.InnerException)
                    failures.Add(new { type = current.GetType().Name, hResult = "0x" + current.HResult.ToString("X8", System.Globalization.CultureInfo.InvariantCulture) });
                var directory = Path.Combine(@"D:\home\data\multiidp", Startup.AppId);
                Directory.CreateDirectory(directory);
                System.IO.File.WriteAllText(Path.Combine(directory, "registration-failure.json"), JsonConvert.SerializeObject(new { utc = DateTimeOffset.UtcNow, stage = "registration_failure", failures }));
            } catch { /* Diagnostics must never change admission or disclose an exception. */ }
        }
        private ActionResult Error(int status, string title, string message)
        {
            Response.StatusCode = status;
            return Content(HomeController.Page(title, "<p>" + HomeController.Encode(message) + "</p><p><a href='/'>Return home</a></p>"), "text/html");
        }
        private static bool Expected(Exception ex) => ex is RegistrationException || ex is ConfigurationException || ex is IOException || ex is UnauthorizedAccessException || ex is JsonException || ex is System.Net.Http.HttpRequestException || ex is TaskCanceledException;
        private static string MaskEmail(string email)
        {
            var at = email.IndexOf('@'); return at > 0 ? email.Substring(0, 1) + "***" + email.Substring(at) : "the invited account";
        }
        private sealed class CompletionContext { public string Token { get; set; } public InvitationRecord Invitation { get; set; } public ClaimsPrincipal Principal { get; set; } }
    }
}
