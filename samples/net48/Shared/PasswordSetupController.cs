using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Helpers;
using System.Web.Mvc;

namespace MultiIdp.Net48
{
    public sealed partial class RegistrationController
    {
        private const string PasswordSessionKey = "invitation-password-setup";
        private static string InvitationForm(string action, string token, string label) => "<form method='post' action='/Registration/" + action + "'>" + AntiForgery.GetHtml().ToHtmlString() + "<input type='hidden' name='token' value='" + HomeController.Encode(token) + "'><button type='submit'>" + label + "</button></form>";

        [HttpPost, ValidateAntiForgeryToken, AsyncTimeout(120000)]
        public async Task<ActionResult> StartPasswordSetup(string token)
        {
            var guard = Guard(); if (guard != null) return guard;
            try {
                var invitation = RegistrationRuntime.Store(Startup.Config).Preview(Startup.Config, token, DateTimeOffset.UtcNow);
                if (invitation.Source != "external") throw new RegistrationException("Use your organization's account for this invitation.");
                var previous = Session[PasswordSessionKey] as PasswordSetupSession;
                if (previous != null && previous.InvitationId == invitation.Id && previous.ExpiresUtc > DateTimeOffset.UtcNow && new[] { "email", "password", "pending", "complete" }.Contains(previous.Stage)) {
                    previous.RequireInvitation(invitation); return Redirect("/Registration/PasswordSetup");
                }
                var settings = RegistrationRuntime.Settings(Startup.Config);
                var api = PasswordApi(); // Validate setup configuration before reserving a send.
                var roles = await RegistrationRuntime.CurrentSponsorRolesAsync(Startup.Config, invitation);
                var sponsor = RegistrationPolicy.RecheckSponsor(Startup.Config, invitation, RegistrationRuntime.ReadEntitlements(Startup.Config), roles, DateTimeOffset.UtcNow);
                if (!sponsor.Allowed) throw new RegistrationException(sponsor.Reason);
                var user = await RegistrationRuntime.GraphAsync(settings, true, HttpMethod.Get, "/users/" + RegistrationPolicy.GuidValue(invitation.ObjectId) + "?$select=id,accountEnabled,identities");
                if ((bool?)user["accountEnabled"] != true || !user["identities"].Any(i => (string)i["signInType"] == "emailAddress" && (string)i["issuer"] == settings.External.InitialDomain && string.Equals((string)i["issuerAssignedId"], invitation.RecipientEmail, StringComparison.OrdinalIgnoreCase)))
                    throw new RegistrationException("The invited account is no longer available for setup.");
                RegistrationRuntime.Store(Startup.Config).ReservePasswordSetup(Startup.Config, token, DateTimeOffset.UtcNow);
                var session = new PasswordSetupSession { AppId = Startup.AppId, InvitationId = invitation.Id, ObjectId = invitation.ObjectId, InvitationToken = token, Stage = "new", ExpiresUtc = invitation.ExpiresUtc < DateTimeOffset.UtcNow.AddMinutes(10) ? invitation.ExpiresUtc : DateTimeOffset.UtcNow.AddMinutes(10) };
                Session[PasswordSessionKey] = session;
                await api.StartAsync(session, invitation.RecipientEmail);
                return Redirect("/Registration/PasswordSetup");
            } catch (RegistrationException ex) { return Error(400, "Account setup", ex.Message); }
            catch (Exception ex) when (Expected(ex)) { return Unavailable(ex); }
        }

        [HttpGet]
        public ActionResult PasswordSetup()
        {
            var guard = Guard(); if (guard != null) return guard;
            try { return PasswordPage(ReadPasswordSession()); }
            catch (RegistrationException ex) { return Error(400, "Account setup", ex.Message); }
            catch (Exception ex) when (Expected(ex)) { return Unavailable(ex); }
        }

        [HttpPost, ValidateAntiForgeryToken, AsyncTimeout(120000)]
        public async Task<ActionResult> VerifySetupEmail(string code)
        {
            var guard = Guard(); if (guard != null) return guard;
            try { var session = ReadPasswordSession(); await PasswordApi().VerifyAsync(session, code); return Redirect("/Registration/PasswordSetup"); }
            catch (RegistrationException ex) { return PasswordError(ex); }
            catch (Exception ex) when (Expected(ex)) { return Unavailable(ex); }
            finally { ModelState.Clear(); code = null; }
        }

        [HttpPost, ValidateAntiForgeryToken, ValidateInput(false), AsyncTimeout(120000)]
        public async Task<ActionResult> CreatePassword(string password, string confirmPassword)
        {
            var guard = Guard(); if (guard != null) return guard;
            try { var session = ReadPasswordSession(); await PasswordApi().SubmitAsync(session, password, confirmPassword); return Redirect("/Registration/PasswordSetup"); }
            catch (RegistrationException ex) { return PasswordError(ex); }
            catch (Exception ex) when (Expected(ex)) { return Unavailable(ex); }
            finally { ModelState.Clear(); password = null; confirmPassword = null; }
        }

        [HttpPost, ValidateAntiForgeryToken, AsyncTimeout(120000)]
        public async Task<ActionResult> CheckPasswordSetup()
        {
            var guard = Guard(); if (guard != null) return guard;
            try { var session = ReadPasswordSession(); await PasswordApi().PollAsync(session); return Redirect("/Registration/PasswordSetup"); }
            catch (RegistrationException ex) { return PasswordError(ex); }
            catch (Exception ex) when (Expected(ex)) { return Unavailable(ex); }
        }

        private PasswordSetupSession ReadPasswordSession()
        {
            var session = Session[PasswordSessionKey] as PasswordSetupSession;
            if (session == null) throw new RegistrationException("Reopen your invitation to start account setup.");
            session.RequireInvitation(RegistrationRuntime.Store(Startup.Config).Preview(Startup.Config, session.InvitationToken, DateTimeOffset.UtcNow));
            return session;
        }
        private NativePasswordSetup PasswordApi()
        {
            var settings = RegistrationRuntime.Settings(Startup.Config);
            return new NativePasswordSetup(Startup.Config.External.CiamDomain, settings.External.InitialDomain, settings.External.PasswordSetupClientId);
        }
        private ActionResult PasswordError(RegistrationException error)
        {
            ModelState.Clear();
            try { return PasswordPage(ReadPasswordSession(), error.Message); }
            catch (RegistrationException) { return Error(400, "Account setup", error.Message); }
        }
        private ActionResult PasswordPage(PasswordSetupSession session, string error = null)
        {
            var body = error == null ? "" : "<p role='alert'>" + HomeController.Encode(error) + "</p>";
            string title;
            if (session.Stage == "email") {
                title = "Verify your email";
                body += "<p>Microsoft sent a verification code to your account's email verification address. Enter it below to create your password.</p><form method='post' action='/Registration/VerifySetupEmail'>" + AntiForgery.GetHtml().ToHtmlString()
                    + "<label for='setup-code'>Verification code</label><input id='setup-code' name='code' inputmode='numeric' autocomplete='one-time-code' pattern='[0-9]{" + session.CodeLength + "}' maxlength='" + session.CodeLength + "' required><button type='submit'>Verify email</button></form>";
            } else if (session.Stage == "password") {
                title = "Create your password";
                body += "<p>Your email is verified. Choose a password for your Caldova External ID account. Use 8–256 characters; Microsoft checks its strength.</p><form method='post' action='/Registration/CreatePassword'>" + AntiForgery.GetHtml().ToHtmlString()
                    + "<label for='new-password'>New password</label><input id='new-password' name='password' type='password' autocomplete='new-password' minlength='8' maxlength='256' required><label for='confirm-password'>Confirm password</label><input id='confirm-password' name='confirmPassword' type='password' autocomplete='new-password' minlength='8' maxlength='256' required><button type='submit'>Create password</button></form>";
            } else if (session.Stage == "pending") {
                title = "Finishing account setup";
                body += "<p>Your password was submitted to Microsoft. Check completion in a few seconds.</p><form method='post' action='/Registration/CheckPasswordSetup'>" + AntiForgery.GetHtml().ToHtmlString() + "<button type='submit'>Continue</button></form>";
            } else if (session.Stage == "complete") {
                title = "Your password is ready";
                body += "<p>Sign in with your invited email and new password, then confirm your application registration.</p>" + InvitationForm("Begin", session.InvitationToken, "Continue to sign in");
            } else { title = "Account setup"; body += "<p>Reopen your invitation to continue. If you just submitted a password, try signing in with it before starting again.</p>"; }
            return Content(HomeController.Page(title, body), "text/html");
        }
    }
}
