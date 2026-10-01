using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace MultiIdp.Net48
{
    // Server-side ASP.NET session only. Never serialize this into a URL, cookie or log.
    // No password or email verification code is retained in this object.
    public sealed class PasswordSetupSession
    {
        public string AppId { get; set; }
        public string InvitationId { get; set; }
        public string ObjectId { get; set; }
        public string InvitationToken { get; set; }
        public string ContinuationToken { get; set; }
        public string Stage { get; set; }
        public int CodeLength { get; set; }
        public DateTimeOffset ExpiresUtc { get; set; }
        public DateTimeOffset NextPollUtc { get; set; }
        public int PollIntervalSeconds { get; set; }
        public void RequireInvitation(InvitationRecord invitation)
        {
            if (ExpiresUtc <= DateTimeOffset.UtcNow || invitation == null || invitation.AppId != AppId || invitation.Id != InvitationId || invitation.ObjectId != ObjectId || invitation.Source != "external" || invitation.Status != "ready" || invitation.ExpiresUtc <= DateTimeOffset.UtcNow)
                throw new RegistrationException("Account setup has expired. Reopen your invitation.");
        }
    }

    // Microsoft's native SSPR protocol sets a recipient-chosen password on the
    // pre-provisioned customer after Microsoft verifies email ownership. This is
    // account setup only: never redeem its continuation token for sign-in tokens.
    // Application sign-in remains MSAL authorization code + PKCE.
    public sealed class NativePasswordSetup
    {
        private readonly Uri root;
        private readonly string clientId;
        private readonly HttpClient http;
        private static readonly HttpClient SharedHttp = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(30) };
        public NativePasswordSetup(string ciamDomain, string initialDomain, string clientId, HttpClient http = null)
        {
            if (ciamDomain == null || !Regex.IsMatch(ciamDomain, "\\A[a-zA-Z0-9-]+\\.ciamlogin\\.com\\z") || initialDomain != ciamDomain.Replace(".ciamlogin.com", ".onmicrosoft.com"))
                throw new RegistrationException("Account setup tenant configuration is invalid.");
            this.clientId = RegistrationPolicy.GuidValue(clientId);
            root = new Uri("https://" + ciamDomain + "/" + initialDomain + "/resetpassword/v1.0/");
            this.http = http ?? SharedHttp;
        }
        public async Task StartAsync(PasswordSetupSession state, string email)
        {
            RequireStage(state, "new"); state.Stage = "starting";
            var started = await SendAsync("start", new Dictionary<string, string> { ["username"] = email, ["challenge_type"] = "oob redirect" }).ConfigureAwait(false);
            state.ContinuationToken = Continuation(started);
            var challenge = await SendAsync("challenge", new Dictionary<string, string> { ["continuation_token"] = state.ContinuationToken, ["challenge_type"] = "oob redirect" }).ConfigureAwait(false);
            if ((string)challenge["challenge_type"] != "oob" || (string)challenge["challenge_channel"] != "email")
                throw new RegistrationException("Microsoft could not start email verification. Contact your application administrator.");
            state.ContinuationToken = Continuation(challenge);
            state.CodeLength = (int?)challenge["code_length"] ?? 8;
            if (state.CodeLength < 4 || state.CodeLength > 12) throw new RegistrationException("Microsoft returned an unsupported verification code format.");
            state.Stage = "email";
        }
        public async Task VerifyAsync(PasswordSetupSession state, string code)
        {
            RequireStage(state, "email");
            if (code == null || !Regex.IsMatch(code, "\\A[0-9]{" + state.CodeLength + "}\\z")) throw new RegistrationException("Enter the verification code from your email.");
            var verified = await SendAsync("continue", new Dictionary<string, string> { ["continuation_token"] = state.ContinuationToken, ["grant_type"] = "oob", ["oob"] = code }).ConfigureAwait(false);
            state.ContinuationToken = Continuation(verified); state.Stage = "password";
            var expires = Math.Min(600, Math.Max(1, (int?)verified["expires_in"] ?? 600));
            var limit = DateTimeOffset.UtcNow.AddSeconds(expires);
            if (limit < state.ExpiresUtc) state.ExpiresUtc = limit;
        }
        public async Task SubmitAsync(PasswordSetupSession state, string password, string confirmation)
        {
            RequireStage(state, "password");
            if (password == null || password.Length < 8 || password.Length > 256) throw new RegistrationException("Use a password between 8 and 256 characters. Microsoft also checks password strength.");
            if (!string.Equals(password, confirmation, StringComparison.Ordinal)) throw new RegistrationException("The passwords do not match.");
            state.Stage = "submitting";
            JObject submitted;
            try { submitted = await SendAsync("submit", new Dictionary<string, string> { ["continuation_token"] = state.ContinuationToken, ["new_password"] = password }).ConfigureAwait(false); }
            catch (PasswordPolicyException) { state.Stage = "password"; throw new RegistrationException("Choose a stronger password that you have not used before."); }
            // An ambiguous timeout stays 'submitting': never automatically resubmit a password.
            state.ContinuationToken = Continuation(submitted);
            state.PollIntervalSeconds = Math.Max(1, (int?)submitted["poll_interval"] ?? 2);
            state.NextPollUtc = DateTimeOffset.UtcNow.AddSeconds(state.PollIntervalSeconds); state.Stage = "pending";
        }
        public async Task PollAsync(PasswordSetupSession state)
        {
            RequireStage(state, "pending");
            if (DateTimeOffset.UtcNow < state.NextPollUtc) return;
            var result = await SendAsync("poll_completion", new Dictionary<string, string> { ["continuation_token"] = state.ContinuationToken }).ConfigureAwait(false);
            var status = (string)result["status"];
            if (status == "succeeded") { state.ContinuationToken = null; state.Stage = "complete"; return; }
            if (status != "in_progress" && status != "not_started") { state.ContinuationToken = null; state.Stage = "failed"; throw new RegistrationException("Microsoft could not finish password creation. Reopen your invitation and try again."); }
            state.ContinuationToken = Continuation(result);
            state.NextPollUtc = DateTimeOffset.UtcNow.AddSeconds(state.PollIntervalSeconds);
        }
        private async Task<JObject> SendAsync(string action, Dictionary<string, string> form)
        {
            form["client_id"] = clientId;
            try {
                using (var request = new HttpRequestMessage(HttpMethod.Post, new Uri(root, action))) {
                    request.Content = new FormUrlEncodedContent(form);
                    using (var response = await http.SendAsync(request).ConfigureAwait(false)) {
                        JObject data;
                        try { data = JObject.Parse(await response.Content.ReadAsStringAsync().ConfigureAwait(false)); }
                        catch (JsonException) { throw new RegistrationException("Microsoft account setup is temporarily unavailable."); }
                        if (!response.IsSuccessStatusCode) {
                            var suberror = (string)data["suberror"];
                            if (action == "submit" && new[] { "password_too_weak", "password_too_short", "password_too_long", "password_recently_used", "password_banned", "password_is_invalid" }.ContainsOrdinal(suberror)) throw new PasswordPolicyException();
                            if (action == "continue" && suberror == "invalid_oob_value") throw new RegistrationException("That verification code is incorrect. Check the email and try again.");
                            if ((int)response.StatusCode == 429) throw new RegistrationException("Too many attempts. Wait a few minutes before trying again.");
                            throw new RegistrationException("Microsoft could not complete this account setup step. Reopen your invitation and try again.");
                        }
                        if ((string)data["challenge_type"] == "redirect") throw new RegistrationException("This account requires an authentication method not available in this setup flow. Contact your application administrator.");
                        return data;
                    }
                }
            } finally { form.Clear(); }
        }
        private static string Continuation(JObject data)
        {
            var value = (string)data["continuation_token"];
            if (string.IsNullOrWhiteSpace(value)) throw new RegistrationException("Microsoft account setup returned an incomplete response.");
            return value;
        }
        private static void RequireStage(PasswordSetupSession state, string stage)
        {
            if (state == null || state.ExpiresUtc <= DateTimeOffset.UtcNow || state.Stage != stage) throw new RegistrationException("Account setup has expired or this step was already completed. Reopen your invitation.");
        }
        private sealed class PasswordPolicyException : Exception { }
    }
    internal static class PasswordSetupValues
    {
        internal static bool ContainsOrdinal(this string[] values, string value) => Array.Exists(values, item => string.Equals(item, value, StringComparison.Ordinal));
    }
}
