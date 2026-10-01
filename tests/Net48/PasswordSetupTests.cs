using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using MultiIdp.Net48;

internal static class PasswordSetupTests
{
    internal static void Run(Action<string, Func<bool>> check)
    {
        check("password setup mutations are POST and CSRF protected", () => {
            foreach (var name in new[] { "StartPasswordSetup", "VerifySetupEmail", "CreatePassword", "CheckPasswordSetup" }) {
                var method = typeof(RegistrationController).GetMethod(name);
                if (!Attribute.IsDefined(method, typeof(System.Web.Mvc.HttpPostAttribute)) || !Attribute.IsDefined(method, typeof(System.Web.Mvc.ValidateAntiForgeryTokenAttribute))) return false;
            }
            return true;
        });
        check("password setup requires email verification before password submission", () => {
            var f = new Fixture(); return Denied(() => f.Api.SubmitAsync(f.State, "Example-password-123!", "Example-password-123!").GetAwaiter().GetResult()) && f.Handler.Calls == 0;
        });
        check("password setup verifies email then submits password and confirms completion", () => {
            var f = new Fixture(); f.Start(); f.Handler.Add("{\"continuation_token\":\"verified\",\"expires_in\":600}");
            f.Api.VerifyAsync(f.State, "12345678").GetAwaiter().GetResult();
            f.Handler.Add("{\"continuation_token\":\"pending\",\"poll_interval\":0}");
            f.Api.SubmitAsync(f.State, "Example-password-123!", "Example-password-123!").GetAwaiter().GetResult();
            if (f.State.Stage != "pending") return false;
            f.State.NextPollUtc = DateTimeOffset.MinValue;
            f.Handler.Add("{\"status\":\"succeeded\",\"continuation_token\":\"never-redeem-this\"}");
            f.Api.PollAsync(f.State).GetAwaiter().GetResult();
            return f.State.Stage == "complete" && f.State.ContinuationToken == null && !f.Handler.TokenEndpointCalled;
        });
        check("password setup rejects mismatched confirmation before contacting Microsoft", () => {
            var f = new Fixture(); f.State.Stage = "password";
            return Denied(() => f.Api.SubmitAsync(f.State, "Example-password-123!", "different").GetAwaiter().GetResult()) && f.Handler.Calls == 0;
        });
        check("password setup rejects expired session", () => {
            var f = new Fixture(); f.State.ExpiresUtc = DateTimeOffset.UtcNow.AddSeconds(-1);
            return Denied(() => f.Api.VerifyAsync(f.State, "12345678").GetAwaiter().GetResult()) && f.Handler.Calls == 0;
        });
        check("password setup does not reflect Microsoft descriptions or submitted values", () => {
            var f = new Fixture(); f.State.Stage = "password"; f.State.ContinuationToken = "verified";
            f.Handler.Add("{\"error\":\"invalid_grant\",\"suberror\":\"password_too_weak\",\"error_description\":\"SECRET-MUST-NOT-REFLECT\"}", HttpStatusCode.BadRequest);
            try { f.Api.SubmitAsync(f.State, "Example-password-123!", "Example-password-123!").GetAwaiter().GetResult(); return false; }
            catch (RegistrationException ex) { return !ex.Message.Contains("SECRET") && f.State.Stage == "password"; }
        });
        check("password setup fails closed when Microsoft requires a browser redirect", () => {
            var f = new Fixture(); f.Handler.Add("{\"challenge_type\":\"redirect\"}");
            return Denied(() => f.Api.StartAsync(f.State, "test@example.test").GetAwaiter().GetResult()) && f.State.Stage != "password";
        });
        check("password setup does not allow a second password submission while pending", () => {
            var f = new Fixture(); f.State.Stage = "pending";
            return Denied(() => f.Api.SubmitAsync(f.State, "Example-password-123!", "Example-password-123!").GetAwaiter().GetResult()) && f.Handler.Calls == 0;
        });
        check("password setup rejects wrong application and identity session binding", () => {
            var f = new Fixture(); var invite = new InvitationRecord { AppId = "sampleapp02", Id = "invite", ObjectId = "other", Source = "external", Status = "ready", ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(5) };
            return Denied(() => f.State.RequireInvitation(invite));
        });
        check("password setup cannot poll before provider interval", () => {
            var f = new Fixture(); f.State.Stage = "pending"; f.State.NextPollUtc = DateTimeOffset.UtcNow.AddMinutes(1);
            f.Api.PollAsync(f.State).GetAwaiter().GetResult(); return f.Handler.Calls == 0 && f.State.Stage == "pending";
        });
    }
    private static bool Denied(Action action) { try { action(); return false; } catch (RegistrationException) { return true; } }
    private sealed class Fixture
    {
        public readonly FakeHandler Handler = new FakeHandler();
        public readonly PasswordSetupSession State = new PasswordSetupSession { AppId = "sampleapp01", InvitationId = "invite", ObjectId = "user", Stage = "new", ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(10) };
        public readonly NativePasswordSetup Api;
        public Fixture() { Api = new NativePasswordSetup("example.ciamlogin.com", "example.onmicrosoft.com", "11111111-1111-1111-1111-111111111111", new HttpClient(Handler)); }
        public void Start() { Handler.Add("{\"continuation_token\":\"start\"}"); Handler.Add("{\"continuation_token\":\"challenge\",\"challenge_type\":\"oob\",\"challenge_channel\":\"email\",\"code_length\":8}"); Api.StartAsync(State, "test@example.test").GetAwaiter().GetResult(); }
    }
    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Queue<HttpResponseMessage> responses = new Queue<HttpResponseMessage>();
        public int Calls; public bool TokenEndpointCalled;
        public void Add(string json, HttpStatusCode status = HttpStatusCode.OK) => responses.Enqueue(new HttpResponseMessage(status) { Content = new StringContent(json) });
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) { Calls++; TokenEndpointCalled |= request.RequestUri.AbsolutePath.EndsWith("/token"); return Task.FromResult(responses.Dequeue()); }
    }
}
