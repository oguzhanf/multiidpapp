using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using MultiIdp.Net48;
using Newtonsoft.Json;
using Owin;

internal static class CookieLifetimeTests
{
    internal static void Run(Action<string, Func<bool>> check)
    {
        foreach (var source in new[] { "workforce", "external" })
        {
            var provider = source;
            check(provider + " sign-in respects the fixed 20-minute application session", () => {
                using (var fixture = new Fixture())
                {
                    var options = fixture.Builder.Options.OfType<OpenIdConnectAuthenticationOptions>().Single(o => o.AuthenticationType == provider);
                    var cookie = fixture.Builder.Options.OfType<CookieAuthenticationOptions>().Single();
                    // Katana otherwise copies the ID token expiry to the ticket, which
                    // takes precedence over the cookie middleware's ExpireTimeSpan.
                    return !options.UseTokenLifetime && cookie.ExpireTimeSpan == TimeSpan.FromMinutes(20) && !cookie.SlidingExpiration;
                }
            });
        }
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string directory = Path.Combine(Path.GetTempPath(), "multiidp-cookie-lifetime-" + Guid.NewGuid().ToString("N"));
        private readonly Dictionary<string, string> previousEnvironment = new Dictionary<string, string>();
        private readonly AppConfiguration previousConfig = Startup.Config;
        private readonly string previousError = Startup.ConfigurationError;
        internal readonly RecordingAppBuilder Builder = new RecordingAppBuilder();

        internal Fixture()
        {
            Directory.CreateDirectory(directory);
            try
            {
                const string workforce = "11111111-1111-1111-1111-111111111111";
                const string external = "22222222-2222-2222-2222-222222222222";
                var config = new AppConfiguration {
                    AppId = Startup.AppId,
                    EmployeeDomains = new[] { "employee.example" },
                    ApprovedPartnerDomains = new string[0],
                    EntitlementFile = Path.Combine(directory, "entitlements.json"),
                    Workforce = new TenantConfiguration {
                        TenantId = workforce, ClientId = "33333333-3333-3333-3333-333333333333",
                        Issuer = "https://login.microsoftonline.com/" + workforce + "/v2.0",
                        RedirectUri = "https://application.example/signin-workforce",
                        ClientSecretEnvironmentVariable = "MULTIIDP_TEST_COOKIE_WORKFORCE_SECRET"
                    },
                    External = new TenantConfiguration {
                        TenantId = external, ClientId = "44444444-4444-4444-4444-444444444444",
                        CiamDomain = "example.ciamlogin.com",
                        Issuer = "https://example.ciamlogin.com/" + external + "/v2.0",
                        RedirectUri = "https://application.example/signin-external",
                        ClientSecretEnvironmentVariable = "MULTIIDP_TEST_COOKIE_EXTERNAL_SECRET"
                    }
                };
                var configPath = Path.Combine(directory, "identity.json");
                File.WriteAllText(configPath, JsonConvert.SerializeObject(config));
                File.WriteAllText(config.EntitlementFile, "[]");
                SetEnvironment("MULTIIDP_" + Startup.AppId.ToUpperInvariant() + "_CONFIG", configPath);
                SetEnvironment(config.Workforce.ClientSecretEnvironmentVariable, "synthetic-test-value");
                SetEnvironment(config.External.ClientSecretEnvironmentVariable, "synthetic-test-value");
                typeof(Startup).GetProperty("ConfigurationError").SetValue(null, null);
                new Startup().Configuration(Builder);
                if (Startup.ConfigurationError != null) throw new InvalidOperationException("Synthetic authentication configuration was rejected.");
            }
            catch { Dispose(); throw; }
        }

        private void SetEnvironment(string name, string value)
        {
            previousEnvironment.Add(name, Environment.GetEnvironmentVariable(name));
            Environment.SetEnvironmentVariable(name, value);
        }

        public void Dispose()
        {
            foreach (var entry in previousEnvironment) Environment.SetEnvironmentVariable(entry.Key, entry.Value);
            typeof(Startup).GetProperty("Config").SetValue(null, previousConfig);
            typeof(Startup).GetProperty("ConfigurationError").SetValue(null, previousError);
            if (Directory.Exists(directory)) Directory.Delete(directory, true);
        }
    }

    private sealed class RecordingAppBuilder : IAppBuilder
    {
        public IDictionary<string, object> Properties { get; } = new Dictionary<string, object>();
        internal readonly List<object> Options = new List<object>();
        public IAppBuilder Use(object middleware, params object[] args)
        {
            Options.AddRange(args.Where(arg => arg is CookieAuthenticationOptions || arg is OpenIdConnectAuthenticationOptions));
            return this;
        }
        public IAppBuilder New() => new RecordingAppBuilder();
        public object Build(Type returnType) => throw new NotSupportedException("The configuration test does not execute an HTTP pipeline.");
    }
}
