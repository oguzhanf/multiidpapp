(function () {
  "use strict";
  const shared = "samples/net48/Shared/";
  const excerpts = {
    login: { file: "Controllers.cs", start: "public async Task<ActionResult> Login(string email)", end: "[HttpPost, ValidateAntiForgeryToken]", before: 1 },
    runtime: { file: "RegistrationServices.cs", start: 'if (config?.AppId == "sampleapp01")', end: 'if (config?.AppId == "sampleapp02")' },
    resolver: { file: "WorkforceAccountResolver.cs", start: "public async Task<IdentitySource> ResolveAsync", end: "public static string NormalizeIdentifier" },
    providers: { file: "Startup.cs", start: "Config = ConfigurationLoader.Load(AppId);", end: "catch (ConfigurationException ex)", before: 2 },
    authority: { file: "Startup.cs", start: "var source = external ?", end: "RequireHttpsMetadata = true", inclusive: true },
    msal: { file: "MsalOpenIdConnect.cs", start: "protected override async Task<OpenIdConnectMessage> RedeemAuthorizationCodeAsync", end: "// AccessToken is transient" },
    "validation-hook": { file: "Startup.cs", start: "SecurityTokenValidated = notification =>", end: "AuthenticationFailed = notification =>" },
    admission: { file: "Policy.cs", start: "var tid = Single(principal,", end: "var requiredRole =" },
    "dependent-admission": { file: "Policy.cs", start: 'if (entry.Persona == "dependent")', end: 'else if (entry.Persona == "partner")' },
    "invitation-begin": { file: "RegistrationControllers.cs", start: "public ActionResult Begin(string token)", end: "[HttpPost, ValidateAntiForgeryToken, AsyncTimeout", before: 1 },
    failure: { file: "Startup.cs", start: "AuthenticationFailed = notification =>", end: "return Task.FromResult(0);", inclusive: true }
  };
  const files = window.pocCodeSamples && window.pocCodeSamples.files;
  let loaded = 0;
  let failed = 0;
  document.querySelectorAll("[data-snippet]").forEach(element => {
    const name = element.dataset.snippet;
    const definition = excerpts[name];
    const path = definition && shared + definition.file;
    const matches = Array.isArray(files) ? files.filter(file => file.path === path) : [];
    const lines = matches.length === 1 && typeof matches[0].content === "string" ? matches[0].content.split(/\r?\n/) : [];
    const starts = definition ? lines.map((line, index) => line.includes(definition.start) ? index : -1).filter(index => index >= 0) : [];
    const marker = starts.length === 1 ? starts[0] : -1;
    const endMarker = marker >= 0 ? lines.findIndex((line, index) => index > marker && line.includes(definition.end)) : -1;
    if (marker < 0 || endMarker < 0) {
      element.textContent = "Excerpt unavailable. Open the complete source file using the link above.";
      failed++;
      return;
    }
    const start = Math.max(0, marker - (definition.before || 0));
    let end = endMarker + (definition.inclusive ? 1 : 0);
    while (end > start && !lines[end - 1].trim()) end--;
    const selected = lines.slice(start, end);
    const indentation = Math.min(...selected.filter(line => line.trim()).map(line => line.match(/^\s*/)[0].length));
    element.textContent = selected.map(line => line.slice(indentation)).join("\n");
    element.dataset.loaded = "true";
    document.querySelectorAll('[data-source-link="' + name + '"]').forEach(link => {
      link.textContent = definition.file + ":" + (start + 1) + "–" + end;
      link.href = "index.html#code/sampleapp01/" + encodeURIComponent(path);
    });
    loaded++;
  });
  const status = document.getElementById("routing-status");
  if (status) status.textContent = failed
    ? loaded + " source excerpts loaded; " + failed + " unavailable. Use the full-file links for those excerpts."
    : loaded + " source excerpts loaded from the deployed source catalog.";
}());
