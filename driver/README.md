# Onsite PoC driver

Portable, static runbook for `samples/net48/sampleapp01` and `sampleapp02`. The complete local copy requires no packages, CDN or backend. The hosted Caldova driver requires approved workforce sign-in for every page, asset, catalog and source download. Microsoft portal/reference links need a network connection.

From `C:\multiidpapp`, run:

```powershell
py -m http.server 8085 --bind 127.0.0.1 --directory .\driver
```

Open `http://127.0.0.1:8085`. Stop the server with Ctrl+C. If Python is unavailable, open `driver/index.html` directly; browser support for storage and clipboard on `file:` URLs varies.

Copy the whole `driver` folder to the onsite machine. Select an app, expand **Application values**, replace synthetic IDs/hostnames and save. Values and checked progress are stored in this browser's localStorage only; changing values resets that app's checkpoints. Each app has independent progress. **Print runbook** prints all 12 steps for the selected app.

The driver starts with **Architecture**, including when an earlier runbook step is saved. Select a diagram node for its design choice or source, and open **Registration flow** for the implemented invitation design, marked configured/pending live validation. Steps 6–8 explain the exact capabilities, ACS/native B2B delivery and server approval. **Runbook** resumes the saved step without clearing progress. `#architecture` opens the overview; the numbered runbook remains 12 steps. The desktop menu scrolls within a viewport-bounded rail while the progress tracker occupies its own fixed area.

See [Sponsored registration and account setup](../docs/poc/REGISTRATION.md) for the exact `admin` / `dependentRegistrant` capabilities, one-use invitation lifecycle and Microsoft-controlled account setup. This guide records the new workflow contract; the latest build has zero warnings/errors and 165/165 implementation checks pass. Private runtime state outside `wwwroot` survived several later ZIP deployments in the live UI. One authorized personal-email invitation reached ACS `Succeeded` and live app sent status. Inbox receipt, owner account setup, confirmation and protected admission remain separate pending validation results.

The driver never writes to IIS or tenants. Its configuration snippet contains credential environment-variable names, never credential values. Do not enter secrets, tokens, passwords, personal information or real governance records. Keep private deployment/configuration inventories outside this folder and source control. Consult `docs/poc/DESIGN.md` and the net48 sample README for the implementation and deployment contract.

Steps 2–4 always explain the four registrations. Later steps use the selected app's values. Local checkbox completion is an operator record; it does not imply a successful live authentication.

**Code samples** beside the application tabs opens actual source files for the selected app. Choose a file, read its purpose, copy it, or download the complete source ZIP. Direct links `#code/sampleapp01` and `#code/sampleapp02` select the application and open this view; **Back to runbook** retains the current step. Printing still includes the 12-step runbook.

Keep the generated `code-samples.js` beside `index.html` when making an offline copy. It defines `window.pocCodeSamples` with `files: [{path,title,language,content}]` and `apps: {sampleapp01: [paths], sampleapp02: [paths]}` from actual source; optional `description` supplies the one-line purpose. The catalog currently has 14 files and 12 selections per app, including the shared registration sources. The reader uses the local catalog without a fetch and displays content as text. Regenerate it when source changes; keep credentials and runtime/private configuration out of it.

Hosted packaging can add `lab-settings.json` for the **Load hosted lab setup** button; the page fetches it only when clicked. Use `{ "apps": { "sampleapp01": { ... }, "sampleapp02": { ... } } }` with the same flat non-secret fields as the application-values form. Routing domain values accept comma-separated strings or arrays. Do not include credentials or user records. Source download expects `source/net48-source.zip`; include the archive when distributing an offline copy. Neither deployment artifact belongs in the reusable customer template with real lab identifiers.

Include `web.config` when hosting on IIS. It explicitly serves the non-secret lab manifest as `application/json` and the source archive as `application/zip`; `Deploy-PocSites.ps1` packages it with the driver. Hosted authentication must also protect these URLs and `code-samples.js`.

Microsoft reference pages were checked on 30 September and 1 October 2026. External ID supports a different feature set from workforce; application entitlements in this PoC are not an Entra ID Governance deployment.
