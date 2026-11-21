# Winche.Integrity

Proof that a request comes from one of the project's own apps, not a copy of it, a script or someone's curl. An app
proves itself once, gets a short-lived **Integrity token** for it, and sends the token with every request. Each product
(database, storage, authentication, functions, assets) checks the token, counts it, and, where it's enforced, refuses
requests without one.

How an app proves itself:

| Platform | Proof | |
| --- | --- | --- |
| Simulators, emulators, desktop builds, CI | a **debug token** made in the console | now |
| iOS, macOS | Apple App Attest | to come |
| Android | Google Play Integrity | to come |
| Web | a browser check | to come |

Windows and Linux have no proof an app can give of itself: they use debug tokens.

## Install

```sh
dotnet add package Winche.Integrity.AspNetCore   # brings Winche.Integrity
```

## Use

```csharp
builder.Services.AddWincheConfig(o => { o.ConnectionString = conn; o.MasterKey = config["Winche:MasterKey"]; });
builder.Services.AddWincheIntegrity(o => o.ProjectId = _ => "clinic");

var app = builder.Build();
app.MapWincheIntegrity();   // POST /integrity/v1/exchange
// Before each product's API: check, count, and refuse where it's enforced.
app.Use(async (http, next) =>
{
    if (http.Request.Path.StartsWithSegments("/documents/v1") && await IntegrityEndpoints.CheckAsync(http, "database")) return;
    await next(http);
});
```

Winche Server does this for every project; its console's **Integrity** page changes the settings.

### Settings (area `integrity`)

- **Apps**: each with an id (it goes in the app's `winche_options.dart`), a name, and what identifies it on each platform:
  Android package, Apple bundle id and team id.
- **Enforcement**, per product: `off` (not checked), `monitor` (the default: checked and counted, never refused) or
  `enforce` (refused without a valid token: `permission-denied`, reason `integrity-required`). Watch the counts in
  monitor first, then enforce once your apps all send tokens.
- **Token lifetime**: 30 minutes to 24 hours (default 60 minutes).
- **Debug tokens**: one per place that can't prove itself (a simulator, CI), for one app. Only their SHA-256 is kept;
  the token is shown once. Removing one ends the Integrity tokens it got.

### The exchange

```http
POST /integrity/v1/exchange
{ "app": "clinic-app", "provider": "debug", "debugToken": "wdt_…" }

200 { "token": "wit1.…", "expiresAt": "2026-11-21T15:00:00Z" }
```

The app sends the token in `X-Winche-Integrity` (on WebSockets, the query parameter `winche_integrity`) and gets a new
one before it expires. The Winche SDKs do all of this.

A token is signed with a key derived from the master key and the project id (HMAC-SHA256), so it's only good on servers
with the same master key, for that project. After a master key change, tokens signed with a previous key
(`PreviousMasterKeys`) still work until they expire. Removing an app ends its tokens.

### What's never checked

Addresses browsers open from a link or other services call: email action links (`/auth/v1/action`), the key set
(`/auth/v1/.well-known`), identity providers' notices (`/auth/v1/providers/{name}/backchannel-logout`, `…/changed`),
HTTP functions (`/functions/v1/http/…`, such as webhooks), and CORS preflights. Signed file links are the host's to leave
out.

### Counts

Requests per app and product per day, and those without a valid token apart, in `winche_integrity_usage` in the config
database (written every 30 seconds): `IntegrityUsage.ReadAsync()` gives today's and the last 7 days'.

## Develop

```sh
dotnet test   # PostgreSQL in Docker (Testcontainers)
```

Publishing: push a tag `v<version>` (the version in Directory.Build.props); the workflow tests it and publishes both
packages to nuget.org with trusted publishing. Release after Winche.Core, before Winche Server and the CLI.

## License

Elastic License 2.0 (`LICENSE`).
