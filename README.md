# Winche.Integrity

Proof that a request comes from one of the project's own apps, not a copy of it, a script or someone's curl. An app
proves itself once, gets a short-lived **Integrity token** for it, and sends the token with every request. Each product
(database, storage, authentication, functions, assets) checks the token, counts it, and, where it's enforced, refuses
requests without one.

How an app proves itself:

| Platform | Proof | |
| --- | --- | --- |
| Simulators, emulators, desktop builds, CI | a **debug token** made in the console | now |
| iOS 14+, macOS 11+ | Apple App Attest (`winche_app_attest` for Flutter) | now |
| Android 6+ (with Google Play) | Google Play Integrity, standard API (`winche_integrity` for Flutter) | now |
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
  Android package, Apple bundle id and team id (App Attest needs both), and whether App Attest keys from development
  builds (run from Xcode) are accepted besides TestFlight and App Store ones (`appleDevelopment`, off by default).
  Android: the Google Cloud project number Play Integrity runs under, whether builds Google Play doesn't know are
  accepted (`androidSideloaded`, off), how good the device must be (`androidDeviceIntegrity`: `basic`, `device` (the
  default) or `strong`), and optionally the signing certificates (SHA-256, base64url, as Play Console shows them).
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

With App Attest, the app first asks for a challenge (`POST /integrity/v1/challenge { "app" }` → `{ challenge,
expiresAt }`: one use, 5 minutes), then sends `{ app, provider: "appAttest", keyId, challenge, attestation }` the
first time (the key's attestation, base64, made for SHA-256 of the challenge's UTF-8) and `{ …, assertion }` every
time after. The server checks the attestation against Apple's App Attestation root (embedded, checked by its
SHA-256): the chain, the challenge in the credential certificate, the key id, the App ID (team id and bundle id), the
environment and a zero counter; then keeps the device's public key (`winche_integrity_keys`). An assertion must be
signed by a kept key, for this challenge and app, with its counter above the last: a replay is refused. A key the
project doesn't know answers `integrity-unknown-key`, and the app attests a new one. Removing an app forgets its keys.

With Play Integrity, the challenge's answer also carries the app's `androidCloudProjectNumber` (the app prepares
Play Integrity with it), and the app sends `{ app, provider: "playIntegrity", challenge, token }`, the token requested
with `requestHash` = SHA-256 of the challenge's UTF-8, lower-case hex. The server has Google decode it
(`decodeIntegrityToken`, signed in as the project's **Google service account**: its key file in the project secret
`integrity.playIntegrity.serviceAccount`, with the Play Integrity API on and its Cloud project linked to the app in Play
Console), then checks the request (package, request hash, made within 7 minutes), the app (`PLAY_RECOGNIZED`, or with
`androidSideloaded` anything but `UNEVALUATED`; the certificate when set) and the device (the app's level). Google being
down is `integrity-unavailable`; a service account it refuses is `integrity-not-set-up`.

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
