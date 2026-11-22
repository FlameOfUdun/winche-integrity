using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Winche.Integrity.AspNetCore;

public static class IntegrityEndpoints
{
    /// <summary>The header apps send their Integrity token in (WebSockets: the query parameter <see cref="QueryParameter"/>).</summary>
    public const string Header = "X-Winche-Integrity", QueryParameter = "winche_integrity";

    /// <summary>Where <see cref="CheckAsync"/> leaves the request's <see cref="IntegrityVerdict"/>.</summary>
    public const string ItemKey = "winche.integrity";

    /// <summary>
    /// What an app sends to get a token: its id, how it proves itself (<c>appAttest</c>, <c>playIntegrity</c>,
    /// <c>turnstile</c> or <c>debug</c>), and the proof. App Attest: the key's id, the challenge answered, and either the
    /// key's attestation (base64, the first time) or an assertion with it (base64, every time after). Play Integrity and
    /// Turnstile: the token the platform gave (<c>token</c>) and the challenge. Debug: the debug token.
    /// </summary>
    public sealed record ExchangeRequest(string? App, string? Provider, string? DebugToken = null,
        string? KeyId = null, string? Challenge = null, string? Attestation = null, string? Assertion = null, string? Token = null);

    /// <summary>An app asking for a challenge to answer (App Attest, Play Integrity, Turnstile).</summary>
    public sealed record ChallengeRequest(string? App);

    private const string Providers = "debug, appAttest, playIntegrity or turnstile";

    private static IResult Error(WincheErrorCode code, string message, string reason) => new WincheError(code, message, reason).ToResult();

    private static IResult UnknownApp() =>
        Error(WincheErrorCode.NotFound, "There's no such app in this project: add it under Integrity in the console.", "integrity-unknown-app");

    private static IntegrityLimiter LimiterOf(HttpContext http) => http.RequestServices.GetRequiredService<IntegrityLimiter>();

    private static IResult TooMany(HttpContext http)
    {
        http.Response.Headers.RetryAfter = "60";
        return Error(WincheErrorCode.ResourceExhausted, "Too many tries from here or for this app: try again in a minute.", "integrity-rate-limited");
    }

    /// <summary>A token and how long it lasts: <c>expiresIn</c> (seconds) lets apps whose clocks are off still refresh it in time.</summary>
    private static IResult Issued(WincheIntegrity integrity, (string Token, DateTimeOffset ExpiresAt) t) =>
        Results.Json(new { token = t.Token, expiresAt = t.ExpiresAt, expiresIn = integrity.Current.TokenMinutes * 60 });

    /// <summary>
    /// The server's side of why a provider couldn't be used (a service account's address, Google's or Cloudflare's own
    /// words): logged for the project's admins, never told to whoever called.
    /// </summary>
    private static void Log(IServiceProvider services, IntegrityApp app, string provider, string detail) =>
        services.GetService<ILoggerFactory>()?.CreateLogger("Winche.Integrity")
            .LogInformation("Integrity: {Provider} refused a token for the app {App}: {Detail}", provider, app.Id, detail);

    private static IResult NotSetUp(IServiceProvider services, IntegrityApp app, string provider, string detail, bool unavailable)
    {
        services.GetService<ILoggerFactory>()?.CreateLogger("Winche.Integrity")
            .LogWarning("Integrity: {Provider} for the app {App} {What}: {Detail}", provider, app.Id, unavailable ? "couldn't be checked" : "isn't set up right", detail);
        return unavailable
            ? Error(WincheErrorCode.Unavailable, $"{provider} couldn't be checked just now: try again shortly.", "integrity-unavailable")
            : Error(WincheErrorCode.FailedPrecondition, $"{provider} isn't set up right for this app on the server (its admins can see why in the server's log).", "integrity-not-set-up");
    }

    /// <summary>
    /// Maps the apps' side of Integrity under <paramref name="prefix"/> (default <c>/integrity/v1</c>):
    /// <c>POST challenge</c> (<c>{ app }</c> → <c>{ challenge, expiresAt, androidCloudProjectNumber, webSiteKey }</c>,
    /// one use, for App Attest, Play Integrity and Turnstile) and <c>POST exchange</c>, where an app trades proof that
    /// it's the project's own for an Integrity token, <c>{ token, expiresAt, expiresIn }</c>. Anyone may call them
    /// (limited per address, and per app for proofs that cost a call to Google or Cloudflare); only proof gets a token.
    /// </summary>
    public static RouteGroupBuilder MapWincheIntegrity(this IEndpointRouteBuilder app, string prefix = "/integrity/v1")
    {
        var group = app.MapGroup(prefix.TrimEnd('/'));
        group.AllowAnonymous();

        group.MapPost("/challenge", async (ChallengeRequest body, HttpContext http, CancellationToken ct) =>
        {
            if (Unavailable(http) is { } no) return no;
            var integrity = http.RequestServices.GetRequiredService<WincheIntegrity>();
            if (integrity.Find(body.App?.Trim()) is not { } found) return UnknownApp();
            if (!LimiterOf(http).TryTakeAddress(http.Connection.RemoteIpAddress?.ToString())) return TooMany(http);
            var (challenge, expires) = await http.RequestServices.GetRequiredService<IntegrityStore>().NewChallengeAsync(found.Id, ct);
            // Play Integrity asks the app for its Google Cloud project number, Turnstile for its site key: they come from here, not the app's options.
            return Results.Json(new { challenge, expiresAt = expires, androidCloudProjectNumber = found.AndroidCloudProjectNumber, webSiteKey = found.WebSiteKey });
        });

        group.MapPost("/exchange", async (ExchangeRequest body, HttpContext http, CancellationToken ct) =>
        {
            if (Unavailable(http) is { } no) return no;
            var integrity = http.RequestServices.GetRequiredService<WincheIntegrity>();
            if (integrity.Find(body.App?.Trim()) is not { } found) return UnknownApp();
            if (!LimiterOf(http).TryTakeAddress(http.Connection.RemoteIpAddress?.ToString())) return TooMany(http);
            switch (body.Provider)
            {
                case "debug":
                    if (integrity.FindDebugToken(found.Id, body.DebugToken?.Trim()) is not { } debug)
                        return Error(WincheErrorCode.PermissionDenied, $"That isn't a debug token for {found.Name}: make one under Integrity in the console.", "integrity-rejected");
                    return Issued(integrity, integrity.Issue(found.Id, "debug", debug.Id));
                case "appAttest":
                    return await AppAttestAsync(body, found, integrity, http.RequestServices, ct);
                case "playIntegrity":
                    return await PlayIntegrityAsync(body, found, integrity, http, ct);
                case "turnstile":
                    return await TurnstileAsync(body, found, integrity, http, ct);
                case null or "":
                    return Error(WincheErrorCode.InvalidArgument, $"Say how the app proves itself (provider): {Providers}.", "integrity-provider");
                default:
                    return Error(WincheErrorCode.InvalidArgument, $"That isn't a way to prove an app Winche has: {Providers}.", "integrity-provider");
            }
        });
        return group;
    }

    private static IResult? Unavailable(HttpContext http) =>
        // Looked up rather than injected: a host that maps this without AddWincheIntegrity answers "unavailable".
        http.RequestServices.GetService<WincheIntegrity>() is { Available: true, CanSign: true } && http.RequestServices.GetService<IntegrityStore>() is { Available: true }
            ? null
            : Error(WincheErrorCode.FailedPrecondition, "Integrity isn't set up on this server: it needs its settings, a master key and the config database.", "integrity-unavailable");

    /// <summary>
    /// The browser check (Cloudflare Turnstile): the challenge is used up, then Cloudflare checks the token with the
    /// app's secret key, and the site, action and challenge (the widget's cData) are checked.
    /// </summary>
    private static async Task<IResult> TurnstileAsync(ExchangeRequest body, IntegrityApp app, WincheIntegrity integrity, HttpContext http, CancellationToken ct)
    {
        var services = http.RequestServices;
        if (app.WebSiteKey is null)
            return Error(WincheErrorCode.FailedPrecondition, $"{app.Name} has no Turnstile site key: set it under Integrity to use the browser check.", "integrity-not-set-up");
        var secrets = services.GetService<Winche.Secrets.SecretStore>();
        var secret = secrets is { Available: true } ? await secrets.GetAsync(WincheIntegrity.TurnstileSecret(app.Id), ct) : null;
        if (string.IsNullOrEmpty(secret))
            return Error(WincheErrorCode.FailedPrecondition, $"{app.Name} has no Turnstile secret key: set it under Integrity.", "integrity-not-set-up");
        if (IntegritySettings.TestSecretRx().IsMatch(secret.Trim()))
            return NotSetUp(services, app, "The browser check", "its Turnstile secret key is one of Cloudflare's test keys, which pass any token: give the app its own widget's keys.", unavailable: false);
        if (string.IsNullOrWhiteSpace(body.Token) || body.Token.Length > 2048)
            return Error(WincheErrorCode.InvalidArgument, "The browser check needs the token Turnstile gave (token) and the challenge.", "integrity-proof");
        if (!await services.GetRequiredService<IntegrityStore>().UseChallengeAsync(app.Id, body.Challenge, ct))
            return Error(WincheErrorCode.PermissionDenied, "The challenge isn't one this project gave, was used already, or expired: ask for a new one.", "integrity-challenge");
        if (!LimiterOf(http).TryTakeApp(app.Id)) return TooMany(http);   // a call to Cloudflare: the app's budget
        try
        {
            await services.GetRequiredService<Turnstile.TurnstileVerifier>().VerifyAsync(body.Token, body.Challenge!, app, secret, http.Connection.RemoteIpAddress?.ToString(), ct);
        }
        catch (Turnstile.TurnstileException e) when (e.Retryable)
        {
            return NotSetUp(services, app, "The browser check", e.Message, unavailable: true);
        }
        catch (Turnstile.TurnstileException e) when (e.Reason is "secret" or "testing")
        {
            return NotSetUp(services, app, "The browser check", e.Message, unavailable: false);
        }
        catch (Turnstile.TurnstileException e)
        {
            // Cloudflare's own error codes stay in the log; our own checks (site, action, challenge, age) are said.
            if (e.Reason == "token") { Log(services, app, "The browser check", e.Message); return Error(WincheErrorCode.PermissionDenied, "The browser check refused the token (expired, used before, or not a real one).", "integrity-rejected"); }
            return Error(WincheErrorCode.PermissionDenied, $"The browser check refused it: {e.Message}", "integrity-rejected");
        }
        return Issued(integrity, integrity.Issue(app.Id, "turnstile"));
    }

    /// <summary>
    /// Play Integrity (standard API): the challenge is used up, then Google decodes the token (with the project's
    /// service account) and its request, app and device verdicts are checked. The app's request hash is SHA-256 of the
    /// challenge, hex.
    /// </summary>
    private static async Task<IResult> PlayIntegrityAsync(ExchangeRequest body, IntegrityApp app, WincheIntegrity integrity, HttpContext http, CancellationToken ct)
    {
        var services = http.RequestServices;
        if (app.AndroidPackage is null)
            return Error(WincheErrorCode.FailedPrecondition, $"{app.Name} has no Android package: set it under Integrity to use Play Integrity.", "integrity-not-set-up");
        var secrets = services.GetService<Winche.Secrets.SecretStore>();
        var account = secrets is { Available: true } ? PlayIntegrity.GoogleServiceAccount.Parse(await secrets.GetAsync(WincheIntegrity.PlayServiceAccountSecret, ct)) : null;
        if (account is null)
            return Error(WincheErrorCode.FailedPrecondition, "This project has no Google service account for Play Integrity: set its key file under Integrity.", "integrity-not-set-up");
        if (string.IsNullOrWhiteSpace(body.Token) || body.Token.Length > 20_000)
            return Error(WincheErrorCode.InvalidArgument, "Play Integrity needs the token the app got (token) and the challenge.", "integrity-proof");
        if (!await services.GetRequiredService<IntegrityStore>().UseChallengeAsync(app.Id, body.Challenge, ct))
            return Error(WincheErrorCode.PermissionDenied, "The challenge isn't one this project gave, was used already, or expired: ask for a new one.", "integrity-challenge");
        if (!LimiterOf(http).TryTakeApp(app.Id)) return TooMany(http);   // a call to Google (a daily quota): the app's budget
        try
        {
            await services.GetRequiredService<PlayIntegrity.PlayIntegrityVerifier>().VerifyAsync(body.Token, body.Challenge!, app, account, ct);
        }
        catch (PlayIntegrity.PlayIntegrityException e) when (e.Retryable)
        {
            return NotSetUp(services, app, "Play Integrity", e.Message, unavailable: true);
        }
        catch (PlayIntegrity.PlayIntegrityException e) when (e.Reason == "google")
        {
            return NotSetUp(services, app, "Play Integrity", e.Message, unavailable: false);
        }
        catch (PlayIntegrity.PlayIntegrityException e)
        {
            // Google's own words stay in the log; our own checks (app, request, device) are said.
            if (e.Reason == "token") { Log(services, app, "Play Integrity", e.Message); return Error(WincheErrorCode.PermissionDenied, "Google couldn't read the Play Integrity token: ask for a new one.", "integrity-rejected"); }
            return Error(WincheErrorCode.PermissionDenied, $"Play Integrity refused it: {e.Message}", "integrity-rejected");
        }
        return Issued(integrity, integrity.Issue(app.Id, "playIntegrity"));
    }

    /// <summary>
    /// App Attest: the challenge is used up, then the attestation (a new key: kept) or the assertion (a kept key: its
    /// counter moves on) is checked. A key the project doesn't know is <c>integrity-unknown-key</c>: the app attests a
    /// new one.
    /// </summary>
    private static async Task<IResult> AppAttestAsync(ExchangeRequest body, IntegrityApp app, WincheIntegrity integrity, IServiceProvider services, CancellationToken ct)
    {
        if (app.AppleTeamId is not { } team || app.AppleBundleId is not { } bundle)
            return Error(WincheErrorCode.FailedPrecondition, $"{app.Name} has no Apple team id and bundle id: set them under Integrity to use App Attest.", "integrity-not-set-up");
        if (string.IsNullOrWhiteSpace(body.KeyId) || (body.Attestation is null) == (body.Assertion is null))
            return Error(WincheErrorCode.InvalidArgument, "App Attest needs the key id and either its attestation (the first time) or an assertion.", "integrity-proof");
        var store = services.GetRequiredService<IntegrityStore>();
        var verifier = services.GetRequiredService<AppAttest.AppAttestVerifier>();
        if (!await store.UseChallengeAsync(app.Id, body.Challenge, ct))
            return Error(WincheErrorCode.PermissionDenied, "The challenge isn't one this project gave, was used already, or expired: ask for a new one.", "integrity-challenge");
        var clientDataHash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(body.Challenge!));
        byte[] proof;
        try { proof = Convert.FromBase64String(body.Attestation ?? body.Assertion!); }
        catch (FormatException) { return Error(WincheErrorCode.InvalidArgument, "The attestation or assertion isn't base64.", "integrity-proof"); }
        try
        {
            if (body.Attestation is not null)
            {
                var key = verifier.VerifyAttestation(proof, clientDataHash, body.KeyId, team, bundle, app.AppleDevelopment);
                if (!await store.AddKeyAsync(body.KeyId, app.Id, "appAttest", key.PublicKey, key.Development, key.Receipt, ct))
                    return Error(WincheErrorCode.PermissionDenied, "That key was attested before: send an assertion with it.", "integrity-rejected");
            }
            else
            {
                if (await store.FindKeyAsync(body.KeyId, ct) is not { Provider: "appAttest" } kept || kept.AppId != app.Id)
                    return Error(WincheErrorCode.PermissionDenied, "This project doesn't know that key: attest a new one.", "integrity-unknown-key");
                // A key from a development build (run from Xcode) stops working once the app no longer accepts them.
                if (kept.Development && !app.AppleDevelopment)
                    return Error(WincheErrorCode.PermissionDenied, "That key is from a development build, which the app no longer accepts.", "integrity-rejected");
                var counter = verifier.VerifyAssertion(proof, clientDataHash, kept.PublicKey, team, bundle, (uint)kept.Counter);
                if (!await store.AdvanceAsync(kept.KeyId, counter, ct))
                    return Error(WincheErrorCode.PermissionDenied, "That assertion was used before.", "integrity-rejected");
            }
        }
        catch (AppAttest.AppAttestException e)
        {
            return Error(WincheErrorCode.PermissionDenied, $"App Attest refused it: {e.Message}", "integrity-rejected");
        }
        return Issued(integrity, integrity.Issue(app.Id, "appAttest"));
    }

    /// <summary>
    /// Addresses under a product's path that never need a token: what browsers open from a link (email actions) or an
    /// image (users' photos), what
    /// other services call (identity providers' notices, HTTP functions such as webhooks), and the key set tokens are
    /// checked with.
    /// </summary>
    public static bool IsExempt(PathString path, string method)
    {
        if (path.StartsWithSegments("/auth/v1/action") || path.StartsWithSegments("/functions/v1/http")) return true;
        // Read-only ones, only for reading: users' photos (<img> tags can't send a token), and the key set and discovery
        // document other services check Winche tokens with (/.well-known/jwks.json, …/openid-configuration).
        var reading = HttpMethods.IsGet(method) || HttpMethods.IsHead(method);
        if (reading && (path.StartsWithSegments("/.well-known") || path.StartsWithSegments("/auth/v1/.well-known") || path.StartsWithSegments("/auth/v1/photos"))) return true;
        // /auth/v1/providers/{name}/backchannel-logout and /auth/v1/providers/{name}/changed: the provider's own server calls them.
        var parts = (path.Value ?? "").Split('/', StringSplitOptions.RemoveEmptyEntries);
        static bool Is(string a, string b) => a.Equals(b, StringComparison.OrdinalIgnoreCase);
        return parts.Length == 5 && Is(parts[0], "auth") && Is(parts[1], "v1") && Is(parts[2], "providers")
            && (Is(parts[4], "backchannel-logout") || Is(parts[4], "changed"));
    }

    /// <summary>The token a request carries (header, else the WebSocket query parameter).</summary>
    public static string? TokenOf(HttpRequest request) =>
        request.Headers[Header].FirstOrDefault() is { Length: > 0 } h ? h.Trim()
        : request.Query[QueryParameter].FirstOrDefault() is { Length: > 0 } q ? q.Trim() : null;

    /// <summary>What <see cref="CheckAsync"/> found for the request being handled: its app, when the token was valid.</summary>
    public static IntegrityVerdict? VerdictOf(HttpContext http) => http.Items.TryGetValue(ItemKey, out var v) ? v as IntegrityVerdict : null;

    /// <summary>
    /// For a request to <paramref name="product"/>'s API: checks its token, counts it, and when the product is enforced
    /// and the token isn't valid, answers it (permission-denied, reason <c>integrity-required</c>) and returns true.
    /// CORS preflights and <see cref="IsExempt"/> addresses pass unchecked.
    /// </summary>
    public static async Task<bool> CheckAsync(HttpContext http, string product)
    {
        var integrity = http.RequestServices.GetService<WincheIntegrity>();
        if (integrity is not { Available: true } || HttpMethods.IsOptions(http.Request.Method) || IsExempt(http.Request.Path, http.Request.Method)) return false;
        var mode = integrity.Current.ModeOf(product);
        if (mode == "off") return false;
        var token = TokenOf(http.Request);
        var verdict = integrity.Verify(token);
        if (verdict is not null) http.Items[ItemKey] = verdict;
        http.RequestServices.GetService<IntegrityUsage>()?.Count(verdict?.AppId ?? IntegrityUsage.Unverified, product);
        if (verdict is not null || mode != "enforce") return false;
        await new WincheError(WincheErrorCode.PermissionDenied,
            token is null
                ? "This project only answers its own apps: the request has no Integrity token."
                : "This project only answers its own apps: the request's Integrity token isn't valid (expired, or its app or debug token was removed).",
            "integrity-required").ToResult().ExecuteAsync(http);
        return true;
    }
}
