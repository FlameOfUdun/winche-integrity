using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Winche.Integrity.AspNetCore;

public static class IntegrityEndpoints
{
    /// <summary>The header apps send their Integrity token in (WebSockets: the query parameter <see cref="QueryParameter"/>).</summary>
    public const string Header = "X-Winche-Integrity", QueryParameter = "winche_integrity";

    /// <summary>Where <see cref="CheckAsync"/> leaves the request's <see cref="IntegrityVerdict"/>.</summary>
    public const string ItemKey = "winche.integrity";

    /// <summary>
    /// What an app sends to get a token: its id, how it proves itself (<c>debug</c> or <c>appAttest</c>), and the
    /// proof. App Attest: the key's id, the challenge answered, and either the key's attestation (base64, the first time)
    /// or an assertion with it (base64, every time after).
    /// </summary>
    public sealed record ExchangeRequest(string? App, string? Provider, string? DebugToken = null,
        string? KeyId = null, string? Challenge = null, string? Attestation = null, string? Assertion = null);

    public sealed record ChallengeRequest(string? App);

    private const string Providers = "debug or appAttest";

    private static IResult Error(WincheErrorCode code, string message, string reason) => new WincheError(code, message, reason).ToResult();

    /// <summary>
    /// Maps the apps' side of Integrity under <paramref name="prefix"/> (default <c>/integrity/v1</c>):
    /// <c>POST challenge</c> (<c>{ app }</c> → <c>{ challenge, expiresAt }</c>, one use, for App Attest) and
    /// <c>POST exchange</c>, where an app trades proof that it's the project's own for an Integrity token,
    /// <c>{ token, expiresAt }</c>. Anyone may call them; only proof gets a token.
    /// </summary>
    public static RouteGroupBuilder MapWincheIntegrity(this IEndpointRouteBuilder app, string prefix = "/integrity/v1")
    {
        var group = app.MapGroup(prefix.TrimEnd('/'));
        group.AllowAnonymous();

        group.MapPost("/challenge", async (ChallengeRequest body, HttpContext http, CancellationToken ct) =>
        {
            if (Unavailable(http) is { } no) return no;
            var integrity = http.RequestServices.GetRequiredService<WincheIntegrity>();
            if (integrity.Find(body.App?.Trim()) is not { } found)
                return Error(WincheErrorCode.NotFound, $"There's no app '{body.App}' in this project: add it under Integrity in the console.", "integrity-unknown-app");
            var (challenge, expires) = await http.RequestServices.GetRequiredService<IntegrityStore>().NewChallengeAsync(found.Id, ct);
            return Results.Json(new { challenge, expiresAt = expires });
        });

        group.MapPost("/exchange", async (ExchangeRequest body, HttpContext http, CancellationToken ct) =>
        {
            if (Unavailable(http) is { } no) return no;
            var integrity = http.RequestServices.GetRequiredService<WincheIntegrity>();
            if (integrity.Find(body.App?.Trim()) is not { } found)
                return Error(WincheErrorCode.NotFound, $"There's no app '{body.App}' in this project: add it under Integrity in the console.", "integrity-unknown-app");
            switch (body.Provider)
            {
                case "debug":
                    if (integrity.FindDebugToken(found.Id, body.DebugToken?.Trim()) is not { } debug)
                        return Error(WincheErrorCode.PermissionDenied, $"That isn't a debug token for {found.Name}: make one under Integrity in the console.", "integrity-rejected");
                    var (token, expires) = integrity.Issue(found.Id, "debug", debug.Id);
                    return Results.Json(new { token, expiresAt = expires });
                case "appAttest":
                    return await AppAttestAsync(body, found, integrity, http.RequestServices, ct);
                case null or "":
                    return Error(WincheErrorCode.InvalidArgument, $"Say how the app proves itself (provider): {Providers}.", "integrity-provider");
                default:
                    return Error(WincheErrorCode.InvalidArgument, $"'{body.Provider}' isn't a way to prove an app Winche has yet: {Providers}.", "integrity-provider");
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
                var counter = verifier.VerifyAssertion(proof, clientDataHash, kept.PublicKey, team, bundle, (uint)kept.Counter);
                if (!await store.AdvanceAsync(kept.KeyId, counter, ct))
                    return Error(WincheErrorCode.PermissionDenied, "That assertion was used before.", "integrity-rejected");
            }
        }
        catch (AppAttest.AppAttestException e)
        {
            return Error(WincheErrorCode.PermissionDenied, $"App Attest refused it: {e.Message}", "integrity-rejected");
        }
        var (token, expires) = integrity.Issue(app.Id, "appAttest");
        return Results.Json(new { token, expiresAt = expires });
    }

    /// <summary>
    /// Addresses under a product's path that never need a token: what browsers open from a link (email actions), what
    /// other services call (identity providers' notices, HTTP functions such as webhooks), and the key set tokens are
    /// checked with.
    /// </summary>
    public static bool IsExempt(PathString path)
    {
        if (path.StartsWithSegments("/auth/v1/action") || path.StartsWithSegments("/auth/v1/.well-known") || path.StartsWithSegments("/functions/v1/http"))
            return true;
        // /auth/v1/providers/{name}/backchannel-logout and …/changed: the provider's own server calls them.
        var p = path.Value ?? "";
        return p.StartsWith("/auth/v1/providers/", StringComparison.OrdinalIgnoreCase)
            && (p.EndsWith("/backchannel-logout", StringComparison.OrdinalIgnoreCase) || p.EndsWith("/changed", StringComparison.OrdinalIgnoreCase));
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
        if (integrity is not { Available: true } || HttpMethods.IsOptions(http.Request.Method) || IsExempt(http.Request.Path)) return false;
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
