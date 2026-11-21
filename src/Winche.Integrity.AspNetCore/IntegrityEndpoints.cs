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

    /// <summary>What an app sends to get a token: its id, how it proves itself, and the proof.</summary>
    public sealed record ExchangeRequest(string? App, string? Provider, string? DebugToken);

    /// <summary>
    /// Maps <c>POST {prefix}/exchange</c> (default <c>/integrity/v1</c>): an app trades proof that it's the project's own
    /// (for now a debug token) for an Integrity token, <c>{ token, expiresAt }</c>. Anyone may call it; only proof gets
    /// a token.
    /// </summary>
    public static IEndpointConventionBuilder MapWincheIntegrity(this IEndpointRouteBuilder app, string prefix = "/integrity/v1") =>
        app.MapPost($"{prefix.TrimEnd('/')}/exchange", (ExchangeRequest body, WincheIntegrity integrity) =>
        {
            if (!integrity.Available || !integrity.CanSign)
                return new WincheError(WincheErrorCode.FailedPrecondition, "Integrity isn't set up on this server: it needs its settings and a master key.", "integrity-unavailable").ToResult();
            if (integrity.Find(body.App?.Trim()) is not { } found)
                return new WincheError(WincheErrorCode.NotFound, $"There's no app '{body.App}' in this project: add it under Integrity in the console.", "integrity-unknown-app").ToResult();
            switch (body.Provider)
            {
                case "debug":
                    if (integrity.FindDebugToken(found.Id, body.DebugToken?.Trim()) is not { } debug)
                        return new WincheError(WincheErrorCode.PermissionDenied, $"That isn't a debug token for {found.Name}: make one under Integrity in the console.", "integrity-rejected").ToResult();
                    var (token, expires) = integrity.Issue(found.Id, "debug", debug.Id);
                    return Results.Json(new { token, expiresAt = expires });
                case null or "":
                    return new WincheError(WincheErrorCode.InvalidArgument, "Say how the app proves itself (provider): debug.", "integrity-provider").ToResult();
                default:
                    return new WincheError(WincheErrorCode.InvalidArgument, $"'{body.Provider}' isn't a way to prove an app Winche has yet: debug.", "integrity-provider").ToResult();
            }
        }).AllowAnonymous();

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
