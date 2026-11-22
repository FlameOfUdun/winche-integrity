using System.Text.Json;
using System.Text.Json.Nodes;

namespace Winche.Integrity.Turnstile;

/// <summary>Why a Turnstile token was refused: a short reason and a sentence.</summary>
public sealed class TurnstileException(string reason, string message, bool retryable = false) : Exception(message)
{
    /// <summary>A short reason, e.g. <c>token</c>, <c>request</c>, <c>testing</c>, <c>cloudflare</c>, <c>secret</c>.</summary>
    public string Reason { get; } = reason;

    /// <summary>Cloudflare couldn't be asked: not the browser's fault.</summary>
    public bool Retryable { get; } = retryable;
}

/// <summary>
/// Checks Cloudflare Turnstile tokens (the browser check): Cloudflare's siteverify with the app's secret key, then that
/// the token was made on one of the app's hostnames, for Winche Integrity's action and this challenge (in its cData),
/// within the challenge's lifetime, and not with Cloudflare's always-passing test keys.
/// </summary>
public sealed class TurnstileVerifier(HttpClient? http = null, TimeProvider? time = null)
{
    /// <summary>Where Cloudflare answers (tests point it elsewhere).</summary>
    internal static class Endpoints
    {
        public static string Siteverify = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
    }

    /// <summary>The action the widget runs with (Turnstile: up to 32 letters, digits, _ and -).</summary>
    public const string Action = "winche-integrity";

    /// <summary>How old a solved challenge may be: Turnstile's own 5 minutes, and a little for clocks.</summary>
    public static readonly TimeSpan MaxAge = TimeSpan.FromMinutes(6);

    private static readonly HttpClient Shared = new() { Timeout = TimeSpan.FromSeconds(10) };
    private readonly HttpClient _http = http ?? Shared;
    private readonly TimeProvider _time = time ?? TimeProvider.System;

    /// <summary>
    /// Checks <paramref name="token"/> for <paramref name="challenge"/> and <paramref name="app"/> with its
    /// <paramref name="secret"/>; <paramref name="remoteIp"/> is the browser's address, when known.
    /// </summary>
    public async Task VerifyAsync(string token, string challenge, IntegrityApp app, string secret, string? remoteIp, CancellationToken ct)
    {
        JsonNode? r;
        try
        {
            var form = new Dictionary<string, string>
            {
                ["secret"] = secret, ["response"] = token,
                // Retried with the same key, a check isn't taken for a second use of the token.
                ["idempotency_key"] = Guid.NewGuid().ToString(),
            };
            if (!string.IsNullOrEmpty(remoteIp)) form["remoteip"] = remoteIp;
            using var response = await _http.PostAsync(Endpoints.Siteverify, new FormUrlEncodedContent(form), ct);
            if ((int)response.StatusCode >= 500) throw new TurnstileException("cloudflare", $"Cloudflare answered {(int)response.StatusCode}.", retryable: true);
            r = JsonNode.Parse(await response.Content.ReadAsStringAsync(ct));
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            throw new TurnstileException("cloudflare", $"Cloudflare can't be reached: {e.Message}", retryable: true);
        }
        catch (JsonException) { throw new TurnstileException("cloudflare", "Cloudflare's answer can't be read.", retryable: true); }

        // Cloudflare's always-passing test keys would let anyone in: never accepted.
        if (r?["metadata"]?["result_with_testing_key"]?.GetValue<bool>() == true)
            throw new TurnstileException("testing", "The token was checked with one of Cloudflare's test keys: give the app its own widget's keys.");
        if (r?["success"]?.GetValue<bool>() != true)
        {
            var codes = r?["error-codes"]?.AsArray().Select(c => c?.GetValue<string>()).ToList() ?? [];
            if (codes.Contains("invalid-input-secret") || codes.Contains("missing-input-secret"))
                throw new TurnstileException("secret", "Cloudflare doesn't know the app's secret key: set it again (the widget's secret key, Cloudflare dashboard → Turnstile).");
            if (codes.Contains("internal-error")) throw new TurnstileException("cloudflare", "Cloudflare had an internal error.", retryable: true);
            throw new TurnstileException("token", codes.Contains("timeout-or-duplicate")
                ? "The browser check expired or was used before."
                : $"Cloudflare refused the browser check ({string.Join(", ", codes)}).");
        }

        // This app's site, this action, this challenge, just now.
        var hostname = r["hostname"]?.GetValue<string>();
        if (app.WebHostnames.Count > 0 && (hostname is null || !app.WebHostnames.Contains(hostname.ToLowerInvariant())))
            throw new TurnstileException("request", $"The browser check was made on {hostname ?? "an unknown site"}, not one of {app.Name}'s.");
        if (r["action"]?.GetValue<string>() != Action) throw new TurnstileException("request", "The browser check was made for something else (another action).");
        if (r["cdata"]?.GetValue<string>() != challenge) throw new TurnstileException("request", "The browser check wasn't made for this challenge.");
        if (r["challenge_ts"]?.GetValue<string>() is not { } at || !DateTimeOffset.TryParse(at, out var solved) || _time.GetUtcNow() - solved > MaxAge)
            throw new TurnstileException("request", "The browser check is too old.");
    }
}
