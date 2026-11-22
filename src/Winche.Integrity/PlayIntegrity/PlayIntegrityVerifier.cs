using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Winche.Integrity.PlayIntegrity;

/// <summary>Why a Play Integrity token was refused: a short reason and a sentence.</summary>
public sealed class PlayIntegrityException(string reason, string message, bool retryable = false) : Exception(message)
{
    /// <summary>A short reason, e.g. <c>request</c>, <c>app</c>, <c>device</c>, <c>google</c>.</summary>
    public string Reason { get; } = reason;

    /// <summary>Google couldn't be asked (it's down, or answered too slowly): not the app's fault.</summary>
    public bool Retryable { get; } = retryable;
}

/// <summary>A Google service account's key (its JSON, as Google Cloud gives it): what the server signs in to Google with.</summary>
public sealed record GoogleServiceAccount(string ClientEmail, string PrivateKey, string TokenUri)
{
    /// <summary>The key file's JSON; null when it isn't a service account's key.</summary>
    public static GoogleServiceAccount? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            var o = JsonNode.Parse(json)?.AsObject();
            if (o?["type"]?.GetValue<string>() != "service_account") return null;
            var email = o["client_email"]?.GetValue<string>();
            var key = o["private_key"]?.GetValue<string>();
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(key) || !key.Contains("PRIVATE KEY")) return null;
            return new(email, key, o["token_uri"]?.GetValue<string>() ?? "https://oauth2.googleapis.com/token");
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException) { return null; }
    }
}

/// <summary>What a valid Play Integrity token said about the app and the device.</summary>
public sealed record PlayVerdict(string AppRecognition, IReadOnlyList<string> Device, string? Licensing, string? VersionCode);

/// <summary>
/// Checks Play Integrity tokens (the standard API): has Google decode one with the project's service account, then
/// checks it was made for this app and challenge, recently, by a build Google Play knows, on a device that's good
/// enough.
/// </summary>
public sealed class PlayIntegrityVerifier(HttpClient? http = null, TimeProvider? time = null)
{
    /// <summary>Where Google answers (tests point them elsewhere).</summary>
    internal static class Endpoints
    {
        public static string Api = "https://playintegrity.googleapis.com";
    }

    private const string Scope = "https://www.googleapis.com/auth/playintegrity";
    /// <summary>How old a token may be: a challenge lasts 5 minutes; a little more for clocks that differ.</summary>
    public static readonly TimeSpan MaxAge = TimeSpan.FromMinutes(7);

    private static readonly HttpClient Shared = new() { Timeout = TimeSpan.FromSeconds(15) };
    private readonly HttpClient _http = http ?? Shared;
    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly ConcurrentDictionary<string, (string Token, DateTimeOffset Expires)> _access = new();

    /// <summary>The request hash an app sends for <paramref name="challenge"/>: SHA-256 of its UTF-8, lower-case hex.</summary>
    public static string RequestHash(string challenge) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(challenge)));

    /// <summary>The device verdicts each level accepts: a strong device meets device integrity too, and so on.</summary>
    public static readonly IReadOnlyDictionary<string, string[]> Levels = new Dictionary<string, string[]>
    {
        ["basic"] = ["MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"],
        ["device"] = ["MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"],
        ["strong"] = ["MEETS_STRONG_INTEGRITY"],
    };

    /// <summary>
    /// Checks <paramref name="token"/>, made for <paramref name="challenge"/> by <paramref name="app"/> (its Android
    /// package and requirements), decoded with <paramref name="account"/>.
    /// </summary>
    public async Task<PlayVerdict> VerifyAsync(string token, string challenge, IntegrityApp app, GoogleServiceAccount account, CancellationToken ct)
    {
        var package = app.AndroidPackage ?? throw new PlayIntegrityException("app", $"{app.Name} has no Android package.");
        var access = await AccessTokenAsync(account, ct);
        JsonObject payload;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, $"{Endpoints.Api}/v1/{Uri.EscapeDataString(package)}:decodeIntegrityToken")
            {
                Content = JsonContent.Create(new Dictionary<string, string> { ["integrity_token"] = token }),
            };
            request.Headers.Authorization = new("Bearer", access);
            using var response = await _http.SendAsync(request, ct);
            var text = await response.Content.ReadAsStringAsync(ct);
            if ((int)response.StatusCode is 400 or 404)
                throw new PlayIntegrityException("token", $"Google couldn't read the token ({(int)response.StatusCode}): {GoogleMessage(text)}");
            if ((int)response.StatusCode is 401 or 403)
            {
                _access.TryRemove(account.ClientEmail, out _);
                throw new PlayIntegrityException("google", $"Google refused the service account {account.ClientEmail} ({(int)response.StatusCode}): {GoogleMessage(text)} Link its Google Cloud project to the app in Play Console and give it the Play Integrity API.");
            }
            if (!response.IsSuccessStatusCode)
                throw new PlayIntegrityException("google", $"Google answered {(int)response.StatusCode}: {GoogleMessage(text)}",
                    retryable: (int)response.StatusCode >= 500 || response.StatusCode == System.Net.HttpStatusCode.TooManyRequests);   // 429: the quota, for now
            payload = (JsonNode.Parse(text)?["tokenPayloadExternal"] as JsonObject) ?? throw new PlayIntegrityException("token", "Google's answer has no verdict.");
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            throw new PlayIntegrityException("google", $"Google can't be reached: {e.Message}", retryable: true);
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException) { throw new PlayIntegrityException("google", "Google's answer can't be read.", retryable: true); }

        try
        {
            // The request first: this app, this challenge, just now.
            var details = payload["requestDetails"];
            if (details?["requestPackageName"]?.GetValue<string>() != package)
                throw new PlayIntegrityException("request", $"The token was asked for by another app than {package}.");
            if (details?["requestHash"]?.GetValue<string>() != RequestHash(challenge))
                throw new PlayIntegrityException("request", "The token wasn't made for this challenge.");
            var millis = details?["timestampMillis"] switch
            {
                JsonValue v when v.TryGetValue<long>(out var n) => n,
                JsonValue v when v.TryGetValue<string>(out var s) && long.TryParse(s, out var n) => n,
                _ => throw new PlayIntegrityException("request", "The token has no time."),
            };
            var age = _time.GetUtcNow() - DateTimeOffset.FromUnixTimeMilliseconds(millis);
            if (age > MaxAge || age < TimeSpan.FromMinutes(-2)) throw new PlayIntegrityException("request", "The token is too old (or from the future).");

            // The app: a build Google Play knows (or, where the app accepts others, at least its own signing certificate).
            var appIntegrity = payload["appIntegrity"];
            var recognition = appIntegrity?["appRecognitionVerdict"]?.GetValue<string>() ?? "UNEVALUATED";
            if (recognition == "UNEVALUATED") throw new PlayIntegrityException("app", "Google couldn't tell which app made the token (the device may be compromised).");
            if (recognition != "PLAY_RECOGNIZED" && !app.AndroidSideloaded)
                throw new PlayIntegrityException("app", "The app isn't a build Google Play knows (installed some other way, or changed). Accept builds from elsewhere for the app to allow it.");
            // A build Google Play doesn't know passes only when signed with one of the app's certificates (settings saved
            // before that rule may lack one: then only Play's own builds pass).
            if (recognition != "PLAY_RECOGNIZED" && app.AndroidCertificates.Count == 0)
                throw new PlayIntegrityException("app", "The app isn't a build Google Play knows, and it has no signing certificate set to accept others by.");
            if (app.AndroidCertificates.Count > 0)
            {
                var digests = appIntegrity?["certificateSha256Digest"]?.AsArray().Select(d => d?.GetValue<string>()).ToList() ?? [];
                if (!digests.Any(d => d is not null && app.AndroidCertificates.Contains(d.TrimEnd('='))))
                    throw new PlayIntegrityException("app", "The app isn't signed with one of its certificates.");
            }

            // The device: at least the app's level.
            var device = payload["deviceIntegrity"]?["deviceRecognitionVerdict"]?.AsArray().Select(d => d?.GetValue<string>()).OfType<string>().ToList() ?? [];
            if (!device.Any(Levels[app.AndroidDeviceIntegrity].Contains))
                throw new PlayIntegrityException("device", device.Count == 0
                    ? "The device doesn't pass Google's integrity checks (rooted, an emulator, or a token decoded before)."
                    : $"The device is only {string.Join(", ", device)}: the app needs {app.AndroidDeviceIntegrity} integrity.");
            return new PlayVerdict(recognition, device, payload["accountDetails"]?["appLicensingVerdict"]?.GetValue<string>(),
                appIntegrity?["versionCode"]?.ToString());
        }
        catch (InvalidOperationException)
        {
            // A verdict field of another type than Google documents: never a pass.
            throw new PlayIntegrityException("google", "Google's verdict can't be read.", retryable: true);
        }
    }

    /// <summary>An access token for the Play Integrity API: a signed assertion traded at Google's token endpoint, kept until near expiry.</summary>
    private async Task<string> AccessTokenAsync(GoogleServiceAccount account, CancellationToken ct)
    {
        var now = _time.GetUtcNow();
        if (_access.TryGetValue(account.ClientEmail, out var held) && held.Expires > now.AddMinutes(5)) return held.Token;
        string assertion;
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(account.PrivateKey);
            static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            var header = B64(JsonSerializer.SerializeToUtf8Bytes(new { alg = "RS256", typ = "JWT" }));
            var claims = B64(JsonSerializer.SerializeToUtf8Bytes(new { iss = account.ClientEmail, scope = Scope, aud = account.TokenUri, iat = now.ToUnixTimeSeconds(), exp = now.AddHours(1).ToUnixTimeSeconds() }));
            var signature = B64(rsa.SignData(Encoding.ASCII.GetBytes($"{header}.{claims}"), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            assertion = $"{header}.{claims}.{signature}";
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException)
        {
            throw new PlayIntegrityException("google", "The service account's private key can't be read: set the key file again.");
        }
        try
        {
            using var response = await _http.PostAsync(account.TokenUri, new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer", ["assertion"] = assertion,
            }), ct);
            var text = await response.Content.ReadAsStringAsync(ct);
            if (!response.IsSuccessStatusCode)
                throw new PlayIntegrityException("google", $"Google didn't sign the service account {account.ClientEmail} in ({(int)response.StatusCode}): {GoogleMessage(text)}",
                    retryable: (int)response.StatusCode >= 500 || response.StatusCode == System.Net.HttpStatusCode.TooManyRequests);
            var body = JsonNode.Parse(text);
            var token = body?["access_token"]?.GetValue<string>() ?? throw new PlayIntegrityException("google", "Google's sign-in answer has no access token.");
            var seconds = body?["expires_in"]?.GetValue<int>() ?? 3600;
            _access[account.ClientEmail] = (token, now.AddSeconds(seconds));
            return token;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            throw new PlayIntegrityException("google", $"Google can't be reached: {e.Message}", retryable: true);
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException) { throw new PlayIntegrityException("google", "Google's sign-in answer can't be read.", retryable: true); }
    }

    private static string GoogleMessage(string text)
    {
        string said;
        try { said = JsonNode.Parse(text)?["error"] is { } e ? (e["message"]?.GetValue<string>() ?? e.GetValue<string>()) : text; }
        catch (Exception) { said = text; }
        return said.Length > 200 ? said[..200] + "…" : said;
    }
}
