using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.DependencyInjection;
using Winche.Core;

namespace Winche.Integrity;

/// <summary>Who a valid Integrity token says is calling: the app, how it proved itself, and until when.</summary>
public sealed record IntegrityVerdict(string AppId, string Provider, DateTimeOffset ExpiresAt);

/// <summary>How Integrity is set up in the host (<c>AddWincheIntegrity(o => …)</c>).</summary>
public sealed class WincheIntegrityOptions
{
    /// <summary>
    /// The project tokens are for: part of each token and of its signing key, so one project's tokens never work in
    /// another's on the same server. Default <c>winche</c>.
    /// </summary>
    public Func<IServiceProvider, string>? ProjectId { get; set; }

    /// <summary>
    /// Apps to start with until the settings are first saved (a host's apps from before Integrity); none by default.
    /// </summary>
    public Func<IServiceProvider, IReadOnlyList<IntegrityApp>>? CarryOverApps { get; set; }

    /// <summary>The root App Attest attestations must chain to: Apple's (tests make their own).</summary>
    internal System.Security.Cryptography.X509Certificates.X509Certificate2? AppAttestRoot { get; set; }

    /// <summary>
    /// Challenges and proofs each address may ask for a minute (each can cost a call to Google or Cloudflare); 0: no
    /// limit. Default 30.
    /// </summary>
    public int AttemptsPerMinutePerAddress { get; set; } = 30;

    /// <summary>Challenges and proofs per app a minute, from every address together (0: no limit). Default 600.</summary>
    public int AttemptsPerMinutePerApp { get; set; } = 600;

    /// <summary>How Google is called (tests answer for it).</summary>
    internal HttpClient? PlayIntegrityHttp { get; set; }

    /// <summary>How Cloudflare is called (tests answer for it).</summary>
    internal HttpClient? TurnstileHttp { get; set; }
}

/// <summary>
/// Winche Integrity: apps prove they're the project's own (App Attest on Apple devices, Play Integrity on Android, a
/// browser check on the web, or a debug token), get a short-lived token for it, and send it with every request. Each product checks it,
/// counts it, and refuses requests without one where it's enforced (Winche.Integrity.AspNetCore).
/// <para>Tokens are signed with a key derived from the master key (<see cref="WincheKeys"/>); without one, none are made.</para>
/// </summary>
public sealed class WincheIntegrity(IServiceProvider services, WincheIntegrityOptions options, TimeProvider? time = null)
{
    /// <summary>The project secret with the Google service account's key file (JSON), for Play Integrity.</summary>
    public const string PlayServiceAccountSecret = "integrity.playIntegrity.serviceAccount";

    /// <summary>The project secret with an app's Turnstile secret key, for the browser check.</summary>
    public static string TurnstileSecret(string appId) => $"integrity.apps.{appId}.turnstileSecret";

    private const string TokenPrefix = "wit1.", DebugPrefix = "wdt_";
    private readonly TimeProvider _time = time ?? TimeProvider.System;

    private SettingsArea<IntegritySettings>? Area => services.GetService<SettingsArea<IntegritySettings>>();

    /// <summary>Whether the settings can be changed and kept here (a settings store).</summary>
    public bool Available => Area is not null && services.GetService<SettingsStore>() is not null;

    /// <summary>Whether tokens can be made and checked: they're signed with a key from the master key.</summary>
    public bool CanSign => services.GetService<WincheKeys>()?.Available == true;

    /// <summary>The project tokens are for.</summary>
    public string ProjectId => options.ProjectId?.Invoke(services) ?? "winche";

    /// <summary>The settings; until they're first saved, <see cref="WincheIntegrityOptions.CarryOverApps"/> are its apps.</summary>
    public IntegritySettings Current
    {
        get
        {
            var area = Area;
            if (area is null) return new();
            if (area.Source == SettingsSource.Saved || options.CarryOverApps?.Invoke(services) is not { Count: > 0 } apps) return area.Current;
            return area.Current with { Apps = [.. apps] };
        }
    }

    public IntegrityApp? Find(string? id) => id is null ? null : Current.Apps.FirstOrDefault(a => a.Id == id);

    /// <summary>A chosen app id: 3 to 40 lower-case letters, digits and dashes, starting with a letter.</summary>
    public static bool IsValidId(string? id) => id is { Length: >= 3 and <= 40 } && char.IsAsciiLetterLower(id[0])
        && id.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c == '-');

    /// <summary>A new id: <paramref name="prefix"/> and 12 lower-case letters and digits.</summary>
    public static string NewId(string prefix = "app-")
    {
        const string alphabet = "abcdefghijkmnpqrstuvwxyz23456789";
        return prefix + string.Concat(RandomNumberGenerator.GetItems<char>(alphabet, 12));
    }

    /// <summary>Saves <paramref name="next"/> as a new version of the settings (with who and why, for the history).</summary>
    public async Task SaveAsync(IntegritySettings next, string? by, string reason, CancellationToken ct = default)
    {
        var store = services.GetRequiredService<SettingsStore>();
        await store.SaveAsync(IntegritySettings.Area, JsonSerializer.SerializeToNode(next, SettingsArea.Json)!, by, reason, ct);
    }

    // ---- Debug tokens ----

    /// <summary>A new debug token for <paramref name="app"/> (shown once) and what's kept of it.</summary>
    public (string Token, IntegrityDebugToken Kept) NewDebugToken(string app, string name, string? by)
    {
        var token = DebugPrefix + Base64Url(RandomNumberGenerator.GetBytes(32));
        return (token, new IntegrityDebugToken { Id = NewId("dt-"), App = app, Name = name, Hash = Sha256(token), CreatedAt = _time.GetUtcNow(), CreatedBy = by });
    }

    /// <summary>The debug token <paramref name="token"/> is, for <paramref name="app"/>; null when it isn't one.</summary>
    public IntegrityDebugToken? FindDebugToken(string app, string? token)
    {
        if (token is null || !token.StartsWith(DebugPrefix, StringComparison.Ordinal) || token.Length > 100) return null;
        var hash = Encoding.ASCII.GetBytes(Sha256(token));
        return Current.DebugTokens.FirstOrDefault(t => t.App == app && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(t.Hash), hash));
    }

    // ---- Integrity tokens ----

    private sealed record Payload(
        [property: JsonPropertyName("p")] string Project, [property: JsonPropertyName("a")] string App,
        [property: JsonPropertyName("k")] string Provider, [property: JsonPropertyName("e")] long Expires,
        [property: JsonPropertyName("i")] string Id, [property: JsonPropertyName("d")] string? DebugToken = null);

    private IEnumerable<byte[]> Keys()
    {
        var keys = services.GetRequiredService<WincheKeys>();
        var purpose = $"integrity-tokens:{ProjectId}";
        yield return Encoding.UTF8.GetBytes(keys.Derive(purpose));
        foreach (var k in keys.DerivePrevious(purpose)) yield return Encoding.UTF8.GetBytes(k);
    }

    /// <summary>
    /// A token for <paramref name="app"/>, which proved itself with <paramref name="provider"/> (and, for debug, which
    /// debug token: removing it ends the tokens it got).
    /// </summary>
    public (string Token, DateTimeOffset ExpiresAt) Issue(string app, string provider, string? debugToken = null)
    {
        var expires = _time.GetUtcNow().AddMinutes(Current.TokenMinutes);
        var payload = new Payload(ProjectId, app, provider, expires.ToUnixTimeSeconds(), NewId("t-"), debugToken);
        var body = TokenPrefix + Base64Url(JsonSerializer.SerializeToUtf8Bytes(payload));
        return ($"{body}.{Base64Url(HMACSHA256.HashData(Keys().First(), Encoding.ASCII.GetBytes(body)))}", expires);
    }

    /// <summary>
    /// What <paramref name="token"/> says, when it's this project's, signed here (with the master key or a previous
    /// one), not expired, and its app (and debug token) are still there. Null otherwise.
    /// </summary>
    public IntegrityVerdict? Verify(string? token)
    {
        if (token is null || token.Length > 2000 || !token.StartsWith(TokenPrefix, StringComparison.Ordinal) || !CanSign) return null;
        var dot = token.LastIndexOf('.');
        if (dot <= TokenPrefix.Length) return null;
        var body = token[..dot];
        byte[] signature;
        try { signature = FromBase64Url(token[(dot + 1)..]); }
        catch (FormatException) { return null; }
        var data = Encoding.ASCII.GetBytes(body);
        if (!Keys().Any(k => CryptographicOperations.FixedTimeEquals(HMACSHA256.HashData(k, data), signature))) return null;
        Payload? p;
        try { p = JsonSerializer.Deserialize<Payload>(FromBase64Url(body[TokenPrefix.Length..])); }
        catch (Exception e) when (e is JsonException or FormatException) { return null; }
        if (p is null || p.Project != ProjectId) return null;
        var expires = DateTimeOffset.FromUnixTimeSeconds(p.Expires);
        if (expires <= _time.GetUtcNow()) return null;
        var current = Current;
        if (current.Apps.All(a => a.Id != p.App)) return null;   // the app was removed: its tokens stop working
        if (p.DebugToken is { } d && current.DebugTokens.All(t => t.Id != d)) return null;   // so was the debug token
        return new IntegrityVerdict(p.App, p.Provider, expires);
    }

    private static string Sha256(string s) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(s)));
    private static string Base64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] FromBase64Url(string s)
    {
        var b = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(b.PadRight(b.Length + (4 - b.Length % 4) % 4, '='));
    }
}
