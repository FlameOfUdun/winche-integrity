using System.Text.RegularExpressions;

namespace Winche.Integrity;

/// <summary>
/// An app of the project: its name, the SDK it's built with, and what identifies it on each platform. Its
/// <see cref="Id"/> goes in its <c>winche_options.dart</c>; it proves it's this app (and not a copy or a script) to get
/// an Integrity token, which it sends with every request.
/// </summary>
public sealed record IntegrityApp
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string Sdk { get; init; } = "flutter";
    /// <summary>Android: the package name (com.example.app), for Play Integrity.</summary>
    public string? AndroidPackage { get; init; }
    /// <summary>Android: the Google Cloud project number Play Integrity asks for (the app gets it with each challenge).</summary>
    public long? AndroidCloudProjectNumber { get; init; }
    /// <summary>Android: also accept builds Google Play doesn't know (installed some other way, internal builds). Off by default.</summary>
    public bool AndroidSideloaded { get; init; }
    /// <summary>Android: how good the device must be: <c>basic</c>, <c>device</c> (the default) or <c>strong</c>.</summary>
    public string AndroidDeviceIntegrity { get; init; } = "device";
    /// <summary>Android: when set, the app must be signed with one of these certificates (SHA-256, base64url, as Play Console shows).</summary>
    public IReadOnlyList<string> AndroidCertificates { get; init; } = [];
    /// <summary>Web: the Cloudflare Turnstile widget's site key (public; the browser gets it with each challenge).</summary>
    public string? WebSiteKey { get; init; }
    /// <summary>Web: the sites the app runs on (app.example.com); a browser check made elsewhere is refused. Empty: any.</summary>
    public IReadOnlyList<string> WebHostnames { get; init; } = [];
    /// <summary>Apple (iOS, macOS): the bundle id (com.example.app), for App Attest.</summary>
    public string? AppleBundleId { get; init; }
    /// <summary>Apple: the developer team id (10 letters and digits), for App Attest.</summary>
    public string? AppleTeamId { get; init; }
    /// <summary>
    /// Apple: also accept App Attest keys from development builds (run from Xcode), besides TestFlight and App Store
    /// ones. Off by default.
    /// </summary>
    public bool AppleDevelopment { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
}

/// <summary>
/// A debug token: lets a simulator, an emulator, a desktop build or CI get Integrity tokens for an app without proving
/// anything. Only its SHA-256 is kept; the token itself is shown once, when it's made.
/// </summary>
public sealed record IntegrityDebugToken
{
    public string Id { get; init; } = "";
    public string App { get; init; } = "";
    public string Name { get; init; } = "";
    /// <summary>The token's SHA-256, hex.</summary>
    public string Hash { get; init; } = "";
    public DateTimeOffset CreatedAt { get; init; }
    public string? CreatedBy { get; init; }
}

/// <summary>
/// The project's Integrity settings (area <c>integrity</c>): its apps, how each product treats requests without a
/// valid Integrity token, how long tokens last, and the debug tokens.
/// </summary>
public sealed partial record IntegritySettings
{
    public const string Area = "integrity";
    public const int MaxApps = 100, MaxDebugTokens = 100;
    public static readonly string[] Sdks = ["flutter"];

    /// <summary>The products whose requests Integrity checks.</summary>
    public static readonly string[] Products = ["database", "storage", "authentication", "functions", "assets"];

    /// <summary>
    /// Not checked (<c>off</c>); checked and counted, never refused (<c>monitor</c>, the default); refused without a
    /// valid token (<c>enforce</c>).
    /// </summary>
    public static readonly string[] Modes = ["off", "monitor", "enforce"];

    public IReadOnlyList<IntegrityApp> Apps { get; init; } = [];

    /// <summary>Each product's mode (database, storage, authentication, functions, assets); missing: <c>monitor</c>.</summary>
    public IReadOnlyDictionary<string, string> Enforcement { get; init; } = new Dictionary<string, string>();

    /// <summary>How long an Integrity token lasts: 30 minutes to 24 hours.</summary>
    public int TokenMinutes { get; init; } = 60;

    public IReadOnlyList<IntegrityDebugToken> DebugTokens { get; init; } = [];

    public string ModeOf(string product) => Enforcement.TryGetValue(product, out var m) && Modes.Contains(m) ? m : "monitor";

    public IReadOnlyList<string> Problems()
    {
        var problems = new List<string>();
        if (Apps.Count > MaxApps) problems.Add($"At most {MaxApps} apps.");
        if (Apps.GroupBy(a => a.Id).Any(g => g.Count() > 1)) problems.Add("Two apps have the same id.");
        foreach (var a in Apps) problems.AddRange(ProblemsOf(a));
        foreach (var (product, mode) in Enforcement)
        {
            if (!Products.Contains(product)) problems.Add($"'{product}' isn't a product.");
            if (!Modes.Contains(mode)) problems.Add($"'{mode}' isn't a mode: off, monitor or enforce.");
        }
        if (Apps.Count == 0 && Enforcement.Values.Contains("enforce")) problems.Add("Add an app before refusing requests without a token: nothing could call.");
        if (TokenMinutes is < 30 or > 1440) problems.Add("Integrity tokens last 30 minutes to 24 hours.");
        if (DebugTokens.Count > MaxDebugTokens) problems.Add($"At most {MaxDebugTokens} debug tokens.");
        foreach (var t in DebugTokens)
            if (Apps.All(a => a.Id != t.App)) problems.Add($"The debug token '{t.Name}' is for an app that isn't there ({t.App}).");
        return problems;
    }

    public static IEnumerable<string> ProblemsOf(IntegrityApp a)
    {
        if (string.IsNullOrWhiteSpace(a.Name)) yield return "Name every app.";
        else if (a.Name.Length > 80) yield return $"'{a.Name[..20]}…' is too long a name (80 at most).";
        if (!Sdks.Contains(a.Sdk)) yield return $"'{a.Sdk}' isn't an SDK Winche has yet.";
        if (a.AndroidPackage is { } pkg && !AndroidPackageRx().IsMatch(pkg)) yield return $"'{pkg}' isn't an Android package name (like com.example.app).";
        if (a.AppleBundleId is { } bundle && !BundleRx().IsMatch(bundle)) yield return $"'{bundle}' isn't a bundle id (like com.example.app).";
        if (a.AppleTeamId is { } team && !TeamRx().IsMatch(team)) yield return $"'{team}' isn't an Apple team id (10 capital letters and digits, like ABCDE12345).";
        if (a.AndroidCloudProjectNumber is <= 0) yield return "A Google Cloud project number is a positive number (Google Cloud console → the project's dashboard).";
        if (a.AndroidDeviceIntegrity is not ("basic" or "device" or "strong")) yield return $"'{a.AndroidDeviceIntegrity}' isn't a device integrity level: basic, device or strong.";
        if (a.WebSiteKey is { } siteKey && !SiteKeyRx().IsMatch(siteKey)) yield return $"'{siteKey}' isn't a Turnstile site key (like 0x4AAAAAAA…).";
        foreach (var h in a.WebHostnames)
            if (!HostnameRx().IsMatch(h)) yield return $"'{h}' isn't a site's hostname (like app.example.com: no https:// or path).";
        foreach (var c in a.AndroidCertificates)
            if (!CertificateRx().IsMatch(c)) yield return $"'{c}' isn't a certificate's SHA-256 (43 base64url characters, as Play Console shows it).";
    }

    [GeneratedRegex(@"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$")]
    private static partial Regex AndroidPackageRx();

    [GeneratedRegex(@"^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$")]
    private static partial Regex BundleRx();

    [GeneratedRegex(@"^[A-Z0-9]{10}$")]
    private static partial Regex TeamRx();

    [GeneratedRegex(@"^[A-Za-z0-9_-]{43}$")]
    private static partial Regex CertificateRx();

    [GeneratedRegex(@"^[0-9]x[A-Za-z0-9_-]{10,100}$")]
    private static partial Regex SiteKeyRx();

    [GeneratedRegex(@"^(localhost|([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})$")]
    private static partial Regex HostnameRx();
}
