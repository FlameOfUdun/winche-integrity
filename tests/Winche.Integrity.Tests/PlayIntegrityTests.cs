using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Winche.Integrity.PlayIntegrity;
using Winche.Secrets;

namespace Winche.Integrity.Tests;

/// <summary>
/// Google as Play Integrity's server side sees it: a token endpoint that checks the service account's signed assertion,
/// and decodeIntegrityToken answering with the verdict a test sets for each token.
/// </summary>
public sealed class FakeGoogle : HttpMessageHandler
{
    public const string Host = "https://google.test";
    public RSA Key { get; } = RSA.Create(2048);
    public string ServiceAccountJson => new JsonObject
    {
        ["type"] = "service_account", ["client_email"] = "integrity@my-app.iam.gserviceaccount.com",
        ["private_key"] = Key.ExportPkcs8PrivateKeyPem(), ["token_uri"] = $"{Host}/token",
    }.ToJsonString();

    public Dictionary<string, JsonObject> Verdicts { get; } = [];
    public int TokenCalls, DecodeCalls;
    public HttpStatusCode? DecodeStatus;
    public List<string> DecodedPackages { get; } = [];

    static FakeGoogle() => PlayIntegrityVerifier.Endpoints.Api = Host;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var path = request.RequestUri!.AbsolutePath;
        if (path == "/token")
        {
            TokenCalls++;
            var form = await request.Content!.ReadAsStringAsync(ct);
            var assertion = Uri.UnescapeDataString(form.Split('&').First(p => p.StartsWith("assertion=", StringComparison.Ordinal))["assertion=".Length..]);
            var parts = assertion.Split('.');
            var signed = Key.VerifyData(Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"), FromB64(parts[2]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var claims = JsonNode.Parse(FromB64(parts[1]))!;
            if (!signed || claims["scope"]!.GetValue<string>() != "https://www.googleapis.com/auth/playintegrity" || claims["aud"]!.GetValue<string>() != $"{Host}/token")
                return new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = JsonContent.Create(new { error = "invalid_grant" }) };
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(new { access_token = "ya29.fake", expires_in = 3599 }) };
        }
        DecodeCalls++;
        if (request.Headers.Authorization?.Parameter != "ya29.fake") return new HttpResponseMessage(HttpStatusCode.Unauthorized);
        if (DecodeStatus is { } status) return new HttpResponseMessage(status) { Content = JsonContent.Create(new { error = new { message = "Something went wrong" } }) };
        DecodedPackages.Add(path["/v1/".Length..path.IndexOf(':')]);
        var token = JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))!["integrity_token"]!.GetValue<string>();
        return Verdicts.TryGetValue(token, out var payload)
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(new JsonObject { ["tokenPayloadExternal"] = payload.DeepClone() }.ToJsonString(), Encoding.UTF8, "application/json") }
            : new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = JsonContent.Create(new { error = new { message = "Integrity token cannot be decoded." } }) };
    }

    private static byte[] FromB64(string s)
    {
        var b = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(b.PadRight(b.Length + (4 - b.Length % 4) % 4, '='));
    }

    /// <summary>A verdict as Google gives one: this app, this challenge, now, a Play build on a good device.</summary>
    public static JsonObject Verdict(string challenge, DateTimeOffset at, string package = "com.example.clinic", string recognition = "PLAY_RECOGNIZED",
        string[]? device = null, string? requestHash = null, string[]? certificates = null) => new()
    {
        ["requestDetails"] = new JsonObject
        {
            ["requestPackageName"] = package, ["requestHash"] = requestHash ?? PlayIntegrityVerifier.RequestHash(challenge),
            ["timestampMillis"] = at.ToUnixTimeMilliseconds().ToString(),
        },
        ["appIntegrity"] = new JsonObject
        {
            ["appRecognitionVerdict"] = recognition, ["packageName"] = package, ["versionCode"] = "42",
            ["certificateSha256Digest"] = new JsonArray([.. (certificates ?? ["Sig1Sig1Sig1Sig1Sig1Sig1Sig1Sig1Sig1Sig1Sig"]).Select(c => (JsonNode)c)]),
        },
        ["deviceIntegrity"] = device is { Length: 0 } ? new JsonObject() : new JsonObject { ["deviceRecognitionVerdict"] = new JsonArray([.. (device ?? ["MEETS_DEVICE_INTEGRITY"]).Select(d => (JsonNode)d)]) },
        ["accountDetails"] = new JsonObject { ["appLicensingVerdict"] = "LICENSED" },
    };
}

[Collection("postgres")]
public class PlayIntegrityTests(PostgresFixture pg)
{
    private static async Task<(TestApp App, FakeGoogle Google)> StartAsync(PostgresFixture pg, Func<IntegrityApp, IntegrityApp>? app = null, bool account = true)
    {
        var google = new FakeGoogle();
        var test = await TestApp.StartAsync(await pg.NewDatabaseAsync(), configure: o => o.PlayIntegrityHttp = new HttpClient(google));
        var clinic = new IntegrityApp { Id = "clinic-app", Name = "Clinic", AndroidPackage = "com.example.clinic", AndroidCloudProjectNumber = 123456789012 };
        await test.SaveAsync(s => s with { Apps = [app?.Invoke(clinic) ?? clinic] });
        if (account) await test.Services.GetRequiredService<SecretStore>().SetAsync(WincheIntegrity.PlayServiceAccountSecret, google.ServiceAccountJson, "admin@example.com");
        return (test, google);
    }

    private static async Task<string> ChallengeAsync(TestApp app)
    {
        var body = await (await app.Client.PostAsJsonAsync("/integrity/v1/challenge", new { app = "clinic-app" })).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(123456789012, body.GetProperty("androidCloudProjectNumber").GetInt64());   // what the app prepares Play Integrity with
        return body.GetProperty("challenge").GetString()!;
    }

    /// <summary>A challenge, Google's verdict for it (as <paramref name="verdict"/> makes it), and the exchange.</summary>
    private static async Task<HttpResponseMessage> ProveAsync(TestApp app, FakeGoogle google, Func<string, JsonObject>? verdict = null)
    {
        var challenge = await ChallengeAsync(app);
        var token = $"play-token-{Guid.NewGuid():N}";
        google.Verdicts[token] = verdict?.Invoke(challenge) ?? FakeGoogle.Verdict(challenge, app.Clock.GetUtcNow());
        return await app.ExchangeAsync(new { app = "clinic-app", provider = "playIntegrity", challenge, token });
    }

    [Fact]
    public async Task A_Play_build_on_a_good_device_gets_a_token_and_Google_is_signed_in_to_once()
    {
        var (app, google) = await StartAsync(pg);
        await using var _ = app;
        var r = await ProveAsync(app, google);
        Assert.True(r.StatusCode == HttpStatusCode.OK, await r.Content.ReadAsStringAsync());
        var token = (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("token").GetString();
        Assert.Equal(("clinic-app", "playIntegrity"), (app.Integrity.Verify(token)!.AppId, app.Integrity.Verify(token)!.Provider));
        Assert.Equal(HttpStatusCode.OK, (await ProveAsync(app, google)).StatusCode);
        Assert.Equal(1, google.TokenCalls);   // the access token is kept
        Assert.Equal(["com.example.clinic", "com.example.clinic"], google.DecodedPackages);
    }

    [Fact]
    public async Task Tokens_for_another_app_challenge_or_time_are_refused()
    {
        var (app, google) = await StartAsync(pg);
        await using var _ = app;
        async Task<string> Refused(Func<string, JsonObject> verdict)
        {
            var r = await ProveAsync(app, google, verdict);
            Assert.Equal("integrity-rejected", await TestApp.ReasonOf(r));
            return await r.Content.ReadAsStringAsync();
        }
        var now = app.Clock.GetUtcNow();
        Assert.Contains("another app", await Refused(c => FakeGoogle.Verdict(c, now, package: "com.example.copy")));
        Assert.Contains("this challenge", await Refused(c => FakeGoogle.Verdict(c, now, requestHash: PlayIntegrityVerifier.RequestHash("another"))));
        Assert.Contains("too old", await Refused(c => FakeGoogle.Verdict(c, now.AddMinutes(-8))));
        Assert.Contains("too old", await Refused(c => FakeGoogle.Verdict(c, now.AddMinutes(5))));
        // A token Google can't read; the same challenge twice.
        var challenge = await ChallengeAsync(app);
        Assert.Equal("integrity-rejected", await TestApp.ReasonOf(await app.ExchangeAsync(new { app = "clinic-app", provider = "playIntegrity", challenge, token = "garbage" })));
        Assert.Equal("integrity-challenge", await TestApp.ReasonOf(await app.ExchangeAsync(new { app = "clinic-app", provider = "playIntegrity", challenge, token = "garbage" })));
    }

    [Fact]
    public async Task Builds_Google_Play_doesnt_know_only_where_accepted_and_signed_with_the_apps_certificate()
    {
        var (app, google) = await StartAsync(pg);
        await using var _ = app;
        var now = app.Clock.GetUtcNow();
        var sideloaded = await ProveAsync(app, google, c => FakeGoogle.Verdict(c, now, recognition: "UNRECOGNIZED_VERSION"));
        Assert.Contains("isn't a build Google Play knows", await sideloaded.Content.ReadAsStringAsync());
        Assert.Contains("couldn't tell which app", await (await ProveAsync(app, google, c => FakeGoogle.Verdict(c, now, recognition: "UNEVALUATED"))).Content.ReadAsStringAsync());

        const string ours = "OursOursOursOursOursOursOursOursOursOursOur";
        await app.SaveAsync(s => s with { Apps = [s.Apps[0] with { AndroidSideloaded = true, AndroidCertificates = [ours] }] });
        Assert.Equal(HttpStatusCode.OK, (await ProveAsync(app, google, c => FakeGoogle.Verdict(c, now, recognition: "UNRECOGNIZED_VERSION", certificates: [ours]))).StatusCode);
        var resigned = await ProveAsync(app, google, c => FakeGoogle.Verdict(c, now, recognition: "UNRECOGNIZED_VERSION"));
        Assert.Contains("isn't signed with one of its certificates", await resigned.Content.ReadAsStringAsync());
        // Google not knowing which app it is is never accepted, whatever the certificate.
        Assert.Contains("couldn't tell which app", await (await ProveAsync(app, google, c => FakeGoogle.Verdict(c, now, recognition: "UNEVALUATED", certificates: [ours]))).Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task The_device_must_reach_the_apps_level()
    {
        var (app, google) = await StartAsync(pg);
        await using var _ = app;
        var now = app.Clock.GetUtcNow();
        async Task<HttpStatusCode> Device(params string[] verdicts) => (await ProveAsync(app, google, c => FakeGoogle.Verdict(c, now, device: verdicts))).StatusCode;

        Assert.Equal(HttpStatusCode.Forbidden, await Device());   // no label: rooted, an emulator, or decoded before
        Assert.Equal(HttpStatusCode.Forbidden, await Device("MEETS_BASIC_INTEGRITY"));
        Assert.Equal(HttpStatusCode.OK, await Device("MEETS_DEVICE_INTEGRITY"));
        Assert.Equal(HttpStatusCode.OK, await Device("MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"));
        await app.SaveAsync(s => s with { Apps = [s.Apps[0] with { AndroidDeviceIntegrity = "basic" }] });
        Assert.Equal(HttpStatusCode.OK, await Device("MEETS_BASIC_INTEGRITY"));
        await app.SaveAsync(s => s with { Apps = [s.Apps[0] with { AndroidDeviceIntegrity = "strong" }] });
        Assert.Equal(HttpStatusCode.Forbidden, await Device("MEETS_DEVICE_INTEGRITY"));
        Assert.Equal(HttpStatusCode.OK, await Device("MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"));
    }

    [Fact]
    public async Task Without_a_service_account_or_package_it_says_whats_missing_and_Googles_failures_are_told_apart()
    {
        var (app, google) = await StartAsync(pg, account: false);
        await using var _ = app;
        var missing = await ProveAsync(app, google);
        Assert.Equal("integrity-not-set-up", await TestApp.ReasonOf(missing));
        Assert.Contains("service account", await missing.Content.ReadAsStringAsync());
        await app.Services.GetRequiredService<SecretStore>().SetAsync(WincheIntegrity.PlayServiceAccountSecret, "{\"not\":\"a key\"}", null);
        Assert.Equal("integrity-not-set-up", await TestApp.ReasonOf(await ProveAsync(app, google)));
        await app.Services.GetRequiredService<SecretStore>().SetAsync(WincheIntegrity.PlayServiceAccountSecret, google.ServiceAccountJson, null);

        google.DecodeStatus = HttpStatusCode.Forbidden;   // the service account's project isn't linked in Play Console
        var unlinked = await ProveAsync(app, google);
        Assert.Equal("integrity-not-set-up", await TestApp.ReasonOf(unlinked));
        // Why is for the server's log: the caller never learns the service account or Google's words.
        var said = await unlinked.Content.ReadAsStringAsync();
        Assert.Contains("server's log", said);
        Assert.DoesNotContain("iam.gserviceaccount.com", said);
        google.DecodeStatus = HttpStatusCode.TooManyRequests;   // the quota used up: for now, not a set-up problem
        Assert.Equal("integrity-unavailable", await TestApp.ReasonOf(await ProveAsync(app, google)));
        google.DecodeStatus = HttpStatusCode.ServiceUnavailable;
        Assert.Equal("integrity-unavailable", await TestApp.ReasonOf(await ProveAsync(app, google)));
        google.DecodeStatus = null;
        Assert.Equal(HttpStatusCode.OK, (await ProveAsync(app, google)).StatusCode);

        await app.SaveAsync(s => s with { Apps = [s.Apps[0] with { AndroidPackage = null }] });
        Assert.Equal("integrity-not-set-up", await TestApp.ReasonOf(await ProveAsync(app, google)));
    }

    [Fact]
    public void Android_settings_that_cant_work_are_refused()
    {
        var bad = new IntegrityApp { Id = "a-1", Name = "A", AndroidCloudProjectNumber = -1, AndroidDeviceIntegrity = "great", AndroidCertificates = ["AB:CD"] };
        var problems = IntegritySettings.ProblemsOf(bad).ToList();
        Assert.Contains(problems, p => p.Contains("project number"));
        Assert.Contains(problems, p => p.Contains("basic, device or strong"));
        Assert.Contains(problems, p => p.Contains("certificate's SHA-256"));
        Assert.Null(GoogleServiceAccount.Parse("{\"type\":\"authorized_user\"}"));
        Assert.Equal(64, PlayIntegrityVerifier.RequestHash("ch").Length);
    }
}
