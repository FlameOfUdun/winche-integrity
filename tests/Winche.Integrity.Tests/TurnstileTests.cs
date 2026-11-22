using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Winche.Integrity.Turnstile;
using Winche.Secrets;

namespace Winche.Integrity.Tests;

/// <summary>Cloudflare's siteverify: each token a test hands out answers as the test sets it.</summary>
public sealed class FakeCloudflare : HttpMessageHandler
{
    public const string Secret = "0x4AAAAAAAsecretsecretsecret";
    public Dictionary<string, JsonObject> Answers { get; } = [];
    public List<Dictionary<string, string>> Calls { get; } = [];
    public HttpStatusCode? Status;

    static FakeCloudflare() => TurnstileVerifier.Endpoints.Siteverify = "https://cloudflare.test/siteverify";

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var form = (await request.Content!.ReadAsStringAsync(ct)).Split('&').Select(p => p.Split('=', 2))
            .ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p[1].Replace('+', ' ')));
        Calls.Add(form);
        if (Status is { } s) return new HttpResponseMessage(s);
        JsonObject answer = form["secret"] != Secret ? new() { ["success"] = false, ["error-codes"] = new JsonArray("invalid-input-secret") }
            : Answers.TryGetValue(form["response"], out var a) ? a : new() { ["success"] = false, ["error-codes"] = new JsonArray("invalid-input-response") };
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(answer.ToJsonString(), System.Text.Encoding.UTF8, "application/json") };
    }

    /// <summary>A pass, as Cloudflare gives one for this site, action and cData.</summary>
    public static JsonObject Pass(string cdata, DateTimeOffset at, string hostname = "app.example.com", string action = TurnstileVerifier.Action) => new()
    {
        ["success"] = true, ["challenge_ts"] = at.ToString("O"), ["hostname"] = hostname, ["error-codes"] = new JsonArray(),
        ["action"] = action, ["cdata"] = cdata,
    };
}

[Collection("postgres")]
public class TurnstileTests(PostgresFixture pg)
{
    private static async Task<(TestApp App, FakeCloudflare Cloudflare)> StartAsync(PostgresFixture pg, bool secret = true)
    {
        var cloudflare = new FakeCloudflare();
        var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), configure: o => o.TurnstileHttp = new HttpClient(cloudflare));
        await app.SaveAsync(s => s with { Apps = [new IntegrityApp { Id = "clinic-app", Name = "Clinic", WebSiteKey = "0x4AAAAAAAsitekey123", WebHostnames = ["app.example.com"] }] });
        if (secret) await app.Services.GetRequiredService<SecretStore>().SetAsync(WincheIntegrity.TurnstileSecret("clinic-app"), FakeCloudflare.Secret, null);
        return (app, cloudflare);
    }

    private static async Task<string> ChallengeAsync(TestApp app)
    {
        var body = await (await app.Client.PostAsJsonAsync("/integrity/v1/challenge", new { app = "clinic-app" })).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("0x4AAAAAAAsitekey123", body.GetProperty("webSiteKey").GetString());   // the browser renders the widget with it
        return body.GetProperty("challenge").GetString()!;
    }

    private static async Task<HttpResponseMessage> ProveAsync(TestApp app, FakeCloudflare cloudflare, Func<string, JsonObject>? answer = null)
    {
        var challenge = await ChallengeAsync(app);
        var token = $"turnstile-{Guid.NewGuid():N}";
        cloudflare.Answers[token] = answer?.Invoke(challenge) ?? FakeCloudflare.Pass(challenge, app.Clock.GetUtcNow());
        return await app.ExchangeAsync(new { app = "clinic-app", provider = "turnstile", challenge, token });
    }

    [Fact]
    public async Task A_browser_check_for_this_challenge_on_the_apps_site_gets_a_token()
    {
        var (app, cloudflare) = await StartAsync(pg);
        await using var _ = app;
        var r = await ProveAsync(app, cloudflare);
        Assert.True(r.StatusCode == HttpStatusCode.OK, await r.Content.ReadAsStringAsync());
        var token = (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("token").GetString();
        Assert.Equal("turnstile", app.Integrity.Verify(token)!.Provider);
        var call = cloudflare.Calls.Single();
        Assert.Equal(FakeCloudflare.Secret, call["secret"]);
        Assert.True(Guid.TryParse(call["idempotency_key"], out var key) && key != Guid.Empty);
    }

    [Fact]
    public async Task Checks_on_another_site_for_another_action_or_challenge_old_ones_and_test_keys_are_refused()
    {
        var (app, cloudflare) = await StartAsync(pg);
        await using var _ = app;
        var now = app.Clock.GetUtcNow();
        async Task<(string Reason, string Body)> Refused(Func<string, JsonObject> answer)
        {
            var r = await ProveAsync(app, cloudflare, answer);
            return (await TestApp.ReasonOf(r), await r.Content.ReadAsStringAsync());
        }
        Assert.Contains("evil.example.com", (await Refused(c => FakeCloudflare.Pass(c, now, hostname: "evil.example.com"))).Body);
        Assert.Contains("another action", (await Refused(c => FakeCloudflare.Pass(c, now, action: "login"))).Body);
        Assert.Contains("this challenge", (await Refused(_ => FakeCloudflare.Pass("another-challenge", now))).Body);
        Assert.Contains("too old", (await Refused(c => FakeCloudflare.Pass(c, now.AddMinutes(-7)))).Body);
        Assert.Contains("used before", (await Refused(_ => new JsonObject { ["success"] = false, ["error-codes"] = new JsonArray("timeout-or-duplicate") })).Body);
        // Cloudflare's always-passing test keys: never good enough.
        var testing = await Refused(c => new JsonObject { ["success"] = true, ["hostname"] = "example.com", ["metadata"] = new JsonObject { ["result_with_testing_key"] = true } });
        Assert.Equal("integrity-not-set-up", testing.Reason);
        Assert.Contains("test keys", testing.Body);

        // No hostnames set: any site.
        await app.SaveAsync(s => s with { Apps = [s.Apps[0] with { WebHostnames = [] }] });
        Assert.Equal(HttpStatusCode.OK, (await ProveAsync(app, cloudflare, c => FakeCloudflare.Pass(c, now, hostname: "anywhere.example.com"))).StatusCode);
    }

    [Fact]
    public async Task Without_a_site_key_or_secret_it_says_so_and_Cloudflare_failing_is_unavailable()
    {
        var (app, cloudflare) = await StartAsync(pg, secret: false);
        await using var _ = app;
        Assert.Contains("secret key", await (await ProveAsync(app, cloudflare)).Content.ReadAsStringAsync());
        await app.Services.GetRequiredService<SecretStore>().SetAsync(WincheIntegrity.TurnstileSecret("clinic-app"), "0x4AAAAAAAwrong", null);
        var wrong = await ProveAsync(app, cloudflare);
        Assert.Equal("integrity-not-set-up", await TestApp.ReasonOf(wrong));
        Assert.Contains("doesn't know the app's secret key", await wrong.Content.ReadAsStringAsync());
        await app.Services.GetRequiredService<SecretStore>().SetAsync(WincheIntegrity.TurnstileSecret("clinic-app"), FakeCloudflare.Secret, null);
        cloudflare.Status = HttpStatusCode.BadGateway;
        Assert.Equal("integrity-unavailable", await TestApp.ReasonOf(await ProveAsync(app, cloudflare)));
        cloudflare.Status = null;

        await app.SaveAsync(s => s with { Apps = [s.Apps[0] with { WebSiteKey = null }] });
        var c = (await (await app.Client.PostAsJsonAsync("/integrity/v1/challenge", new { app = "clinic-app" })).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("challenge").GetString();
        Assert.Equal("integrity-not-set-up", await TestApp.ReasonOf(await app.ExchangeAsync(new { app = "clinic-app", provider = "turnstile", challenge = c, token = "t" })));
    }

    [Fact]
    public void Web_settings_that_cant_work_are_refused()
    {
        var problems = IntegritySettings.ProblemsOf(new IntegrityApp { Id = "a-1", Name = "A", WebSiteKey = "sitekey", WebHostnames = ["https://app.example.com/", "app.example.com", "localhost"] }).ToList();
        Assert.Contains(problems, p => p.Contains("Turnstile site key"));
        Assert.Single(problems, p => p.Contains("hostname"));
    }
}
