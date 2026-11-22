using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Npgsql;
using Testcontainers.PostgreSql;
using Winche.Core;
using Winche.Integrity.AspNetCore;

namespace Winche.Integrity.Tests;

public sealed class PostgresFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder("postgres:17-alpine").Build();
    public async Task InitializeAsync() => await _container.StartAsync();
    public async Task DisposeAsync() => await _container.DisposeAsync();

    public async Task<string> NewDatabaseAsync()
    {
        var name = $"i{Guid.NewGuid():N}"[..20];
        await using var conn = new NpgsqlConnection(_container.GetConnectionString());
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand($"CREATE DATABASE {name}", conn);
        await cmd.ExecuteNonQueryAsync();
        return new NpgsqlConnectionStringBuilder(_container.GetConnectionString()) { Database = name }.ConnectionString;
    }
}

[CollectionDefinition("postgres")]
public sealed class PostgresCollection : ICollectionFixture<PostgresFixture>;

/// <summary>A host with Integrity and one product's API (database, at /documents/v1) behind the check.</summary>
public sealed class TestApp : IAsyncDisposable
{
    public const string MasterKey = "integrity-tests-master-key-0123456789abcdef";
    private readonly WebApplication _app;
    public HttpClient Client { get; }
    public FakeTimeProvider Clock { get; }
    public IServiceProvider Services => _app.Services;
    public WincheIntegrity Integrity => _app.Services.GetRequiredService<WincheIntegrity>();

    private TestApp(WebApplication app, FakeTimeProvider clock) { _app = app; Clock = clock; Client = app.GetTestClient(); }

    public static async Task<TestApp> StartAsync(string db, string project = "clinic", string masterKey = MasterKey, string[]? previousKeys = null,
        Action<WincheIntegrityOptions>? configure = null)
    {
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton<TimeProvider>(clock);
        builder.Services.AddWincheConfig(o => { o.ConnectionString = db; o.MasterKey = masterKey; o.PreviousMasterKeys = previousKeys ?? []; });
        builder.Services.AddWincheIntegrity(o => { o.ProjectId = _ => project; configure?.Invoke(o); });
        var app = builder.Build();
        app.Use(async (http, next) =>
        {
            if (http.Request.Path.StartsWithSegments("/documents/v1") && await IntegrityEndpoints.CheckAsync(http, "database")) return;
            await next(http);
        });
        app.MapWincheIntegrity();
        app.MapGet("/documents/v1/ping", (HttpContext http) => Results.Json(new { app = IntegrityEndpoints.VerdictOf(http)?.AppId }));
        app.MapMethods("/documents/v1/ping", ["OPTIONS"], () => Results.NoContent());
        await app.StartAsync();
        await app.Services.GetRequiredService<SettingsStore>().EnsureLoadedAsync();
        return new TestApp(app, clock);
    }

    public async Task SaveAsync(Func<IntegritySettings, IntegritySettings> change) => await Integrity.SaveAsync(change(Integrity.Current), "admin@example.com", "test");

    /// <summary>Adds an app and a debug token for it; the token.</summary>
    public async Task<string> AppWithDebugTokenAsync(string app = "clinic-app")
    {
        var (token, kept) = Integrity.NewDebugToken(app, "CI", "admin@example.com");
        await SaveAsync(s => s with
        {
            Apps = s.Apps.Any(a => a.Id == app) ? s.Apps : [.. s.Apps, new IntegrityApp { Id = app, Name = "Clinic", AndroidPackage = "com.example.clinic" }],
            DebugTokens = [.. s.DebugTokens, kept],
        });
        return token;
    }

    public async Task<HttpResponseMessage> ExchangeAsync(object body) => await Client.PostAsJsonAsync("/integrity/v1/exchange", body);

    public async Task<string> TokenAsync(string debugToken, string app = "clinic-app")
    {
        var r = await ExchangeAsync(new { app, provider = "debug", debugToken });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("token").GetString()!;
    }

    public async Task<HttpResponseMessage> PingAsync(string? token = null, bool query = false)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, query && token is not null ? $"/documents/v1/ping?winche_integrity={Uri.EscapeDataString(token)}" : "/documents/v1/ping");
        if (token is not null && !query) req.Headers.Add(IntegrityEndpoints.Header, token);
        return await Client.SendAsync(req);
    }

    public static async Task<string> ReasonOf(HttpResponseMessage r) =>
        (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("error").GetProperty("reason").GetString()!;

    public async ValueTask DisposeAsync() { Client.Dispose(); await _app.DisposeAsync(); }
}

[Collection("postgres")]
public class IntegrityTests(PostgresFixture pg)
{
    [Fact]
    public async Task A_debug_token_is_exchanged_for_a_token_that_says_which_app_until_it_expires()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync());
        var debug = await app.AppWithDebugTokenAsync();
        var r = await app.ExchangeAsync(new { app = "clinic-app", provider = "debug", debugToken = debug });
        var body = await r.Content.ReadFromJsonAsync<JsonElement>();
        var token = body.GetProperty("token").GetString()!;
        Assert.StartsWith("wit1.", token);
        Assert.InRange(body.GetProperty("expiresAt").GetDateTimeOffset() - app.Clock.GetUtcNow(), TimeSpan.FromMinutes(59), TimeSpan.FromMinutes(61));   // 60 minutes by default

        var verdict = app.Integrity.Verify(token)!;
        Assert.Equal(("clinic-app", "debug"), (verdict.AppId, verdict.Provider));
        Assert.Equal("clinic-app", (await (await app.PingAsync(token)).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("app").GetString());
        Assert.Equal("clinic-app", (await (await app.PingAsync(token, query: true)).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("app").GetString());

        app.Clock.Advance(TimeSpan.FromMinutes(61));
        Assert.Null(app.Integrity.Verify(token));

        // How long tokens last is a setting.
        await app.SaveAsync(s => s with { TokenMinutes = 240 });
        var longer = await (await app.ExchangeAsync(new { app = "clinic-app", provider = "debug", debugToken = debug })).Content.ReadFromJsonAsync<JsonElement>();
        Assert.InRange(longer.GetProperty("expiresAt").GetDateTimeOffset() - app.Clock.GetUtcNow(), TimeSpan.FromMinutes(239), TimeSpan.FromMinutes(241));
    }

    [Fact]
    public async Task Only_proof_gets_a_token()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync());
        var debug = await app.AppWithDebugTokenAsync();
        await app.AppWithDebugTokenAsync("other-app");

        Assert.Equal("integrity-unknown-app", await TestApp.ReasonOf(await app.ExchangeAsync(new { app = "nope", provider = "debug", debugToken = debug })));
        Assert.Equal("integrity-rejected", await TestApp.ReasonOf(await app.ExchangeAsync(new { app = "clinic-app", provider = "debug", debugToken = "wdt_guess" })));
        Assert.Equal("integrity-rejected", await TestApp.ReasonOf(await app.ExchangeAsync(new { app = "other-app", provider = "debug", debugToken = debug })));   // another app's
        Assert.Equal("integrity-provider", await TestApp.ReasonOf(await app.ExchangeAsync(new { app = "clinic-app", provider = "magic" })));
        Assert.Equal("integrity-provider", await TestApp.ReasonOf(await app.ExchangeAsync(new { app = "clinic-app" })));
        // Only its hash is kept.
        Assert.DoesNotContain(app.Integrity.Current.DebugTokens, t => t.Hash.Contains(debug) || debug.Contains(t.Hash));
    }

    [Fact]
    public async Task Tokens_stop_working_when_tampered_with_moved_to_another_project_or_their_app_or_debug_token_is_removed()
    {
        var db = await pg.NewDatabaseAsync();
        string token, debug;
        await using (var app = await TestApp.StartAsync(db))
        {
            debug = await app.AppWithDebugTokenAsync();
            token = await app.TokenAsync(debug);
            var dot = token.LastIndexOf('.');
            Assert.Null(app.Integrity.Verify(token[..dot] + ".AAAA"));
            Assert.Null(app.Integrity.Verify(token[..(dot - 2)] + "xx" + token[dot..]));
            Assert.Null(app.Integrity.Verify("wit1.nonsense"));
            Assert.Null(app.Integrity.Verify("not a token"));
        }
        // The same server (master key) and settings database, another project: refused.
        await using (var other = await TestApp.StartAsync(db, project: "other"))
            Assert.Null(other.Integrity.Verify(token));
        // Another master key: refused; the old one as a previous key: still good (tokens survive a key change).
        await using (var rekeyed = await TestApp.StartAsync(db, masterKey: "a-new-master-key-0123456789abcdefghijk"))
            Assert.Null(rekeyed.Integrity.Verify(token));
        await using (var rotated = await TestApp.StartAsync(db, masterKey: "a-new-master-key-0123456789abcdefghijk", previousKeys: [TestApp.MasterKey]))
            Assert.NotNull(rotated.Integrity.Verify(token));

        await using var again = await TestApp.StartAsync(db);
        Assert.NotNull(again.Integrity.Verify(token));
        await again.SaveAsync(s => s with { DebugTokens = [] });
        Assert.Null(again.Integrity.Verify(token));   // its debug token removed
        var fresh = await again.TokenAsync(await again.AppWithDebugTokenAsync());
        await again.SaveAsync(s => s with { Apps = [], DebugTokens = [] });
        Assert.Null(again.Integrity.Verify(fresh));   // its app removed
    }

    [Fact]
    public async Task Monitor_counts_without_refusing_enforce_refuses_off_does_neither()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync());
        var token = await app.TokenAsync(await app.AppWithDebugTokenAsync());
        var usage = app.Services.GetRequiredService<IntegrityUsage>();

        // Monitor, the default: both answered, counted apart.
        Assert.Equal(HttpStatusCode.OK, (await app.PingAsync()).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await app.PingAsync(token)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await app.PingAsync("wit1.forged.AAAA")).StatusCode);
        var counted = await usage.ReadAsync();
        Assert.Equal(2, counted.Single(u => u.AppId == IntegrityUsage.Unverified && u.Product == "database").Today);
        Assert.Equal(1, counted.Single(u => u.AppId == "clinic-app" && u.Product == "database").Today);

        // Enforce: without a valid token, refused; with one, answered. Preflights pass.
        await app.SaveAsync(s => s with { Enforcement = new Dictionary<string, string> { ["database"] = "enforce" } });
        var refused = await app.PingAsync();
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        Assert.Equal("integrity-required", await TestApp.ReasonOf(refused));
        Assert.Equal("integrity-required", await TestApp.ReasonOf(await app.PingAsync("wit1.forged.AAAA")));
        Assert.Equal(HttpStatusCode.OK, (await app.PingAsync(token)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Options, "/documents/v1/ping"))).StatusCode);

        // Off: not checked, not counted.
        await app.SaveAsync(s => s with { Enforcement = new Dictionary<string, string> { ["database"] = "off" } });
        var before = (await usage.ReadAsync()).Sum(u => u.Today);
        Assert.Equal(HttpStatusCode.OK, (await app.PingAsync()).StatusCode);
        Assert.Equal(before, (await usage.ReadAsync()).Sum(u => u.Today));
    }

    [Fact]
    public async Task A_host_without_Integrity_says_so_at_the_exchange()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        await using var app = builder.Build();
        app.MapWincheIntegrity();
        await app.StartAsync();
        var r = await app.GetTestClient().PostAsJsonAsync("/integrity/v1/exchange", new { app = "x", provider = "debug", debugToken = "wdt_x" });
        Assert.Equal("integrity-unavailable", await TestApp.ReasonOf(r));
    }

    [Fact]
    public void Links_browsers_open_and_calls_from_other_services_never_need_a_token()
    {
        foreach (var path in new[] { "/auth/v1/action", "/auth/v1/action/apply", "/auth/v1/.well-known/jwks.json", "/functions/v1/http/stripeWebhook",
                     "/functions/v1/http/hook/deep/path", "/auth/v1/providers/staff/backchannel-logout", "/auth/v1/providers/staff/changed" })
            Assert.True(IntegrityEndpoints.IsExempt(path), path);
        foreach (var path in new[] { "/auth/v1/signIn", "/auth/v1/providers", "/functions/v1/call/send", "/documents/v1/documents/x", "/auth/v1/actions" })
            Assert.False(IntegrityEndpoints.IsExempt(path), path);
    }

    [Fact]
    public async Task Settings_that_cant_work_are_refused_and_apps_carry_over_until_first_saved()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), configure: o =>
            o.CarryOverApps = _ => [new IntegrityApp { Id = "old-app", Name = "Old", AppleBundleId = "com.example.old" }]);
        Assert.Equal("old-app", Assert.Single(app.Integrity.Current.Apps).Id);
        Assert.Equal("com.example.old", app.Integrity.Current.Apps[0].AppleBundleId);
        Assert.Equal("monitor", app.Integrity.Current.ModeOf("storage"));

        var store = app.Services.GetRequiredService<SettingsStore>();
        async Task<IReadOnlyList<string>> Refused(IntegritySettings s) =>
            (await Assert.ThrowsAsync<SettingsValidationException>(() => app.Integrity.SaveAsync(s, null, "x"))).Errors;
        Assert.Contains(await Refused(new IntegritySettings { Enforcement = new Dictionary<string, string> { ["database"] = "enforce" } }), e => e.Contains("Add an app before"));
        Assert.Contains(await Refused(new IntegritySettings { Enforcement = new Dictionary<string, string> { ["mail"] = "loud" } }), e => e.Contains("'mail' isn't a product"));
        Assert.Contains(await Refused(new IntegritySettings { TokenMinutes = 5 }), e => e.Contains("30 minutes to 24 hours"));
        Assert.Contains(await Refused(new IntegritySettings { Apps = [new IntegrityApp { Id = "a-1", Name = "A", AppleTeamId = "abc" }] }), e => e.Contains("Apple team id"));
        Assert.Contains(await Refused(new IntegritySettings { DebugTokens = [new IntegrityDebugToken { Id = "dt-1", App = "gone", Name = "CI" }] }), e => e.Contains("isn't there"));

        // Once saved, the saved apps are the apps.
        await app.Integrity.SaveAsync(app.Integrity.Current with { Apps = [] }, null, "Start again");
        Assert.Empty(app.Integrity.Current.Apps);
        Assert.DoesNotContain(store.Areas, a => a.Name == "apps");   // nothing of the host's own
    }
}
