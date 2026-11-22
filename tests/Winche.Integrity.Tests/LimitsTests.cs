using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Winche.Integrity.AspNetCore;

namespace Winche.Integrity.Tests;

/// <summary>How often apps may try, what a token says about its lifetime, and which settings can't work.</summary>
[Collection("postgres")]
public class LimitsTests(PostgresFixture pg)
{
    [Fact]
    public async Task Tries_are_limited_per_address_with_a_minute_to_wait()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), configure: o => o.AttemptsPerMinutePerAddress = 3);
        var debug = await app.AppWithDebugTokenAsync();
        for (var i = 0; i < 2; i++) Assert.Equal(HttpStatusCode.OK, (await app.Client.PostAsJsonAsync("/integrity/v1/challenge", new { app = "clinic-app" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await app.ExchangeAsync(new { app = "clinic-app", provider = "debug", debugToken = debug })).StatusCode);
        var limited = await app.ExchangeAsync(new { app = "clinic-app", provider = "debug", debugToken = debug });
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.Equal("integrity-rate-limited", await TestApp.ReasonOf(limited));
        Assert.Equal("60", limited.Headers.GetValues("Retry-After").Single());
        // An app that isn't there costs nothing and says nothing about what was asked.
        var unknown = await app.Client.PostAsJsonAsync("/integrity/v1/challenge", new { app = "<script>" });
        Assert.Equal("integrity-unknown-app", await TestApp.ReasonOf(unknown));
        Assert.DoesNotContain("<script>", await unknown.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task A_token_says_how_long_it_lasts_so_apps_with_a_wrong_clock_refresh_in_time()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync());
        var debug = await app.AppWithDebugTokenAsync();
        await app.SaveAsync(s => s with { TokenMinutes = 90 });
        var body = await (await app.ExchangeAsync(new { app = "clinic-app", provider = "debug", debugToken = debug })).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(90 * 60, body.GetProperty("expiresIn").GetInt32());
    }

    [Fact]
    public void Settings_that_would_let_anyone_through_are_refused()
    {
        static List<string> Of(IntegrityApp a) => IntegritySettings.ProblemsOf(a).ToList();
        Assert.Contains(Of(new IntegrityApp { Id = "a-1", Name = "A", AndroidPackage = "com.example.app", AndroidSideloaded = true }), p => p.Contains("signing certificate"));
        Assert.DoesNotContain(Of(new IntegrityApp { Id = "a-1", Name = "A", AndroidPackage = "com.example.app", AndroidSideloaded = true,
            AndroidCertificates = [new string('a', 43)] }), p => p.Contains("signing certificate"));
        Assert.Contains(Of(new IntegrityApp { Id = "a-1", Name = "A", WebSiteKey = "1x00000000000000000000AA" }), p => p.Contains("test site keys"));
        Assert.Contains(Of(new IntegrityApp { Id = "", Name = "A" }), p => p.Contains("isn't an app id"));
    }

    [Theory]
    [InlineData("/auth/v1/photos/abc", "GET", true)]
    [InlineData("/auth/v1/photos/abc", "POST", false)]
    [InlineData("/auth/v1/photosX", "GET", false)]
    [InlineData("/auth/v1/.well-known/jwks.json", "GET", true)]
    [InlineData("/auth/v1/.well-known/jwks.json", "DELETE", false)]
    [InlineData("/auth/v1/providers/staff/changed", "POST", true)]
    [InlineData("/AUTH/v1/Providers/staff/Backchannel-Logout", "POST", true)]
    [InlineData("/auth/v1/providers/staff/sub/changed", "POST", false)]
    [InlineData("/auth/v1/providers/changed", "POST", false)]
    [InlineData("/auth/v1/action", "POST", true)]
    [InlineData("/functions/v1/http/hook", "POST", true)]
    [InlineData("/documents/v1:commit", "POST", false)]
    public void Only_these_addresses_go_without_a_token(string path, string method, bool exempt) =>
        Assert.Equal(exempt, IntegrityEndpoints.IsExempt(new PathString(path), method));
}
