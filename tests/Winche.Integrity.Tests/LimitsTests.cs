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
    public void Play_proofs_have_an_apps_budget_by_the_minute_and_the_day_and_old_minutes_drop()
    {
        var clock = new Microsoft.Extensions.Time.Testing.FakeTimeProvider(DateTimeOffset.Parse("2026-11-22T10:00:00Z"));
        var limiter = new IntegrityLimiter(new WincheIntegrityOptions { AttemptsPerMinutePerApp = 2, PlayIntegrityPerDayPerApp = 3, AttemptsPerMinutePerAddress = 0 }, clock);
        Assert.True(limiter.TryTakeAddress("1.2.3.4"));   // no caller limit set
        Assert.True(limiter.TryTakePlay("my-app"));
        Assert.True(limiter.TryTakePlay("my-app"));
        Assert.False(limiter.TryTakePlay("my-app"));     // the minute's
        Assert.True(limiter.TryTakePlay("other-app"));   // each app its own
        clock.Advance(TimeSpan.FromMinutes(1));
        Assert.True(limiter.TryTakePlay("my-app"));
        Assert.False(limiter.TryTakePlay("my-app"));     // the day's (3)
        clock.Advance(TimeSpan.FromDays(1));
        Assert.True(limiter.TryTakePlay("my-app"));
    }

    [Theory]
    [InlineData("2001:db8:1:2:aaaa::1", "2001:db8:1:2::/64")]
    [InlineData("2001:db8:1:2:ffff:1:2:3", "2001:db8:1:2::/64")]
    [InlineData("::ffff:10.1.2.3", "10.1.2.3")]
    [InlineData("10.1.2.3", "10.1.2.3")]
    public void An_IPv6_caller_counts_by_its_64(string address, string caller) => Assert.Equal(caller, IntegrityLimiter.CallerOf(address));

    [Fact]
    public void Callers_in_one_64_share_a_limit()
    {
        var limiter = new IntegrityLimiter(new WincheIntegrityOptions { AttemptsPerMinutePerAddress = 2 });
        Assert.True(limiter.TryTakeAddress("2001:db8::1"));
        Assert.True(limiter.TryTakeAddress("2001:db8::2"));
        Assert.False(limiter.TryTakeAddress("2001:db8::ffff"));
        Assert.True(limiter.TryTakeAddress("2001:db8:0:1::1"));   // another /64
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
    public async Task Apps_carried_over_from_before_are_used_only_when_they_pass_the_checks()
    {
        await using var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), configure: o => o.CarryOverApps = _ =>
        [
            new IntegrityApp { Id = "good-app", Name = "Good" },
            new IntegrityApp { Id = "bad-app", Name = "Bad", AndroidPackage = "com.example.bad", AndroidDeviceIntegrity = "great" },
        ]);
        Assert.Equal(["good-app"], app.Integrity.Current.Apps.Select(a => a.Id));
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
    [InlineData("/.well-known/openid-configuration", "GET", true)]
    public void Only_these_addresses_go_without_a_token(string path, string method, bool exempt) =>
        Assert.Equal(exempt, IntegrityEndpoints.IsExempt(new PathString(path), method));
}
