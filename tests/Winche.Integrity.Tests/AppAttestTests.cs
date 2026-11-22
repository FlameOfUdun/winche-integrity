using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Winche.Integrity.AppAttest;

namespace Winche.Integrity.Tests;

public class AppAttestVerifierTests
{
    private const string Team = "ABCDE12345", Bundle = "com.example.clinic";

    [Fact]
    public void Apples_own_root_is_the_one_embedded()
    {
        var root = AppleAppAttestRoot.Certificate;
        Assert.Equal("Apple App Attestation Root CA", root.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, false));
        Assert.Equal(new DateTime(2045, 3, 15, 0, 0, 0, DateTimeKind.Utc), root.NotAfter.ToUniversalTime());
    }

    [Fact]
    public void An_attestation_gives_the_devices_key_then_its_assertions_count_up()
    {
        using var device = new FakeAppAttest();
        var verifier = new AppAttestVerifier(device.Root);
        var cdh = FakeAppAttest.ClientDataHash("challenge-1");
        var key = verifier.VerifyAttestation(device.Attest(cdh, Team, Bundle), cdh, device.KeyId, Team, Bundle, allowDevelopment: false);
        Assert.Equal(device.PublicPoint, key.PublicKey);
        Assert.False(key.Development);
        Assert.Equal("receipt"u8.ToArray(), key.Receipt);

        var cdh2 = FakeAppAttest.ClientDataHash("challenge-2");
        Assert.Equal(1u, verifier.VerifyAssertion(device.Assert(cdh2, Team, Bundle, 1), cdh2, key.PublicKey, Team, Bundle, 0));
        Assert.Equal(7u, verifier.VerifyAssertion(device.Assert(cdh2, Team, Bundle, 7), cdh2, key.PublicKey, Team, Bundle, 1));
    }

    private static string Refused(Action check) => Assert.Throws<AppAttestException>(check).Reason;

    [Fact]
    public void Attestations_are_refused_for_the_wrong_root_challenge_app_key_environment_or_counter()
    {
        using var device = new FakeAppAttest();
        using var other = new FakeAppAttest();
        var verifier = new AppAttestVerifier(device.Root);
        var cdh = FakeAppAttest.ClientDataHash("challenge-1");

        Assert.Equal("chain", Refused(() => new AppAttestVerifier(other.Root).VerifyAttestation(device.Attest(cdh, Team, Bundle), cdh, device.KeyId, Team, Bundle, false)));
        Assert.Equal("chain", Refused(() => new AppAttestVerifier().VerifyAttestation(device.Attest(cdh, Team, Bundle), cdh, device.KeyId, Team, Bundle, false)));   // Apple's root: not ours
        Assert.Equal("chain", Refused(() => verifier.VerifyAttestation(device.Attest(cdh, Team, Bundle, selfIssued: true), cdh, device.KeyId, Team, Bundle, false)));
        Assert.Equal("nonce", Refused(() => verifier.VerifyAttestation(device.Attest(cdh, Team, Bundle), FakeAppAttest.ClientDataHash("another"), device.KeyId, Team, Bundle, false)));
        Assert.Equal("nonce", Refused(() => verifier.VerifyAttestation(device.Attest(cdh, Team, Bundle, nonceOverride: new byte[32]), cdh, device.KeyId, Team, Bundle, false)));
        Assert.Equal("app", Refused(() => verifier.VerifyAttestation(device.Attest(cdh, Team, "com.example.other"), cdh, device.KeyId, Team, Bundle, false)));
        Assert.Equal("app", Refused(() => verifier.VerifyAttestation(device.Attest(cdh, "ZZZZZ99999", Bundle), cdh, device.KeyId, Team, Bundle, false)));
        Assert.Equal("key", Refused(() => verifier.VerifyAttestation(device.Attest(cdh, Team, Bundle), cdh, other.KeyId, Team, Bundle, false)));
        Assert.Equal("key", Refused(() => verifier.VerifyAttestation(device.Attest(cdh, Team, Bundle, credentialKeyId: other.KeyId), cdh, device.KeyId, Team, Bundle, false)));
        Assert.Equal("counter", Refused(() => verifier.VerifyAttestation(device.Attest(cdh, Team, Bundle, counter: 1), cdh, device.KeyId, Team, Bundle, false)));
        Assert.Equal("format", Refused(() => verifier.VerifyAttestation([1, 2, 3], cdh, device.KeyId, Team, Bundle, false)));

        // Development builds only where the app accepts them.
        Assert.Equal("environment", Refused(() => verifier.VerifyAttestation(device.Attest(cdh, Team, Bundle, development: true), cdh, device.KeyId, Team, Bundle, false)));
        Assert.True(verifier.VerifyAttestation(device.Attest(cdh, Team, Bundle, development: true), cdh, device.KeyId, Team, Bundle, true).Development);
    }

    [Fact]
    public void Assertions_are_refused_when_signed_by_another_key_for_another_challenge_or_app_or_not_counting_up()
    {
        using var device = new FakeAppAttest();
        using var thief = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var verifier = new AppAttestVerifier(device.Root);
        var cdh = FakeAppAttest.ClientDataHash("c");
        Assert.Equal("signature", Refused(() => verifier.VerifyAssertion(device.Assert(cdh, Team, Bundle, 2, signWith: thief), cdh, device.PublicPoint, Team, Bundle, 1)));
        Assert.Equal("signature", Refused(() => verifier.VerifyAssertion(device.Assert(cdh, Team, Bundle, 2), FakeAppAttest.ClientDataHash("other"), device.PublicPoint, Team, Bundle, 1)));
        Assert.Equal("app", Refused(() => verifier.VerifyAssertion(device.Assert(cdh, Team, "com.example.other", 2), cdh, device.PublicPoint, Team, Bundle, 1)));
        Assert.Equal("counter", Refused(() => verifier.VerifyAssertion(device.Assert(cdh, Team, Bundle, 1), cdh, device.PublicPoint, Team, Bundle, 1)));
        Assert.Equal("format", Refused(() => verifier.VerifyAssertion([0xa0], cdh, device.PublicPoint, Team, Bundle, 0)));
    }
}

/// <summary>App Attest through the exchange: challenge, attestation, assertions; and what's refused.</summary>
[Collection("postgres")]
public class AppAttestExchangeTests(PostgresFixture pg)
{
    private const string Team = "ABCDE12345", Bundle = "com.example.clinic";

    private static async Task<(TestApp App, FakeAppAttest Device)> StartAsync(PostgresFixture pg, bool development = false, bool apple = true)
    {
        var device = new FakeAppAttest();
        var app = await TestApp.StartAsync(await pg.NewDatabaseAsync(), configure: o => o.AppAttestRoot = device.Root);
        await app.SaveAsync(s => s with
        {
            Apps = [new IntegrityApp { Id = "clinic-app", Name = "Clinic", AppleTeamId = apple ? Team : null, AppleBundleId = apple ? Bundle : null, AppleDevelopment = development }],
        });
        return (app, device);
    }

    private static async Task<string> ChallengeAsync(TestApp app, string id = "clinic-app")
    {
        var r = await app.Client.PostAsJsonAsync("/integrity/v1/challenge", new { app = id });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("challenge").GetString()!;
    }

    private static Task<HttpResponseMessage> AttestAsync(TestApp app, FakeAppAttest device, string challenge, byte[]? attestation = null) =>
        app.ExchangeAsync(new { app = "clinic-app", provider = "appAttest", keyId = device.KeyId, challenge,
            attestation = Convert.ToBase64String(attestation ?? device.Attest(FakeAppAttest.ClientDataHash(challenge), Team, Bundle)) });

    private static Task<HttpResponseMessage> AssertAsync(TestApp app, FakeAppAttest device, string challenge, uint counter, string? keyId = null) =>
        app.ExchangeAsync(new { app = "clinic-app", provider = "appAttest", keyId = keyId ?? device.KeyId, challenge,
            assertion = Convert.ToBase64String(device.Assert(FakeAppAttest.ClientDataHash(challenge), Team, Bundle, counter)) });

    private static async Task<string> TokenOf(HttpResponseMessage r)
    {
        Assert.True(r.StatusCode == HttpStatusCode.OK, await r.Content.ReadAsStringAsync());
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("token").GetString()!;
    }

    [Fact]
    public async Task A_device_attests_its_key_once_then_proves_itself_with_assertions()
    {
        var (app, device) = await StartAsync(pg);
        await using var _ = app;
        using var __ = device;

        var first = await TokenOf(await AttestAsync(app, device, await ChallengeAsync(app)));
        Assert.Equal(("clinic-app", "appAttest"), (app.Integrity.Verify(first)!.AppId, app.Integrity.Verify(first)!.Provider));
        var store = app.Services.GetRequiredService<IntegrityStore>();
        var kept = (await store.FindKeyAsync(device.KeyId))!;
        Assert.Equal((0L, false), (kept.Counter, kept.Development));
        Assert.Equal(device.PublicPoint, kept.PublicKey);
        Assert.Equal(1, (await store.CountKeysAsync())["clinic-app"].Keys);

        await TokenOf(await AssertAsync(app, device, await ChallengeAsync(app), 1));
        await TokenOf(await AssertAsync(app, device, await ChallengeAsync(app), 2));
        Assert.Equal(2, (await store.FindKeyAsync(device.KeyId))!.Counter);
        Assert.Equal(HttpStatusCode.OK, (await app.PingAsync(first)).StatusCode);
    }

    [Fact]
    public async Task Challenges_are_single_use_short_lived_and_the_apps_own()
    {
        var (app, device) = await StartAsync(pg);
        await using var _ = app;
        using var __ = device;
        await app.SaveAsync(s => s with { Apps = [.. s.Apps, new IntegrityApp { Id = "other-app", Name = "Other" }] });

        Assert.Equal("integrity-unknown-app", await TestApp.ReasonOf(await app.Client.PostAsJsonAsync("/integrity/v1/challenge", new { app = "nope" })));
        var challenge = await ChallengeAsync(app);
        await TokenOf(await AttestAsync(app, device, challenge));
        Assert.Equal("integrity-challenge", await TestApp.ReasonOf(await AssertAsync(app, device, challenge, 1)));   // used
        Assert.Equal("integrity-challenge", await TestApp.ReasonOf(await AssertAsync(app, device, "made-up", 1)));
        Assert.Equal("integrity-challenge", await TestApp.ReasonOf(await AssertAsync(app, device, await ChallengeAsync(app, "other-app"), 1)));   // another app's
        var late = await ChallengeAsync(app);
        app.Clock.Advance(TimeSpan.FromMinutes(6));
        Assert.Equal("integrity-challenge", await TestApp.ReasonOf(await AssertAsync(app, device, late, 1)));
    }

    [Fact]
    public async Task Replays_unknown_keys_and_spoiled_proofs_are_refused()
    {
        var (app, device) = await StartAsync(pg);
        await using var _ = app;
        using var __ = device;
        using var stranger = new FakeAppAttest();

        // An assertion with a key never attested: the app is told to attest one.
        Assert.Equal("integrity-unknown-key", await TestApp.ReasonOf(await AssertAsync(app, device, await ChallengeAsync(app), 1)));
        await TokenOf(await AttestAsync(app, device, await ChallengeAsync(app)));
        // The same key attested again; an attestation from another root; a counter that doesn't go up.
        Assert.Equal("integrity-rejected", await TestApp.ReasonOf(await AttestAsync(app, device, await ChallengeAsync(app))));
        var c = await ChallengeAsync(app);
        Assert.Equal("integrity-rejected", await TestApp.ReasonOf(await app.ExchangeAsync(new { app = "clinic-app", provider = "appAttest", keyId = stranger.KeyId, challenge = c,
            attestation = Convert.ToBase64String(stranger.Attest(FakeAppAttest.ClientDataHash(c), Team, Bundle)) })));
        await TokenOf(await AssertAsync(app, device, await ChallengeAsync(app), 5));
        var replay = await AssertAsync(app, device, await ChallengeAsync(app), 5);
        Assert.Equal("integrity-rejected", await TestApp.ReasonOf(replay));
        Assert.Contains("counter", await replay.Content.ReadAsStringAsync());
        // Neither or both proofs; not base64.
        Assert.Equal("integrity-proof", await TestApp.ReasonOf(await app.ExchangeAsync(new { app = "clinic-app", provider = "appAttest", keyId = device.KeyId, challenge = await ChallengeAsync(app) })));
        Assert.Equal("integrity-proof", await TestApp.ReasonOf(await app.ExchangeAsync(new { app = "clinic-app", provider = "appAttest", keyId = device.KeyId, challenge = await ChallengeAsync(app), assertion = "%%%" })));
    }

    [Fact]
    public async Task Development_builds_only_where_the_app_accepts_them_and_App_Attest_needs_the_apps_Apple_ids()
    {
        var (app, device) = await StartAsync(pg);
        await using var _ = app;
        using var __ = device;
        async Task<HttpResponseMessage> AttestDevelopment()
        {
            var c = await ChallengeAsync(app);
            return await AttestAsync(app, device, c, device.Attest(FakeAppAttest.ClientDataHash(c), Team, Bundle, development: true));
        }
        var refused = await AttestDevelopment();
        Assert.Contains("development build", await refused.Content.ReadAsStringAsync());
        await app.SaveAsync(s => s with { Apps = [s.Apps[0] with { AppleDevelopment = true }] });
        await TokenOf(await AttestDevelopment());
        Assert.True((await app.Services.GetRequiredService<IntegrityStore>().FindKeyAsync(device.KeyId))!.Development);
        await TokenOf(await AssertAsync(app, device, await ChallengeAsync(app), 1));
        // Turned off again: the development build's key stops working too.
        await app.SaveAsync(s => s with { Apps = [s.Apps[0] with { AppleDevelopment = false }] });
        var stopped = await AssertAsync(app, device, await ChallengeAsync(app), 2);
        Assert.Equal("integrity-rejected", await TestApp.ReasonOf(stopped));
        Assert.Contains("development build", await stopped.Content.ReadAsStringAsync());

        await app.SaveAsync(s => s with { Apps = [s.Apps[0] with { AppleTeamId = null }] });
        Assert.Equal("integrity-not-set-up", await TestApp.ReasonOf(await AssertAsync(app, device, await ChallengeAsync(app), 1)));
        // Forgetting an app's keys: its devices attest again.
        Assert.Equal(1, await app.Services.GetRequiredService<IntegrityStore>().RemoveKeysAsync("clinic-app"));
        Assert.Null(await app.Services.GetRequiredService<IntegrityStore>().FindKeyAsync(device.KeyId));
    }
}
