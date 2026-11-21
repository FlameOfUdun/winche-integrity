using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Winche.Core;

namespace Winche.Integrity;

/// <summary>A device key an app attested (App Attest): whose it is, its public key, and how far its counter has got.</summary>
public sealed record IntegrityKey(string KeyId, string AppId, string Provider, byte[] PublicKey, long Counter, bool Development,
    DateTimeOffset CreatedAt, DateTimeOffset? LastUsedAt);

/// <summary>
/// What Integrity keeps besides its settings, in the config database: the challenges apps prove themselves against
/// (single use, a few minutes) and the device keys they attested.
/// </summary>
public sealed class IntegrityStore
{
    internal const string Challenges = "winche_integrity_challenges", Keys = "winche_integrity_keys";
    private static readonly string[] Schema =
    [
        $"""
        CREATE TABLE IF NOT EXISTS {Challenges} (
            challenge_hash bytea       PRIMARY KEY,
            app_id         text        NOT NULL,
            expires_at     timestamptz NOT NULL
        );
        CREATE INDEX IF NOT EXISTS {Challenges}_expires ON {Challenges} (expires_at);
        CREATE TABLE IF NOT EXISTS {Keys} (
            key_id       text        PRIMARY KEY,
            app_id       text        NOT NULL,
            provider     text        NOT NULL,
            public_key   bytea       NOT NULL,
            counter      bigint      NOT NULL,
            development  boolean     NOT NULL,
            receipt      bytea,
            created_at   timestamptz NOT NULL,
            last_used_at timestamptz
        );
        CREATE INDEX IF NOT EXISTS {Keys}_app ON {Keys} (app_id);
        """,
    ];

    /// <summary>How long a challenge can be answered.</summary>
    public static readonly TimeSpan ChallengeLifetime = TimeSpan.FromMinutes(5);

    private readonly NpgsqlDataSource? _db;
    private readonly TimeProvider _time;
    private bool _ready;

    public IntegrityStore(IServiceProvider services, TimeProvider? time = null)
    {
        _db = services.GetKeyedService<NpgsqlDataSource>("WincheConfigOptions");
        _time = time ?? TimeProvider.System;
    }

    /// <summary>Whether there's a database to keep challenges and keys in.</summary>
    public bool Available => _db is not null;

    private NpgsqlDataSource Db => _db ?? throw new InvalidOperationException("Integrity keeps challenges and keys in the config database: AddWincheConfig.");

    private async Task EnsureAsync(CancellationToken ct)
    {
        if (_ready) return;
        await WincheSchema.EnsureAsync(Db, "integrity-store", Schema, ct);
        _ready = true;
    }

    private static byte[] Hash(string challenge) => SHA256.HashData(Encoding.UTF8.GetBytes(challenge));

    /// <summary>A new challenge for <paramref name="appId"/>: answerable once, for <see cref="ChallengeLifetime"/>.</summary>
    public async Task<(string Challenge, DateTimeOffset ExpiresAt)> NewChallengeAsync(string appId, CancellationToken ct = default)
    {
        await EnsureAsync(ct);
        var challenge = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var now = _time.GetUtcNow();
        var expires = now + ChallengeLifetime;
        await using var batch = Db.CreateBatch();
        // Expired ones go as new ones come.
        batch.BatchCommands.Add(new NpgsqlBatchCommand($"DELETE FROM {Challenges} WHERE expires_at < $1") { Parameters = { new() { Value = now } } });
        batch.BatchCommands.Add(new NpgsqlBatchCommand($"INSERT INTO {Challenges} (challenge_hash, app_id, expires_at) VALUES ($1, $2, $3)")
        {
            Parameters = { new() { Value = Hash(challenge) }, new() { Value = appId }, new() { Value = expires } },
        });
        await batch.ExecuteNonQueryAsync(ct);
        return (challenge, expires);
    }

    /// <summary>Uses up <paramref name="challenge"/>: true when it was <paramref name="appId"/>'s and hadn't expired.</summary>
    public async Task<bool> UseChallengeAsync(string appId, string? challenge, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(challenge) || challenge.Length > 100) return false;
        await EnsureAsync(ct);
        await using var cmd = Db.CreateCommand($"DELETE FROM {Challenges} WHERE challenge_hash = $1 AND app_id = $2 AND expires_at > $3");
        cmd.Parameters.AddWithValue(Hash(challenge));
        cmd.Parameters.AddWithValue(appId);
        cmd.Parameters.AddWithValue(_time.GetUtcNow());
        return await cmd.ExecuteNonQueryAsync(ct) == 1;
    }

    /// <summary>Keeps a newly attested key; false when the key id is already kept (an attestation is used once).</summary>
    public async Task<bool> AddKeyAsync(string keyId, string appId, string provider, byte[] publicKey, bool development, byte[]? receipt, CancellationToken ct = default)
    {
        await EnsureAsync(ct);
        await using var cmd = Db.CreateCommand($"""
            INSERT INTO {Keys} (key_id, app_id, provider, public_key, counter, development, receipt, created_at)
            VALUES ($1, $2, $3, $4, 0, $5, $6, $7) ON CONFLICT (key_id) DO NOTHING
            """);
        cmd.Parameters.AddWithValue(keyId);
        cmd.Parameters.AddWithValue(appId);
        cmd.Parameters.AddWithValue(provider);
        cmd.Parameters.AddWithValue(publicKey);
        cmd.Parameters.AddWithValue(development);
        cmd.Parameters.AddWithValue((object?)receipt ?? DBNull.Value);
        cmd.Parameters.AddWithValue(_time.GetUtcNow());
        return await cmd.ExecuteNonQueryAsync(ct) == 1;
    }

    public async Task<IntegrityKey?> FindKeyAsync(string keyId, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(keyId) || keyId.Length > 200) return null;
        await EnsureAsync(ct);
        await using var cmd = Db.CreateCommand($"SELECT key_id, app_id, provider, public_key, counter, development, created_at, last_used_at FROM {Keys} WHERE key_id = $1");
        cmd.Parameters.AddWithValue(keyId);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        return await r.ReadAsync(ct)
            ? new IntegrityKey(r.GetString(0), r.GetString(1), r.GetString(2), r.GetFieldValue<byte[]>(3), r.GetInt64(4), r.GetBoolean(5),
                r.GetFieldValue<DateTimeOffset>(6), r.IsDBNull(7) ? null : r.GetFieldValue<DateTimeOffset>(7))
            : null;
    }

    /// <summary>
    /// Moves the key's counter on to <paramref name="counter"/>; false when it's already there or past (the same
    /// assertion twice, or two at once: only one wins).
    /// </summary>
    public async Task<bool> AdvanceAsync(string keyId, long counter, CancellationToken ct = default)
    {
        await EnsureAsync(ct);
        await using var cmd = Db.CreateCommand($"UPDATE {Keys} SET counter = $2, last_used_at = $3 WHERE key_id = $1 AND counter < $2");
        cmd.Parameters.AddWithValue(keyId);
        cmd.Parameters.AddWithValue(counter);
        cmd.Parameters.AddWithValue(_time.GetUtcNow());
        return await cmd.ExecuteNonQueryAsync(ct) == 1;
    }

    /// <summary>Forgets <paramref name="appId"/>'s keys (it was removed, or its Apple ids changed): its devices attest again.</summary>
    public async Task<int> RemoveKeysAsync(string appId, CancellationToken ct = default)
    {
        if (_db is null) return 0;
        await EnsureAsync(ct);
        await using var cmd = Db.CreateCommand($"DELETE FROM {Keys} WHERE app_id = $1");
        cmd.Parameters.AddWithValue(appId);
        return await cmd.ExecuteNonQueryAsync(ct);
    }

    /// <summary>Each app's attested keys: how many, development ones among them, and when one was last used.</summary>
    public async Task<IReadOnlyDictionary<string, (long Keys, long Development, DateTimeOffset? LastUsed)>> CountKeysAsync(CancellationToken ct = default)
    {
        var result = new Dictionary<string, (long, long, DateTimeOffset?)>();
        if (_db is null) return result;
        await EnsureAsync(ct);
        await using var cmd = Db.CreateCommand($"SELECT app_id, count(*), count(*) FILTER (WHERE development), max(last_used_at) FROM {Keys} GROUP BY app_id");
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct)) result[r.GetString(0)] = (r.GetInt64(1), r.GetInt64(2), r.IsDBNull(3) ? null : r.GetFieldValue<DateTimeOffset>(3));
        return result;
    }
}
