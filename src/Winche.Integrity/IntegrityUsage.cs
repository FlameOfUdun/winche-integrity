using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using Winche.Core;

namespace Winche.Integrity;

/// <summary>
/// Requests per app and product per day (and when each was last seen), counted in memory and written every 30 seconds
/// to <c>winche_integrity_usage</c> in the config database. Requests without a valid token count under
/// <see cref="Unverified"/>.
/// </summary>
public sealed class IntegrityUsage
{
    public const string Unverified = "";
    internal const string Table = "winche_integrity_usage";
    private static readonly string[] Schema =
    [
        $"""
        CREATE TABLE IF NOT EXISTS {Table} (
            app_id    text        NOT NULL,
            product   text        NOT NULL,
            day       date        NOT NULL,
            requests  bigint      NOT NULL,
            last_seen timestamptz NOT NULL,
            PRIMARY KEY (app_id, product, day)
        );
        """,
    ];

    private readonly NpgsqlDataSource? _db;
    private readonly TimeProvider _time;
    private ConcurrentDictionary<(string App, string Product, DateOnly Day), (long Count, DateTimeOffset Last)> _pending = new();
    private bool _ready;

    public IntegrityUsage(IServiceProvider services, TimeProvider? time = null)
    {
        _db = services.GetKeyedService<NpgsqlDataSource>("WincheConfigOptions");
        _time = time ?? TimeProvider.System;
    }

    public void Count(string appId, string product)
    {
        var now = _time.GetUtcNow();
        _pending.AddOrUpdate((appId, product, DateOnly.FromDateTime(now.UtcDateTime)), (1, now), (_, v) => (v.Count + 1, now));
    }

    private async Task EnsureAsync(CancellationToken ct)
    {
        if (_ready || _db is null) return;
        await WincheSchema.EnsureAsync(_db, "integrity-usage", Schema, ct);
        _ready = true;
    }

    /// <summary>Writes what's been counted since the last flush.</summary>
    public async Task FlushAsync(CancellationToken ct = default)
    {
        if (_db is null || _pending.IsEmpty) return;
        var batch = Interlocked.Exchange(ref _pending, new());
        await EnsureAsync(ct);
        foreach (var ((app, product, day), (count, last)) in batch)
        {
            await using var cmd = _db.CreateCommand($"""
                INSERT INTO {Table} (app_id, product, day, requests, last_seen) VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (app_id, product, day) DO UPDATE SET requests = {Table}.requests + EXCLUDED.requests,
                    last_seen = GREATEST({Table}.last_seen, EXCLUDED.last_seen)
                """);
            cmd.Parameters.AddWithValue(app);
            cmd.Parameters.AddWithValue(product);
            cmd.Parameters.AddWithValue(day);
            cmd.Parameters.AddWithValue(count);
            cmd.Parameters.AddWithValue(last);
            await cmd.ExecuteNonQueryAsync(ct);
        }
    }

    public sealed record Usage(string AppId, string Product, long Today, long Last7Days, DateTimeOffset? LastSeen);

    /// <summary>Each app's (and the unverified) requests per product, today and over the last 7 days (flushes first).</summary>
    public async Task<IReadOnlyList<Usage>> ReadAsync(CancellationToken ct = default)
    {
        if (_db is null) return [];
        await FlushAsync(ct);
        await EnsureAsync(ct);
        var today = DateOnly.FromDateTime(_time.GetUtcNow().UtcDateTime);
        await using var cmd = _db.CreateCommand($"""
            SELECT app_id, product, COALESCE(SUM(requests) FILTER (WHERE day = $1), 0), SUM(requests), MAX(last_seen)
            FROM {Table} WHERE day > $1 - 7 GROUP BY app_id, product
            """);
        cmd.Parameters.AddWithValue(today);
        var result = new List<Usage>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            result.Add(new(r.GetString(0), r.GetString(1), r.GetInt64(2), r.GetInt64(3), r.GetFieldValue<DateTimeOffset>(4)));
        return result;
    }
}

/// <summary>Writes <see cref="IntegrityUsage"/> every 30 seconds, and once more on the way down.</summary>
internal sealed class IntegrityUsageFlusher(IntegrityUsage usage, ILogger<IntegrityUsageFlusher> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30));
        try
        {
            while (await timer.WaitForNextTickAsync(ct)) await Flush(ct);
        }
        catch (OperationCanceledException) { }
    }

    public override async Task StopAsync(CancellationToken ct)
    {
        await base.StopAsync(ct);
        await Flush(ct);
    }

    private async Task Flush(CancellationToken ct)
    {
        try { await usage.FlushAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { logger.LogWarning(ex, "Couldn't write Integrity usage."); }
    }
}
