using System.Threading.RateLimiting;

namespace Winche.Integrity.AspNetCore;

/// <summary>
/// How often challenges may be asked for and proofs traded: each try can cost a call to Google or Cloudflare (Play
/// Integrity has a daily quota), so tries are limited per address and per app, a minute at a time.
/// </summary>
internal sealed class IntegrityLimiter(WincheIntegrityOptions options) : IDisposable
{
    private readonly PartitionedRateLimiter<string> _limiter = PartitionedRateLimiter.Create<string, string>(key =>
        RateLimitPartition.GetFixedWindowLimiter(key, k => new FixedWindowRateLimiterOptions
        {
            PermitLimit = Math.Max(1, k.StartsWith("app:", StringComparison.Ordinal) ? options.AttemptsPerMinutePerApp : options.AttemptsPerMinutePerAddress),
            Window = TimeSpan.FromMinutes(1), QueueLimit = 0, AutoReplenishment = true,
        }));

    /// <summary>Takes one try for <paramref name="address"/> and <paramref name="app"/>: false when either has used up its minute's.</summary>
    public bool TryTake(string? address, string app)
    {
        if (options.AttemptsPerMinutePerAddress > 0)
        {
            using var lease = _limiter.AttemptAcquire("ip:" + (address ?? "unknown"));
            if (!lease.IsAcquired) return false;
        }
        if (options.AttemptsPerMinutePerApp > 0)
        {
            using var lease = _limiter.AttemptAcquire("app:" + app);
            if (!lease.IsAcquired) return false;
        }
        return true;
    }

    public void Dispose() => _limiter.Dispose();
}
