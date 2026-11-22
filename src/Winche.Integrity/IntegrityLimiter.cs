using System.Collections.Concurrent;

namespace Winche.Integrity;

/// <summary>
/// How often apps may try, a minute at a time: every try per caller's address
/// (<see cref="WincheIntegrityOptions.AttemptsPerMinutePerAddress"/>), and the tries that cost a call to Google or
/// Cloudflare per app (<see cref="WincheIntegrityOptions.AttemptsPerMinutePerApp"/>; Play Integrity has a daily quota).
/// Counts are fixed one-minute windows held in memory: no timers, nothing to dispose.
/// </summary>
public sealed class IntegrityLimiter(WincheIntegrityOptions options, TimeProvider? time = null)
{
    private readonly ConcurrentDictionary<string, Window> _windows = new();
    private readonly TimeProvider _time = time ?? TimeProvider.System;

    private sealed class Window(long minute) { public readonly long Minute = minute; public int Count; }

    /// <summary>Takes one try for <paramref name="address"/>: false when it has used up its minute's.</summary>
    public bool TryTakeAddress(string? address) => Take("ip:" + (address ?? "unknown"), options.AttemptsPerMinutePerAddress);

    /// <summary>Takes one paid try (Play Integrity, Turnstile) for <paramref name="app"/>: false when it has used up its minute's.</summary>
    public bool TryTakeApp(string app) => Take("app:" + app, options.AttemptsPerMinutePerApp);

    private bool Take(string key, int limit)
    {
        if (limit <= 0) return true;
        var minute = _time.GetUtcNow().ToUnixTimeSeconds() / 60;
        var window = _windows.AddOrUpdate(key, _ => new Window(minute), (_, w) => w.Minute == minute ? w : new Window(minute));
        var taken = Interlocked.Increment(ref window.Count) <= limit;
        // Old minutes' windows are dropped now and then, so addresses seen once don't stay.
        if (_windows.Count > 10_000)
            foreach (var (k, w) in _windows)
                if (w.Minute < minute) _windows.TryRemove(new KeyValuePair<string, Window>(k, w));
        return taken;
    }
}
