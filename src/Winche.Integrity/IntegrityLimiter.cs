using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace Winche.Integrity;

/// <summary>
/// How often apps may try: every try per caller (<see cref="WincheIntegrityOptions.AttemptsPerMinutePerAddress"/>; an
/// IPv6 caller counts by its /64, which one machine usually has whole), and Play Integrity proofs, which use up the
/// project's daily quota at Google, per app (<see cref="WincheIntegrityOptions.AttemptsPerMinutePerApp"/>, and
/// optionally <see cref="WincheIntegrityOptions.PlayIntegrityPerDayPerApp"/>). Counts are fixed windows held in memory:
/// cleared as each minute passes, at most <see cref="MaxCallers"/> callers a minute (more share one window), no timers.
/// </summary>
public sealed class IntegrityLimiter(WincheIntegrityOptions options, TimeProvider? time = null)
{
    /// <summary>Callers counted on their own within a minute; beyond them, new ones share one window.</summary>
    public const int MaxCallers = 100_000;

    private readonly ConcurrentDictionary<string, Window> _windows = new();
    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private long _cleared;

    private sealed class Window(long period) { public readonly long Period = period; public int Count; }

    /// <summary>Takes one try for the caller at <paramref name="address"/>: false when it has used up its minute's.</summary>
    public bool TryTakeAddress(string? address)
    {
        var limit = options.AttemptsPerMinutePerAddress;
        if (limit <= 0) return true;
        var minute = Minute();
        var key = "ip:" + CallerOf(address);
        // Past the cap, callers not yet counted share one window with room for many of them.
        if (_windows.Count >= MaxCallers && !_windows.ContainsKey(key)) return Take("ip:overflow", minute, (long)limit * 1000);
        return Take(key, minute, limit);
    }

    /// <summary>Takes one Play Integrity proof for <paramref name="app"/>: false when it has used up its minute's or day's.</summary>
    public bool TryTakePlay(string app)
    {
        if (options.AttemptsPerMinutePerApp > 0 && !Take("play:" + app, Minute(), options.AttemptsPerMinutePerApp)) return false;
        return options.PlayIntegrityPerDayPerApp <= 0
            || Take("play-day:" + app, _time.GetUtcNow().ToUnixTimeSeconds() / 86_400, options.PlayIntegrityPerDayPerApp);
    }

    /// <summary>Who's asking: an IPv4 address as it is, an IPv6 one by its /64.</summary>
    internal static string CallerOf(string? address)
    {
        if (address is null || !IPAddress.TryParse(address, out var ip)) return address ?? "unknown";
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ip.AddressFamily != AddressFamily.InterNetworkV6) return ip.ToString();
        var bytes = ip.GetAddressBytes();
        Array.Clear(bytes, 8, 8);
        return new IPAddress(bytes) + "/64";
    }

    private long Minute()
    {
        var minute = _time.GetUtcNow().ToUnixTimeSeconds() / 60;
        // Once as each minute begins: windows of minutes gone are dropped (days' windows stay their day).
        var cleared = Interlocked.Read(ref _cleared);
        if (minute > cleared && Interlocked.CompareExchange(ref _cleared, minute, cleared) == cleared)
            foreach (var (k, w) in _windows)
                if (!k.StartsWith("play-day:", StringComparison.Ordinal) && w.Period < minute) _windows.TryRemove(new KeyValuePair<string, Window>(k, w));
                else if (k.StartsWith("play-day:", StringComparison.Ordinal) && w.Period < minute / 1440) _windows.TryRemove(new KeyValuePair<string, Window>(k, w));
        return minute;
    }

    private bool Take(string key, long period, long limit)
    {
        var window = _windows.AddOrUpdate(key, _ => new Window(period), (_, w) => w.Period == period ? w : new Window(period));
        return Interlocked.Increment(ref window.Count) <= limit;
    }
}
