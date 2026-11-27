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
    private int _count;   // about how many windows there are (ConcurrentDictionary.Count takes every lock)
    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private long _cleared;

    /// <summary>For tests: the count kept, and the windows there really are.</summary>
    internal (int Counted, int Windows) Counts => (Volatile.Read(ref _count), _windows.Count);

    private sealed class Window(long period) { public readonly long Period = period; public int Count; }

    /// <summary>Takes one try for the caller at <paramref name="address"/>: false when it has used up its minute's.</summary>
    public bool TryTakeAddress(string? address)
    {
        var limit = options.AttemptsPerMinutePerAddress;
        if (limit <= 0) return true;
        var minute = Minute();
        var key = "ip:" + CallerOf(address);
        // Past the cap, callers not yet counted share a window by their network (an IPv6 /48, an IPv4 /16), with room
        // for many of them: one network's many addresses fill only its own. Past twice the cap, one window for all.
        if (Volatile.Read(ref _count) >= MaxCallers && !_windows.ContainsKey(key))
            return Take(Volatile.Read(ref _count) >= 2 * MaxCallers ? "ip:overflow" : "ip:overflow:" + NetworkOf(address), minute, (long)limit * 1000);
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

    /// <summary>A caller's wider network: an IPv6 address's /48, an IPv4 one's /16.</summary>
    internal static string NetworkOf(string? address)
    {
        if (address is null || !IPAddress.TryParse(address, out var ip)) return "unknown";
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        var bytes = ip.GetAddressBytes();
        var kept = ip.AddressFamily == AddressFamily.InterNetworkV6 ? 6 : 2;
        Array.Clear(bytes, kept, bytes.Length - kept);
        return new IPAddress(bytes) + (kept == 6 ? "/48" : "/16");
    }

    private long Minute()
    {
        var minute = _time.GetUtcNow().ToUnixTimeSeconds() / 60;
        // Once as each minute begins: windows of minutes gone are dropped (days' windows stay their day).
        var cleared = Interlocked.Read(ref _cleared);
        if (minute > cleared && Interlocked.CompareExchange(ref _cleared, minute, cleared) == cleared)
            foreach (var (k, w) in _windows)
                if (!k.StartsWith("play-day:", StringComparison.Ordinal) && w.Period < minute) { if (_windows.TryRemove(new KeyValuePair<string, Window>(k, w))) Interlocked.Decrement(ref _count); }
                else if (k.StartsWith("play-day:", StringComparison.Ordinal) && w.Period < minute / 1440) { if (_windows.TryRemove(new KeyValuePair<string, Window>(k, w))) Interlocked.Decrement(ref _count); }
        return minute;
    }

    internal bool Take(string key, long period, long limit)
    {
        // Counted only when a window is really added (AddOrUpdate may run its add more than once for one key).
        while (true)
        {
            if (_windows.TryGetValue(key, out var window))
            {
                // A newer window (another try saw the minute turn first) is never replaced by an older one: counted there.
                if (window.Period >= period) return Interlocked.Increment(ref window.Count) <= limit;
                var next = new Window(period);
                if (_windows.TryUpdate(key, next, window)) return Interlocked.Increment(ref next.Count) <= limit;
            }
            else
            {
                var added = new Window(period);
                if (_windows.TryAdd(key, added))
                {
                    Interlocked.Increment(ref _count);
                    return Interlocked.Increment(ref added.Count) <= limit;
                }
            }
        }
    }
}
