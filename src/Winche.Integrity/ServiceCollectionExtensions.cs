using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Winche.Core;
using Winche.Secrets;

namespace Winche.Integrity;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds Winche Integrity: its settings (area <c>integrity</c>, changed in the console), <see cref="WincheIntegrity"/>
    /// and the request counts (<see cref="IntegrityUsage"/>, written to the config database every 30 seconds). Needs
    /// <c>AddWincheConfig</c> (the master key signs tokens; the config database keeps settings and counts).
    /// </summary>
    public static IServiceCollection AddWincheIntegrity(this IServiceCollection services, Action<WincheIntegrityOptions>? configure = null)
    {
        var options = new WincheIntegrityOptions();
        configure?.Invoke(options);
        services.TryAddSingleton(options);
        services.AddWincheSettingsArea(IntegritySettings.Area, "Integrity", new IntegritySettings(), s => s.Problems());
        services.TryAddSingleton<WincheIntegrity>();
        services.TryAddSingleton<IntegrityUsage>();
        services.TryAddSingleton<IntegrityStore>();
        services.TryAddSingleton(sp => new IntegrityLimiter(options, sp.GetService<TimeProvider>()));
        services.TryAddSingleton(sp => new AppAttest.AppAttestVerifier(options.AppAttestRoot, sp.GetService<TimeProvider>()));
        services.TryAddSingleton(sp => new PlayIntegrity.PlayIntegrityVerifier(options.PlayIntegrityHttp, sp.GetService<TimeProvider>()));
        services.TryAddSingleton(sp => new Turnstile.TurnstileVerifier(options.TurnstileHttp, sp.GetService<TimeProvider>()));
        services.AddWincheSecrets();   // the Google service account
        services.AddHostedService<IntegrityUsageFlusher>();
        return services;
    }
}
