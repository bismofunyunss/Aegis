using System.Diagnostics;

namespace Aegis.App.Settings;

public static class CurrentAegisSettings
{
    private static readonly Lock Sync = new();

    private static AegisSettings _settings = new();

    public static AegisSettings Snapshot()
    {
        lock (Sync)
        {
            return Clone(_settings);
        }
    }

    public static void Apply(AegisSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        lock (Sync)
        {
            _settings = Clone(settings);
        }
    }

    private static AegisSettings Clone(
        AegisSettings settings)
    {
        return new AegisSettings
        {
            Pbkdf2Iterations =
                settings.Pbkdf2Iterations,

            Argon2Iterations =
                settings.Argon2Iterations,

            Argon2MemoryMiB =
                settings.Argon2MemoryMiB,

            Argon2Parallelism =
                settings.Argon2Parallelism,

            Fips =
                settings.Fips,

            KdfTargetMilliseconds =
                settings.KdfTargetMilliseconds
        };
    }
}
