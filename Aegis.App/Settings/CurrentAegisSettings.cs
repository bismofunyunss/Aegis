namespace Aegis.App.Settings;

public static class CurrentAegisSettings
{
    private static readonly Lock Sync =
        new();

    private static AegisSettings _settings =
        new();

    private static AegisSettingsStore? _store;


    // =========================================================
    // CURRENT SETTINGS
    // =========================================================

    public static AegisSettings Current
    {
        get
        {
            lock (Sync)
            {
                return _settings;
            }
        }
    }


    // =========================================================
    // WHETHER ACCOUNT SETTINGS ARE PERSISTED
    // =========================================================

    public static bool IsPersistent
    {
        get
        {
            lock (Sync)
            {
                return _store != null;
            }
        }
    }


    // =========================================================
    // RESET TO DEFAULTS
    //
    // Used before registration or after logout.
    // =========================================================

    public static void ResetToDefaults()
    {
        lock (Sync)
        {
            _store = null;

            _settings =
                new AegisSettings();
        }
    }


    // =========================================================
    // LOAD ACCOUNT SETTINGS
    //
    // Used after successful authentication.
    // =========================================================

    public static void Load(
        string username)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            username);

        lock (Sync)
        {
            var store =
                new AegisSettingsStore(
                    username);

            var settings =
                store.Load();

            _store =
                store;

            _settings =
                settings;
        }
    }


    // =========================================================
    // SAVE
    //
    // Before registration:
    //     settings remain in memory.
    //
    // After authentication:
    //     settings are written to settings.json.
    // =========================================================

    public static void Save()
    {
        lock (Sync)
        {
            _store?.Save(
                    _settings);
        }
    }


    // =========================================================
    // SNAPSHOT
    //
    // Registration should use a copy so that the values used
    // for account creation cannot change underneath the
    // registration operation.
    // =========================================================

    public static AegisSettings Snapshot()
    {
        lock (Sync)
        {
            return new AegisSettings
            {
                Pbkdf2Iterations =
                    _settings.Pbkdf2Iterations,

                Argon2Iterations =
                    _settings.Argon2Iterations,

                Argon2MemoryMiB =
                    _settings.Argon2MemoryMiB,

                Argon2Parallelism =
                    _settings.Argon2Parallelism,

                Fips =
                    _settings.Fips,

                KdfTargetMilliseconds =
                    _settings.KdfTargetMilliseconds
            };
        }
    }


    // =========================================================
    // PERSIST SETTINGS FOR A NEW ACCOUNT
    //
    // Called after registration succeeds.
    // =========================================================

    public static void PersistForUser(
        string username,
        AegisSettings settings)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            username);

        ArgumentNullException.ThrowIfNull(
            settings);

        lock (Sync)
        {
            var store =
                new AegisSettingsStore(
                    username);

            store.Save(
                settings);

            _store =
                store;

            _settings =
                settings;
        }
    }
}
