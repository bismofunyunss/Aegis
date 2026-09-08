using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Aegis.App.Settings;

public sealed class AegisSettingsStore
{
    private static readonly JsonSerializerOptions JsonOptions =
        new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition =
                JsonIgnoreCondition.Never
        };


    private readonly string _path;


    public AegisSettingsStore(
        string username)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            username);


        var userFolder =
            GetUserFolder(
                username);


        Directory.CreateDirectory(
            userFolder);


        _path =
            System.IO.Path.Combine(
                userFolder,
                "settings.json");
    }


    public string Path =>
        _path;


    // =========================================================
    // LOAD
    // =========================================================

    public AegisSettings Load()
    {
        if (!File.Exists(_path))
        {
            var defaults =
                new AegisSettings();

            Save(
                defaults);

            return defaults;
        }


        try
        {
            var json =
                File.ReadAllText(
                    _path,
                    Encoding.UTF8);


            var settings =
                JsonSerializer.Deserialize<AegisSettings>(
                    json,
                    JsonOptions)
                ?? throw new InvalidDataException(
                    "Settings file is empty or invalid.");

            Validate(
                settings);


            return settings;
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException(
                "The Aegis settings file is corrupted.",
                ex);
        }
    }


    // =========================================================
    // SAVE
    // =========================================================

    public void Save(
        AegisSettings settings)
    {
        ArgumentNullException.ThrowIfNull(
            settings);


        Validate(
            settings);


        var json =
            JsonSerializer.Serialize(
                settings,
                JsonOptions);


        var tempPath =
            _path + ".tmp";


        try
        {
            /*
             * Make absolutely certain the containing directory
             * exists before attempting the write.
             */
            var directory =
                System.IO.Path.GetDirectoryName(
                    _path);

            if (string.IsNullOrWhiteSpace(
                    directory))
            {
                throw new InvalidOperationException(
                    "Unable to determine the settings directory.");
            }


            Directory.CreateDirectory(
                directory);


            File.WriteAllText(
                tempPath,
                json,
                Encoding.UTF8);


            /*
             * Replace the destination atomically from the
             * application's point of view.
             */
            File.Move(
                tempPath,
                _path,
                overwrite: true);
        }
        catch
        {
            try
            {
                if (File.Exists(
                        tempPath))
                {
                    File.Delete(
                        tempPath);
                }
            }
            catch
            {
                /*
                 * Never hide the original save exception.
                 */
            }


            throw;
        }
    }


    // =========================================================
    // USER FOLDER
    // =========================================================

    private static string GetUserFolder(
        string username)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            username);


        /*
         * The username becomes one directory name.
         *
         * Reject anything that could change the intended
         * directory structure.
         */
        if (username.Contains('\\') ||
            username.Contains('/') ||
            username.Contains(':') ||
            username.Contains('*') ||
            username.Contains('?') ||
            username.Contains('"') ||
            username.Contains('<') ||
            username.Contains('>') ||
            username.Contains('|'))
        {
            throw new ArgumentException(
                "Username contains invalid path characters.",
                nameof(username));
        }


        var localAppData =
            Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData);


        if (string.IsNullOrWhiteSpace(
                localAppData))
        {
            throw new InvalidOperationException(
                "Unable to determine the LocalAppData directory.");
        }


        return System.IO.Path.Combine(
            localAppData,
            "Aegis",
            "Users",
            username);
    }


    // =========================================================
    // VALIDATION
    // =========================================================

    private static void Validate(
        AegisSettings settings)
    {
        if (settings.Pbkdf2Iterations <
            600_000)
        {
            throw new InvalidDataException(
                "PBKDF2 iteration count is below the minimum.");
        }


        if (settings.Argon2Iterations <
            1)
        {
            throw new InvalidDataException(
                "Argon2 iteration count is invalid.");
        }


        if (settings.Argon2MemoryMiB <
            2048)
        {
            throw new InvalidDataException(
                "Argon2 memory is below the minimum.");
        }


        if (settings.Argon2Parallelism <
            1)
        {
            throw new InvalidDataException(
                "Argon2 parallelism is invalid.");
        }


        if (settings.KdfTargetMilliseconds <=
            0)
        {
            throw new InvalidDataException(
                "KDF target time is invalid.");
        }
    }
}