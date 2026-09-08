namespace Aegis.App.Settings
{
    public sealed class AegisSettings
    {
        public int Pbkdf2Iterations { get; set; } = 600_000;

        public int Argon2Iterations { get; set; } = 1;

        public int Argon2MemoryMiB { get; set; } = 2048;

        public int Argon2Parallelism { get; set; } = 4;

        public bool Fips { get; set; }

        public int KdfTargetMilliseconds { get; set; } = 10_000;
    }
}
