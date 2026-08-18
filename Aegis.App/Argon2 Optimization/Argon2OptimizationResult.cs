namespace Aegis.App.Argon2_Optimization
{
    public sealed class Argon2OptimizationResult
    {
        public int MemoryMiB { get; init; }

        public int Iterations { get; init; }

        public int Parallelism { get; init; }

        public double MeasuredMilliseconds { get; init; }

        public double TargetMilliseconds { get; init; }

        public ulong PhysicalMemoryBytes { get; init; }

        public ulong AvailableMemoryBytes { get; init; }

        public int MaximumAllowedMemoryMiB { get; init; }

        public string Description =>
            $"{MemoryMiB:N0} MiB / " +
            $"{Iterations} iterations / " +
            $"{Parallelism} lanes / " +
            $"{MeasuredMilliseconds:N0} ms";
    }
}
