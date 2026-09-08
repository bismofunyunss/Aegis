using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Aegis.App.Argon2_Optimization;

public static class Argon2Optimizer
{
    // =========================================================
    // TEST DATA
    // =========================================================

    private const int OutputLength =
        64;

    private const int PasswordLength =
        32;

    private const int SaltLength =
        128;


    // =========================================================
    // ARGON2 POLICY
    // =========================================================

    /*
     * Minimum memory the optimizer will consider.
     *
     * 2048 MiB = 2 GiB.
     */
    private const int MinimumMemoryMiB =
        2048;

    /*
     * Fixed Argon2id parallelism used during optimization.
     */
    private const int Argon2Parallelism =
        4;

    /*
     * Maximum Argon2id passes considered.
     */
    private const int MaximumIterations =
        64;


    // =========================================================
    // MEMORY POLICY
    // =========================================================

    /*
     * Physical-memory ceiling.
     *
     * This prevents the optimizer from deliberately selecting
     * an allocation that consumes an excessive percentage of
     * system RAM.
     *
     * Example:
     *
     * 16 GiB x 0.70 = approximately 11.2 GiB.
     */
    private const double MaximumPhysicalMemoryFraction =
        0.70;

    /*
     * Additional absolute application ceiling.
     *
     * Even if a machine has enormous RAM, the optimizer will
     * not deliberately test more than this amount.
     *
     * 8192 MiB = 8 GiB.
     */
    private const int AbsoluteMaximumMemoryMiB =
        8192;

    /*
     * Search granularity.
     *
     * Memory candidates are rounded to 128 MiB boundaries.
     */
    private const int MemoryGranularityMiB =
        128;


    // =========================================================
    // TARGET SAFETY MARGIN
    // =========================================================

    /*
     * The user-selected target is intentionally reduced before
     * optimization.
     *
     * Example:
     *
     * User target = 120,000 ms
     * Effective target = 108,000 ms
     *
     * This leaves headroom for normal system load when the
     * resulting Argon2 parameters are actually used later.
     */
    private const double TargetSafetyFactor =
        0.90;


    /*
     * Expose the minimum to the UI.
     */
    public const int MinimumConfiguredMemoryMiB =
        MinimumMemoryMiB;


    // =========================================================
    // WINDOWS MEMORY INFORMATION
    // =========================================================

    [StructLayout(
        LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength;

        public uint dwMemoryLoad;

        public ulong ullTotalPhys;

        public ulong ullAvailPhys;

        public ulong ullTotalPageFile;

        public ulong ullAvailPageFile;

        public ulong ullTotalVirtual;

        public ulong ullAvailVirtual;

        public ulong ullAvailExtendedVirtual;
    }


    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    [return: MarshalAs(
        UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(
        ref MEMORYSTATUSEX lpBuffer);


    private static (
        ulong TotalBytes,
        ulong AvailableBytes)
        GetPhysicalMemory()
    {
        var status =
            new MEMORYSTATUSEX
            {
                dwLength =
                    (uint)Marshal.SizeOf<
                        MEMORYSTATUSEX>()
            };

        if (!GlobalMemoryStatusEx(
                ref status))
        {
            throw new InvalidOperationException(
                "Unable to determine system memory.");
        }

        return (
            status.ullTotalPhys,
            status.ullAvailPhys);
    }


    // =========================================================
    // GC PREPARATION
    // =========================================================

    private static void PrepareForArgon2Benchmark()
    {
        /*
         * Reduce managed-memory pressure before a large native
         * Argon2 allocation.
         *
         * This does not reclaim kernel memory, driver memory,
         * or native allocations owned by other components.
         */
        GC.Collect(
            GC.MaxGeneration,
            GCCollectionMode.Forced,
            blocking: true,
            compacting: true);

        GC.WaitForPendingFinalizers();

        GC.Collect(
            GC.MaxGeneration,
            GCCollectionMode.Forced,
            blocking: true,
            compacting: true);
    }


    // =========================================================
    // PHYSICAL MEMORY CEILING
    // =========================================================

    private static int GetMaximumPhysicalMemoryMiB(
        ulong physicalBytes)
    {
        double physicalLimitBytes =
            physicalBytes *
            MaximumPhysicalMemoryFraction;

        long maximumMiB =
            (long)(
                physicalLimitBytes /
                (1024d * 1024d));

        maximumMiB =
            Math.Min(
                maximumMiB,
                AbsoluteMaximumMemoryMiB);

        /*
         * Round down to the search granularity.
         */
        maximumMiB =
            maximumMiB /
            MemoryGranularityMiB *
            MemoryGranularityMiB;

        if (maximumMiB <
            MinimumMemoryMiB)
        {
            throw new InvalidOperationException(
                $"The system does not have enough physical memory " +
                $"for the minimum Argon2id configuration of " +
                $"{MinimumMemoryMiB:N0} MiB.");
        }

        return (int)maximumMiB;
    }


    // =========================================================
    // ARGON2 BENCHMARK
    // =========================================================

    private static double Benchmark(
        int memoryMiB,
        int iterations,
        byte[] password,
        byte[] salt,
        int samples = 1)
    {
        if (memoryMiB <
            MinimumMemoryMiB)
        {
            throw new ArgumentOutOfRangeException(
                nameof(memoryMiB),
                $"Memory must be at least " +
                $"{MinimumMemoryMiB:N0} MiB.");
        }

        if (iterations <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(iterations));
        }

        if (samples <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(samples));
        }


        int memoryKiB =
            checked(
                memoryMiB *
                1024);


        var parameters =
            new Argon2Parameters.Builder(
                Argon2Parameters.Argon2id)

            .WithSalt(
                salt)

            .WithMemoryAsKB(
                memoryKiB)

            .WithIterations(
                iterations)

            .WithParallelism(
                Argon2Parallelism)

            .WithVersion(
                Argon2Parameters.Version13)

            .Build();


        var generator =
            new Argon2BytesGenerator();


        generator.Init(
            parameters);


        // =====================================================
        // WARM-UP
        // =====================================================

        byte[] warmup =
            new byte[
                OutputLength];

        try
        {
            generator.GenerateBytes(
                password,
                warmup);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                warmup);
        }


        // =====================================================
        // MEASURE
        // =====================================================

        double totalMilliseconds =
            0;


        for (var sample = 0;
             sample < samples;
             sample++)
        {
            byte[] output =
                new byte[
                    OutputLength];

            try
            {
                var stopwatch =
                    Stopwatch.StartNew();


                generator.GenerateBytes(
                    password,
                    output);


                stopwatch.Stop();


                totalMilliseconds +=
                    stopwatch.Elapsed.TotalMilliseconds;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    output);
            }
        }


        return
            totalMilliseconds /
            samples;
    }


    // =========================================================
    // SAFE BENCHMARK
    // =========================================================

    private static bool TryBenchmark(
        int memoryMiB,
        int iterations,
        byte[] password,
        byte[] salt,
        out double elapsedMilliseconds,
        int samples = 1)
    {
        elapsedMilliseconds =
            0;


        PrepareForArgon2Benchmark();


        try
        {
            elapsedMilliseconds =
                Benchmark(
                    memoryMiB,
                    iterations,
                    password,
                    salt,
                    samples);

            return true;
        }
        catch (OutOfMemoryException)
        {
            Debug.WriteLine(
                $"Argon2 optimizer: OOM at " +
                $"{memoryMiB:N0} MiB / " +
                $"{iterations} iterations.");

            return false;
        }
    }


    // =========================================================
    // PUBLIC OPTIMIZER
    // =========================================================

    public static Argon2OptimizationResult Optimize(
        double targetMilliseconds)
    {
        if (targetMilliseconds <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(targetMilliseconds));
        }


        double effectiveTargetMilliseconds =
            targetMilliseconds *
            TargetSafetyFactor;


        if (effectiveTargetMilliseconds <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(targetMilliseconds));
        }


        byte[] password =
            RandomNumberGenerator.GetBytes(
                PasswordLength);

        byte[] salt =
            RandomNumberGenerator.GetBytes(
                SaltLength);


        try
        {
            // =====================================================
            // MEMORY INFORMATION
            // =====================================================

            var memory =
                GetPhysicalMemory();


            ulong physicalBytes =
                memory.TotalBytes;


            ulong availableBytes =
                memory.AvailableBytes;


            int maximumMemoryMiB =
                GetMaximumPhysicalMemoryMiB(
                    physicalBytes);


            Debug.WriteLine(
                $"Argon2 optimizer: Physical RAM = " +
                $"{physicalBytes / 1024d / 1024d / 1024d:F2} GiB");


            Debug.WriteLine(
                $"Argon2 optimizer: Available RAM = " +
                $"{availableBytes / 1024d / 1024d / 1024d:F2} GiB");


            Debug.WriteLine(
                $"Argon2 optimizer: Physical ceiling = " +
                $"{maximumMemoryMiB:N0} MiB");


            Debug.WriteLine(
                $"Argon2 optimizer: Minimum memory = " +
                $"{MinimumMemoryMiB:N0} MiB");


            Debug.WriteLine(
                $"Argon2 optimizer: Parallelism = " +
                $"{Argon2Parallelism}");


            Debug.WriteLine(
                $"Argon2 optimizer: User target = " +
                $"{targetMilliseconds:N0} ms");


            Debug.WriteLine(
                $"Argon2 optimizer: Effective target = " +
                $"{effectiveTargetMilliseconds:N0} ms");


            // =====================================================
            // FIND MAXIMUM MEMORY THAT FITS ONE ITERATION
            // =====================================================

            int selectedMemoryMiB =
                FindMaximumMemory(
                    password,
                    salt,
                    maximumMemoryMiB,
                    effectiveTargetMilliseconds);


            Debug.WriteLine(
                $"Argon2 optimizer: Selected memory = " +
                $"{selectedMemoryMiB:N0} MiB");


            // =====================================================
            // FIND MAXIMUM ITERATIONS
            // =====================================================

            int selectedIterations =
                FindMaximumIterations(
                    password,
                    salt,
                    selectedMemoryMiB,
                    effectiveTargetMilliseconds);


            /*
             * This should only occur if even one iteration at
             * the selected memory no longer fits.
             *
             * Because system conditions can change between
             * benchmarks, fall back to smaller memory instead
             * of immediately failing.
             */
            while (selectedIterations < 1 &&
                   selectedMemoryMiB >
                   MinimumMemoryMiB)
            {
                selectedMemoryMiB -=
                    MemoryGranularityMiB;


                if (selectedMemoryMiB <
                    MinimumMemoryMiB)
                {
                    selectedMemoryMiB =
                        MinimumMemoryMiB;
                }


                Debug.WriteLine(
                    $"Argon2 optimizer: Reducing memory to " +
                    $"{selectedMemoryMiB:N0} MiB because no " +
                    $"valid iteration count fits.");


                selectedIterations =
                    FindMaximumIterations(
                        password,
                        salt,
                        selectedMemoryMiB,
                        effectiveTargetMilliseconds);
            }


            if (selectedIterations < 1)
            {
                throw new InvalidOperationException(
                    $"Unable to find a valid Argon2id configuration " +
                    $"within the requested target of " +
                    $"{targetMilliseconds:N0} ms.");
            }


            // =====================================================
            // FINAL VALIDATION
            // =====================================================

            if (!TryBenchmark(
                    selectedMemoryMiB,
                    selectedIterations,
                    password,
                    salt,
                    out double finalTime,
                    samples: 3))
            {
                throw new InvalidOperationException(
                    $"The final Argon2id benchmark could not " +
                    $"allocate {selectedMemoryMiB:N0} MiB.");
            }


            /*
             * System load may have changed after the search.
             *
             * Reduce iterations conservatively until the final
             * measurement is within the effective target.
             */
            while (finalTime >
                       effectiveTargetMilliseconds &&
                   selectedIterations > 1)
            {
                double scale =
                    effectiveTargetMilliseconds /
                    finalTime;


                int adjustedIterations =
                    (int)Math.Floor(
                        selectedIterations *
                        scale *
                        0.95);


                adjustedIterations =
                    Math.Clamp(
                        adjustedIterations,
                        1,
                        selectedIterations - 1);


                selectedIterations =
                    adjustedIterations;


                if (!TryBenchmark(
                        selectedMemoryMiB,
                        selectedIterations,
                        password,
                        salt,
                        out finalTime,
                        samples: 2))
                {
                    throw new InvalidOperationException(
                        "The final Argon2id benchmark failed " +
                        "while adjusting iterations.");
                }
            }


            /*
             * If even one iteration at the selected memory
             * exceeds the effective target, reduce memory.
             */
            while (finalTime >
                       effectiveTargetMilliseconds &&
                   selectedMemoryMiB >
                   MinimumMemoryMiB)
            {
                selectedMemoryMiB -=
                    MemoryGranularityMiB;


                if (selectedMemoryMiB <
                    MinimumMemoryMiB)
                {
                    selectedMemoryMiB =
                        MinimumMemoryMiB;
                }


                selectedIterations =
                    FindMaximumIterations(
                        password,
                        salt,
                        selectedMemoryMiB,
                        effectiveTargetMilliseconds);


                if (selectedIterations < 1)
                {
                    continue;
                }


                if (!TryBenchmark(
                        selectedMemoryMiB,
                        selectedIterations,
                        password,
                        salt,
                        out finalTime,
                        samples: 2))
                {
                    continue;
                }
            }


            if (finalTime >
                effectiveTargetMilliseconds)
            {
                throw new InvalidOperationException(
                    $"The minimum valid Argon2id configuration " +
                    $"could not meet the requested target of " +
                    $"{targetMilliseconds:N0} ms.");
            }


            // =====================================================
            // RESULT
            // =====================================================

            var result =
                new Argon2OptimizationResult
                {
                    MemoryMiB =
                        selectedMemoryMiB,

                    Iterations =
                        selectedIterations,

                    Parallelism =
                        Argon2Parallelism,

                    MeasuredMilliseconds =
                        finalTime,

                    TargetMilliseconds =
                        targetMilliseconds,

                    PhysicalMemoryBytes =
                        physicalBytes,

                    AvailableMemoryBytes =
                        availableBytes,

                    MaximumAllowedMemoryMiB =
                        maximumMemoryMiB
                };


            Debug.WriteLine(
                $"Argon2 optimizer: FINAL = " +
                $"{result.Description}");


            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                password);

            CryptographicOperations.ZeroMemory(
                salt);
        }
    }


    // =========================================================
    // FIND MAXIMUM MEMORY
    // =========================================================

    private static int FindMaximumMemory(
        byte[] password,
        byte[] salt,
        int maximumMemoryMiB,
        double targetMilliseconds)
    {
        // =====================================================
        // TEST MINIMUM
        // =====================================================

        if (!TryBenchmark(
                MinimumMemoryMiB,
                1,
                password,
                salt,
                out double minimumTime))
        {
            throw new InvalidOperationException(
                $"The minimum Argon2id configuration of " +
                $"{MinimumMemoryMiB:N0} MiB could not be allocated.");
        }


        Debug.WriteLine(
            $"Argon2 optimizer: " +
            $"{MinimumMemoryMiB:N0} MiB / " +
            $"1 iteration = " +
            $"{minimumTime:N0} ms");


        if (minimumTime >
            targetMilliseconds)
        {
            throw new InvalidOperationException(
                $"The minimum Argon2id configuration of " +
                $"{MinimumMemoryMiB:N0} MiB exceeds the " +
                $"effective target of " +
                $"{targetMilliseconds:N0} ms.");
        }


        // =====================================================
        // TEST MAXIMUM CEILING
        // =====================================================

        if (TryBenchmark(
                maximumMemoryMiB,
                1,
                password,
                salt,
                out double maximumTime))
        {
            Debug.WriteLine(
                $"Argon2 optimizer: " +
                $"{maximumMemoryMiB:N0} MiB / " +
                $"1 iteration = " +
                $"{maximumTime:N0} ms");


            if (maximumTime <=
                targetMilliseconds)
            {
                return maximumMemoryMiB;
            }
        }
        else
        {
            Debug.WriteLine(
                $"Argon2 optimizer: " +
                $"{maximumMemoryMiB:N0} MiB could not be allocated.");
        }


        // =====================================================
        // BINARY SEARCH
        // =====================================================

        int low =
            MinimumMemoryMiB;


        int high =
            maximumMemoryMiB;


        int best =
            MinimumMemoryMiB;


        while (low <= high)
        {
            int middle =
                low +
                ((high - low) / 2);


            middle =
                middle /
                MemoryGranularityMiB *
                MemoryGranularityMiB;


            if (middle <
                MinimumMemoryMiB)
            {
                middle =
                    MinimumMemoryMiB;
            }


            if (!TryBenchmark(
                    middle,
                    1,
                    password,
                    salt,
                    out double elapsed))
            {
                /*
                 * Candidate allocation failed.
                 *
                 * Search lower.
                 */
                high =
                    middle -
                    MemoryGranularityMiB;


                continue;
            }


            Debug.WriteLine(
                $"Argon2 optimizer: " +
                $"{middle:N0} MiB / " +
                $"1 iteration = " +
                $"{elapsed:N0} ms");


            if (elapsed <=
                targetMilliseconds)
            {
                best =
                    middle;


                low =
                    middle +
                    MemoryGranularityMiB;
            }
            else
            {
                high =
                    middle -
                    MemoryGranularityMiB;
            }
        }


        return best;
    }


    // =========================================================
    // FIND MAXIMUM ITERATIONS
    // =========================================================

    private static int FindMaximumIterations(
        byte[] password,
        byte[] salt,
        int memoryMiB,
        double targetMilliseconds)
    {
        // =====================================================
        // ONE ITERATION
        // =====================================================

        if (!TryBenchmark(
                memoryMiB,
                1,
                password,
                salt,
                out double oneIterationTime))
        {
            return 0;
        }


        Debug.WriteLine(
            $"Argon2 optimizer: " +
            $"{memoryMiB:N0} MiB / " +
            $"1 iteration = " +
            $"{oneIterationTime:N0} ms");


        if (oneIterationTime >
            targetMilliseconds)
        {
            return 0;
        }


        // =====================================================
        // MAXIMUM ITERATIONS
        // =====================================================

        if (TryBenchmark(
                memoryMiB,
                MaximumIterations,
                password,
                salt,
                out double maximumIterationTime))
        {
            Debug.WriteLine(
                $"Argon2 optimizer: " +
                $"{memoryMiB:N0} MiB / " +
                $"{MaximumIterations} iterations = " +
                $"{maximumIterationTime:N0} ms");


            if (maximumIterationTime <=
                targetMilliseconds)
            {
                return MaximumIterations;
            }
        }
        else
        {
            Debug.WriteLine(
                $"Argon2 optimizer: maximum iteration " +
                $"benchmark failed.");
        }


        // =====================================================
        // BINARY SEARCH
        // =====================================================

        int low =
            1;


        int high =
            MaximumIterations;


        int best =
            1;


        while (low <= high)
        {
            int middle =
                low +
                ((high - low) / 2);


            if (!TryBenchmark(
                    memoryMiB,
                    middle,
                    password,
                    salt,
                    out double elapsed))
            {
                /*
                 * Allocation failure at a higher iteration count
                 * is treated as a failed candidate.
                 */
                high =
                    middle - 1;


                continue;
            }


            Debug.WriteLine(
                $"Argon2 optimizer: " +
                $"{memoryMiB:N0} MiB / " +
                $"{middle} iterations = " +
                $"{elapsed:N0} ms");


            if (elapsed <=
                targetMilliseconds)
            {
                best =
                    middle;


                low =
                    middle + 1;
            }
            else
            {
                high =
                    middle - 1;
            }
        }


        return best;
    }
}
