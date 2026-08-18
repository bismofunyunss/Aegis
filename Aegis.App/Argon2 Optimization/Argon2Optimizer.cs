using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Aegis.App.Argon2_Optimization
{ 
    public static class Argon2Optimizer
    {
        // =========================================================
        // ARGON2
        // =========================================================

        private const int OutputLength =
            64;

        private const int PasswordLength =
            32;

        private const int SaltLength =
            128;


        // =========================================================
        // SECURITY POLICY
        // =========================================================

        /*
         * Hard minimum.
         *
         * 2048 MiB = 2 GiB.
         */
        private const int MinimumMemoryMiB =
            2048;

        /*
         * Fixed Argon2id parallelism.
         */
        private const int Argon2Parallelism =
            4;

        /*
         * Maximum number of Argon2id passes considered.
         */
        private const int MaximumIterations =
            64;


        // =========================================================
        // AGGRESSIVE MEMORY POLICY
        // =========================================================

        /*
         * Aggressive physical-memory ceiling.
         *
         * Example:
         *
         * 16 GiB RAM × 0.70 = ~11.2 GiB
         */
        private const double MaximumPhysicalMemoryFraction =
            0.70;

        /*
         * Also require the selected allocation to remain within
         * 85% of currently AVAILABLE physical memory.
         *
         * This protects against starting an enormous derivation
         * while the machine is already under heavy load.
         */
        private const double MaximumAvailableMemoryFraction =
            0.85;

        /*
         * Absolute ceiling.
         *
         * 12 GiB = 12,288 MiB.
         */
        private const int AbsoluteMaximumMemoryMiB =
            12 * 1024;


        /*
         * Memory search granularity.
         *
         * The optimizer will refine the maximum memory setting
         * to a 128 MiB boundary.
         */
        private const int MemoryGranularityMiB =
            128;


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
        // MAXIMUM SAFE MEMORY
        // =========================================================

        private static int GetMaximumMemoryMiB(
            ulong physicalBytes,
            ulong availableBytes)
        {
            double physicalLimitBytes =
                physicalBytes *
                MaximumPhysicalMemoryFraction;

            double availableLimitBytes =
                availableBytes *
                MaximumAvailableMemoryFraction;

            double selectedLimitBytes =
                Math.Min(
                    physicalLimitBytes,
                    availableLimitBytes);

            long maximumMiB =
                (long)(
                    selectedLimitBytes /
                    (1024d * 1024d));

            maximumMiB =
                Math.Min(
                    maximumMiB,
                    AbsoluteMaximumMemoryMiB);

            /*
             * Round DOWN to our search granularity.
             */
            maximumMiB =
                maximumMiB /
                MemoryGranularityMiB *
                MemoryGranularityMiB;

            if (maximumMiB <
                MinimumMemoryMiB)
            {
                throw new InvalidOperationException(
                    $"The system does not have enough memory " +
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

            for (var i = 0;
                 i < samples;
                 i++)
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
        // PUBLIC OPTIMIZER
        // =========================================================

        public static Argon2OptimizationResult Optimize(
            double targetMilliseconds = 10000)
        {
            if (targetMilliseconds <= 0)
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
                // =================================================
                // MEMORY INFORMATION
                // =================================================

                var memory =
                    GetPhysicalMemory();

                ulong physicalBytes =
                    memory.TotalBytes;

                ulong availableBytes =
                    memory.AvailableBytes;

                int maximumMemoryMiB =
                    GetMaximumMemoryMiB(
                        physicalBytes,
                        availableBytes);


                Debug.WriteLine(
                    $"Argon2 optimizer: Physical RAM = " +
                    $"{physicalBytes / 1024d / 1024d / 1024d:F2} GiB");

                Debug.WriteLine(
                    $"Argon2 optimizer: Available RAM = " +
                    $"{availableBytes / 1024d / 1024d / 1024d:F2} GiB");

                Debug.WriteLine(
                    $"Argon2 optimizer: Maximum memory = " +
                    $"{maximumMemoryMiB:N0} MiB");

                Debug.WriteLine(
                    $"Argon2 optimizer: Minimum memory = " +
                    $"{MinimumMemoryMiB:N0} MiB");

                Debug.WriteLine(
                    $"Argon2 optimizer: Parallelism = " +
                    $"{Argon2Parallelism}");

                Debug.WriteLine(
                    $"Argon2 optimizer: Target = " +
                    $"{targetMilliseconds:N0} ms");


                // =================================================
                // FIND MAXIMUM MEMORY
                // =================================================

                int maximumMemory =
                    FindMaximumMemory(
                        password,
                        salt,
                        maximumMemoryMiB,
                        targetMilliseconds);


                Debug.WriteLine(
                    $"Argon2 optimizer: Selected memory = " +
                    $"{maximumMemory:N0} MiB");


                // =================================================
                // FIND MAXIMUM ITERATIONS
                // =================================================

                int iterations =
                    FindMaximumIterations(
                        password,
                        salt,
                        maximumMemory,
                        targetMilliseconds);


                if (iterations < 1)
                {
                    throw new InvalidOperationException(
                        $"Unable to find a valid Argon2id " +
                        $"configuration using " +
                        $"{maximumMemory:N0} MiB.");
                }


                // =================================================
                // FINAL ACCURATE MEASUREMENT
                // =================================================

                double finalTime =
                    Benchmark(
                        maximumMemory,
                        iterations,
                        password,
                        salt,
                        samples: 3);


                /*
                 * Hardware/system load can cause the final,
                 * more accurate benchmark to exceed the target.
                 *
                 * Reduce iterations if necessary.
                 */
                while (finalTime >
                           targetMilliseconds &&
                       iterations > 1)
                {
                    iterations--;

                    finalTime =
                        Benchmark(
                            maximumMemory,
                            iterations,
                            password,
                            salt,
                            samples: 2);
                }


                /*
                 * If even one iteration exceeds the target after
                 * final measurement, something changed materially
                 * during optimization.
                 */
                if (finalTime >
                    targetMilliseconds)
                {
                    throw new InvalidOperationException(
                        $"The minimum valid configuration at " +
                        $"{maximumMemory:N0} MiB exceeds the " +
                        $"requested {targetMilliseconds:N0} ms target.");
                }


                var result =
                    new Argon2OptimizationResult
                    {
                        MemoryMiB =
                            maximumMemory,

                        Iterations =
                            iterations,

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
        // MAXIMUM MEMORY SEARCH
        // =========================================================

        private static int FindMaximumMemory(
            byte[] password,
            byte[] salt,
            int maximumMemoryMiB,
            double targetMilliseconds)
        {
            /*
             * First test the hard minimum.
             */
            double minimumTime =
                Benchmark(
                    MinimumMemoryMiB,
                    1,
                    password,
                    salt);

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
                    $"target time of " +
                    $"{targetMilliseconds:N0} ms.");
            }


            /*
             * If our safety ceiling itself fits, use the whole
             * allowed memory budget.
             */
            double maximumTime =
                Benchmark(
                    maximumMemoryMiB,
                    1,
                    password,
                    salt);

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


            /*
             * Binary-search the largest memory allocation that
             * fits within the target.
             */
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

                /*
                 * Round to our memory granularity.
                 */
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


                double elapsed =
                    Benchmark(
                        middle,
                        1,
                        password,
                        salt);


                Debug.WriteLine(
                    $"Argon2 optimizer: Test memory " +
                    $"{middle:N0} MiB = " +
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
        // MAXIMUM ITERATIONS
        // =========================================================

        private static int FindMaximumIterations(
            byte[] password,
            byte[] salt,
            int memoryMiB,
            double targetMilliseconds)
        {
            /*
             * Test one iteration first.
             */
            double oneIterationTime =
                Benchmark(
                    memoryMiB,
                    1,
                    password,
                    salt);


            if (oneIterationTime >
                targetMilliseconds)
            {
                return 0;
            }


            /*
             * Test the maximum iteration count.
             */
            double maximumIterationTime =
                Benchmark(
                    memoryMiB,
                    MaximumIterations,
                    password,
                    salt);


            if (maximumIterationTime <=
                targetMilliseconds)
            {
                return MaximumIterations;
            }


            /*
             * Binary search 1..64.
             */
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


                double elapsed =
                    Benchmark(
                        memoryMiB,
                        middle,
                        password,
                        salt);


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
}
