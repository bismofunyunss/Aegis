using Konscious.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Aegis.App;

public sealed record Pbkdf2OptimizationResult(
    int Iterations,
    double MeasuredMilliseconds,
    double TargetMilliseconds);

public sealed record Argon2OptimizationResult(
    int Iterations,
    int MemoryMiB,
    int Parallelism,
    double MeasuredMilliseconds,
    double TargetMilliseconds);

public sealed class KdfSettingsOptimizer : IDisposable
{
    private const int HashOutputBytes = 32;

    // ---------------------------------------------------------------------
    // PBKDF2 limits
    // ---------------------------------------------------------------------

    private const int MinimumPbkdf2Iterations = 600_000;
    private const int MaximumPbkdf2Iterations = 50_000_000;

    // ---------------------------------------------------------------------
    // Argon2 limits
    // ---------------------------------------------------------------------

    private const int MinimumArgon2Iterations = 1;
    private const int MaximumArgon2Iterations = 256;

    private const int MinimumArgon2MemoryMiB = 512;

    /*
     * This is intentionally 8192 MiB so a known-good 6 GiB configuration
     * is actually reachable by the optimizer.
     *
     * This is only a calibration ceiling. It is NOT a guarantee that the
     * machine can successfully allocate the entire amount.
     *
     * OutOfMemoryException is handled as an unusable candidate.
     */
    private const int MaximumArgon2MemoryMiB = 8192;

    private const int MinimumArgon2Parallelism = 1;
    private const int MaximumArgon2Parallelism = 20;

    // ---------------------------------------------------------------------
    // Calibration behavior
    // ---------------------------------------------------------------------

    /*
     * If a single calibration operation takes this long or longer, we
     * accept the measurement instead of trying to make calibration more
     * complicated.
     *
     * With one Argon2 iteration this should normally be nowhere near
     * several seconds on a machine capable of using multi-GiB memory.
     */
    private const double MaximumCalibrationMilliseconds = 3_000.0;

    /*
     * Timing below this level is susceptible to relatively large
     * measurement noise.
     */
    private const double MinimumUsefulMilliseconds = 0.25;

    // ---------------------------------------------------------------------
    // Physical-memory safety policy
    // ---------------------------------------------------------------------

    /*
     * Hard upper bound for a single Argon2 calibration allocation.
     *
     * 8192 MiB = 8 GiB.
     */
    private const int AbsoluteMaximumMemoryMiB = 8192;

    /*
     * Keep this amount outside the Argon2 allocation.
     */
    private const int ReservedMemoryMiB = 2048;

    /*
     * Use at most this fraction of total physical memory for the single
     * Argon2 allocation.
     *
     * 0.50 permits a 6 GiB allocation on a 16 GiB machine only if the
     * other constraints allow it; on a 32 GiB machine it permits up to
     * 8 GiB because of the absolute cap.
     *
     * This remains only a coarse safety boundary. Actual allocation can
     * still fail, and such candidates are handled as OOM candidates.
     */
    private const double MaximumPhysicalMemoryFraction = 0.50;

    // ---------------------------------------------------------------------
    // Memory search points
    // ---------------------------------------------------------------------

    private static readonly int[] MemoryCandidates =
    {
        512,
        1024,
        2048,
        3072,
        4096,
        5120,
        6144,
        7168,
        8192
    };

    // ---------------------------------------------------------------------
    // Parallelism search points
    // ---------------------------------------------------------------------

    private static readonly int[] ParallelismCandidates =
    {
        1,
        2,
        4,
        6,
        8,
        12,
        16,
        20
    };

    // ---------------------------------------------------------------------
    // State
    // ---------------------------------------------------------------------

    private readonly byte[] _password;
    private readonly byte[] _salt;

    private bool _disposed;

    public KdfSettingsOptimizer()
    {
        _password =
            RandomNumberGenerator.GetBytes(32);

        _salt =
            RandomNumberGenerator.GetBytes(32);
    }

    // =====================================================================
    // PBKDF2
    // =====================================================================

    public async Task<Pbkdf2OptimizationResult> OptimizePbkdf2Async(
        double targetMilliseconds,
        int minimumIterations,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ValidateTarget(targetMilliseconds);

        minimumIterations =
            Math.Clamp(
                minimumIterations,
                MinimumPbkdf2Iterations,
                MaximumPbkdf2Iterations);

        cancellationToken.ThrowIfCancellationRequested();

        var cache =
            new Dictionary<int, double>();

        try
        {
            double minimumTime =
                await BenchmarkPbkdf2CachedAsync(
                    cache,
                    minimumIterations,
                    cancellationToken)
                .ConfigureAwait(false);

            cancellationToken.ThrowIfCancellationRequested();

            /*
             * The minimum iteration count already meets the target.
             */
            if (minimumTime >= targetMilliseconds)
            {
                return new Pbkdf2OptimizationResult(
                    minimumIterations,
                    minimumTime,
                    targetMilliseconds);
            }

            /*
             * PBKDF2 is approximately linear in iteration count, so
             * estimate the required iteration count directly.
             */
            int estimatedIterations =
          EstimateIterations(
              minimumIterations,
              minimumTime,
              targetMilliseconds,
              MinimumPbkdf2Iterations,
              MaximumPbkdf2Iterations);

            double estimatedTime =
                await BenchmarkPbkdf2CachedAsync(
                    cache,
                    estimatedIterations,
                    cancellationToken)
                .ConfigureAwait(false);

            cancellationToken.ThrowIfCancellationRequested();

            /*
             * We now have a bracket if the estimate reached the target.
             */
            if (estimatedTime >= targetMilliseconds)
            {
                return await RefinePbkdf2Async(
                        cache,
                        minimumIterations,
                        minimumTime,
                        estimatedIterations,
                        estimatedTime,
                        targetMilliseconds,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            /*
             * The direct estimate undershot.
             *
             * Recalculate directly from the actual measured point.
             */
            int nextEstimate =
            EstimateIterations(
                minimumIterations,
                minimumTime,
                targetMilliseconds,
                MinimumPbkdf2Iterations,
                MaximumPbkdf2Iterations);

            if (nextEstimate > estimatedIterations)
            {
                double nextTime =
                    await BenchmarkPbkdf2CachedAsync(
                        cache,
                        nextEstimate,
                        cancellationToken)
                    .ConfigureAwait(false);

                cancellationToken.ThrowIfCancellationRequested();

                if (nextTime >= targetMilliseconds)
                {
                    return await RefinePbkdf2Async(
                            cache,
                            estimatedIterations,
                            estimatedTime,
                            nextEstimate,
                            nextTime,
                            targetMilliseconds,
                            cancellationToken)
                        .ConfigureAwait(false);
                }

                estimatedIterations =
                    nextEstimate;

                estimatedTime =
                    nextTime;
            }

            /*
             * We cannot exceed the supported maximum.
             */
            if (estimatedIterations >=
                MaximumPbkdf2Iterations)
            {
                return new Pbkdf2OptimizationResult(
                    estimatedIterations,
                    estimatedTime,
                    targetMilliseconds);
            }

            /*
             * One final proportional estimate.
             */
            int finalEstimate =
       EstimateIterations(
           minimumIterations,
           minimumTime,
           targetMilliseconds,
           MinimumPbkdf2Iterations,
           MaximumPbkdf2Iterations);

            double finalTime =
                await BenchmarkPbkdf2CachedAsync(
                    cache,
                    finalEstimate,
                    cancellationToken)
                .ConfigureAwait(false);

            cancellationToken.ThrowIfCancellationRequested();

            if (finalTime >= targetMilliseconds &&
                finalEstimate > estimatedIterations)
            {
                return await RefinePbkdf2Async(
                        cache,
                        estimatedIterations,
                        estimatedTime,
                        finalEstimate,
                        finalTime,
                        targetMilliseconds,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            return new Pbkdf2OptimizationResult(
                finalEstimate,
                finalTime,
                targetMilliseconds);
        }
        finally
        {
            cache.Clear();
        }
    }

    // =====================================================================
    // Argon2
    // =====================================================================

    public async Task<Argon2OptimizationResult> OptimizeArgon2Async(
        double targetMilliseconds,
        int currentIterations,
        int currentMemoryMiB,
        int currentParallelism,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ValidateTarget(targetMilliseconds);

        currentIterations =
            Math.Clamp(
                currentIterations,
                MinimumArgon2Iterations,
                MaximumArgon2Iterations);

        currentParallelism =
            Math.Clamp(
                currentParallelism,
                MinimumArgon2Parallelism,
                MaximumArgon2Parallelism);

        int safeMaximumMemoryMiB =
            CalculateSafeMaximumMemoryMiB();

        if (safeMaximumMemoryMiB <
            MinimumArgon2MemoryMiB)
        {
            throw new InvalidOperationException(
                "The system does not have enough safe memory " +
                "for the minimum Argon2 configuration.");
        }

        currentMemoryMiB =
            Math.Clamp(
                currentMemoryMiB,
                MinimumArgon2MemoryMiB,
                safeMaximumMemoryMiB);

        cancellationToken.ThrowIfCancellationRequested();

        var cache =
            new Dictionary<Argon2BenchmarkKey, double>();

        try
        {
            // -------------------------------------------------------------
            // Step 1: determine best parallelism at current memory
            // -------------------------------------------------------------

            int bestParallelism =
                await FindBestParallelismAsync(
                    currentMemoryMiB,
                    currentParallelism,
                    safeMaximumMemoryMiB,
                    cache,
                    cancellationToken)
                .ConfigureAwait(false);

            cancellationToken.ThrowIfCancellationRequested();

            // -------------------------------------------------------------
            // Step 2: construct deterministic memory search set
            // -------------------------------------------------------------

            int[] memoryLevels =
                BuildMemoryLevels(
                    currentMemoryMiB,
                    safeMaximumMemoryMiB);

            if (memoryLevels.Length == 0)
            {
                throw new InvalidOperationException(
                    "No valid Argon2 memory configurations were generated.");
            }

            var configurations =
                new List<Argon2Configuration>(
                    memoryLevels.Length);

            // -------------------------------------------------------------
            // Step 3: benchmark one Argon2 iteration at every memory level
            // -------------------------------------------------------------

            foreach (int memoryMiB in memoryLevels)
            {
                cancellationToken.ThrowIfCancellationRequested();

                double benchmarkMilliseconds;

                try
                {
                    benchmarkMilliseconds =
                        await BenchmarkArgon2CachedAsync(
                            cache,
                            memoryMiB,
                            MinimumArgon2Iterations,
                            bestParallelism,
                            safeMaximumMemoryMiB,
                            cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (OutOfMemoryException)
                {
                    /*
                     * This memory level is not usable on this machine.
                     *
                     * Do not abort the entire optimization.
                     */
                    TryForceCollection();
                    continue;
                }

                cancellationToken.ThrowIfCancellationRequested();

                if (!IsValidMeasurement(
                        benchmarkMilliseconds))
                {
                    continue;
                }

                /*
                 * We are measuring one iteration because:
                 *
                 * MinimumArgon2Iterations == 1
                 *
                 * Keep this division anyway so the code remains correct
                 * if that constant is changed later.
                 */
                double oneIterationMilliseconds =
                    benchmarkMilliseconds /
                    MinimumArgon2Iterations;

                if (!IsValidMeasurement(
                        oneIterationMilliseconds))
                {
                    continue;
                }

                /*
                 * If one iteration is already unusually expensive, it is
                 * still a valid measurement. We simply do not attempt
                 * additional calibration at that point.
                 */
                if (oneIterationMilliseconds >
                    MaximumCalibrationMilliseconds)
                {
                    configurations.Add(
                        new Argon2Configuration(
                            memoryMiB,
                            bestParallelism,
                            oneIterationMilliseconds,
                            MinimumArgon2Iterations));

                    continue;
                }

                double iterations =
                    targetMilliseconds /
                    oneIterationMilliseconds;

                if (double.IsNaN(iterations) ||
                    double.IsInfinity(iterations) ||
                    iterations <= 0)
                {
                    continue;
                }

                configurations.Add(
                    new Argon2Configuration(
                        memoryMiB,
                        bestParallelism,
                        oneIterationMilliseconds,
                        iterations));
            }

            if (configurations.Count == 0)
            {
                throw new InvalidOperationException(
                    "Unable to benchmark a usable Argon2 configuration.");
            }

            cancellationToken.ThrowIfCancellationRequested();

            // -------------------------------------------------------------
            // Step 4: choose memory configuration
            // -------------------------------------------------------------

            Argon2Configuration selectedConfiguration =
                SelectMemoryConfiguration(
                    configurations,
                    targetMilliseconds);

            cancellationToken.ThrowIfCancellationRequested();

            int estimatedIterations =
                ClampIterations(
                    selectedConfiguration.EstimatedIterations);

            // -------------------------------------------------------------
            // Step 5: refine selected configuration
            // -------------------------------------------------------------

            Argon2Candidate? candidate = null;

            try
            {
                candidate =
                    await RefineArgon2Async(
                        selectedConfiguration.MemoryMiB,
                        selectedConfiguration.Parallelism,
                        estimatedIterations,
                        targetMilliseconds,
                        safeMaximumMemoryMiB,
                        cache,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OutOfMemoryException)
            {
                /*
                 * The selected memory/iteration combination could not
                 * actually be executed even though the one-iteration
                 * calibration succeeded.
                 */
                TryForceCollection();
            }

            cancellationToken.ThrowIfCancellationRequested();

            int selectedIndex =
                FindConfigurationIndex(
                    configurations,
                    selectedConfiguration);

            Argon2Candidate? bestCandidate =
                candidate;

            // -------------------------------------------------------------
            // Step 6: examine neighboring memory configurations
            // -------------------------------------------------------------

            for (int offset = -1;
                 offset <= 1;
                 offset++)
            {
                if (offset == 0)
                {
                    continue;
                }

                int index =
                    selectedIndex + offset;

                if (index < 0 ||
                    index >= configurations.Count)
                {
                    continue;
                }

                cancellationToken.ThrowIfCancellationRequested();

                Argon2Configuration configuration =
                    configurations[index];

                int iterations =
                    ClampIterations(
                        configuration.EstimatedIterations);

                Argon2Candidate neighbor;

                try
                {
                    neighbor =
                        await RefineArgon2Async(
                            configuration.MemoryMiB,
                            configuration.Parallelism,
                            iterations,
                            targetMilliseconds,
                            safeMaximumMemoryMiB,
                            cache,
                            cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (OutOfMemoryException)
                {
                    TryForceCollection();
                    continue;
                }

                cancellationToken.ThrowIfCancellationRequested();

                if (!bestCandidate.HasValue)
                {
                    bestCandidate =
                        neighbor;

                    continue;
                }

                bestCandidate =
                    SelectArgon2Candidate(
                        bestCandidate.Value,
                        neighbor,
                        targetMilliseconds);
            }

            if (!bestCandidate.HasValue)
            {
                throw new InvalidOperationException(
                    "Unable to produce a valid Argon2 candidate.");
            }

            cancellationToken.ThrowIfCancellationRequested();

            // -------------------------------------------------------------
            // Step 7: final real benchmark
            // -------------------------------------------------------------

            double finalMilliseconds;

            try
            {
                finalMilliseconds =
                    await BenchmarkArgon2CachedAsync(
                        cache,
                        bestCandidate.Value.MemoryMiB,
                        bestCandidate.Value.Iterations,
                        bestCandidate.Value.Parallelism,
                        safeMaximumMemoryMiB,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OutOfMemoryException)
            {
                TryForceCollection();

                throw new InvalidOperationException(
                    "The optimized Argon2 configuration could not be " +
                    "executed safely on this system.");
            }

            cancellationToken.ThrowIfCancellationRequested();

            if (!IsValidMeasurement(
                    finalMilliseconds))
            {
                throw new InvalidOperationException(
                    "The final Argon2 benchmark produced an invalid runtime.");
            }

            return new Argon2OptimizationResult(
                bestCandidate.Value.Iterations,
                bestCandidate.Value.MemoryMiB,
                bestCandidate.Value.Parallelism,
                finalMilliseconds,
                targetMilliseconds);
        }
        finally
        {
            cache.Clear();
            TryForceCollection();
        }
    }

    // =====================================================================
    // Argon2 parallelism search
    // =====================================================================

    private async Task<int> FindBestParallelismAsync(
        int memoryMiB,
        int currentParallelism,
        int safeMaximumMemoryMiB,
        Dictionary<Argon2BenchmarkKey, double> cache,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var candidates =
            new SortedSet<int>
            {
                currentParallelism
            };

        foreach (int value in ParallelismCandidates)
        {
            if (value >= MinimumArgon2Parallelism &&
                value <= MaximumArgon2Parallelism)
            {
                candidates.Add(value);
            }
        }

        int bestParallelism =
            0;

        double bestTime =
            double.MaxValue;

        foreach (int parallelism in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();

            double time;

            try
            {
                time =
                    await BenchmarkArgon2CachedAsync(
                        cache,
                        memoryMiB,
                        MinimumArgon2Iterations,
                        parallelism,
                        safeMaximumMemoryMiB,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OutOfMemoryException)
            {
                /*
                 * This parallelism setting cannot be used for this
                 * memory level.
                 */
                TryForceCollection();
                continue;
            }

            cancellationToken.ThrowIfCancellationRequested();

            if (!IsValidMeasurement(time))
            {
                continue;
            }

            /*
             * Never choose a configuration merely because it produced
             * an invalid/zero measurement.
             */
            if (time < bestTime)
            {
                bestTime =
                    time;

                bestParallelism =
                    parallelism;
            }
        }

        if (bestParallelism == 0)
        {
            throw new InvalidOperationException(
                "Unable to benchmark any supported Argon2 parallelism " +
                "configuration at the current memory size.");
        }

        return bestParallelism;
    }

    // =====================================================================
    // Argon2 refinement
    // =====================================================================

    private async Task<Argon2Candidate> RefineArgon2Async(
        int memoryMiB,
        int parallelism,
        int estimatedIterations,
        double targetMilliseconds,
        int safeMaximumMemoryMiB,
        Dictionary<Argon2BenchmarkKey, double> cache,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        estimatedIterations =
            Math.Clamp(
                estimatedIterations,
                MinimumArgon2Iterations,
                MaximumArgon2Iterations);

        double estimatedTime =
            await BenchmarkArgon2CachedAsync(
                cache,
                memoryMiB,
                estimatedIterations,
                parallelism,
                safeMaximumMemoryMiB,
                cancellationToken)
            .ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();

        if (!IsValidMeasurement(estimatedTime))
        {
            throw new InvalidOperationException(
                "Argon2 refinement produced an invalid measurement.");
        }

        /*
         * Exact hit.
         */
        if (estimatedTime == targetMilliseconds)
        {
            return new Argon2Candidate(
                memoryMiB,
                estimatedIterations,
                parallelism,
                estimatedTime);
        }

        // -------------------------------------------------------------
        // Case 1: estimated point is below target.
        //
        // Expand upward until target is bracketed or maximum is reached.
        // -------------------------------------------------------------

        if (estimatedTime < targetMilliseconds)
        {
            int lowerIterations =
                estimatedIterations;

            double lowerTime =
                estimatedTime;

            int upperIterations =
                estimatedIterations;

            double upperTime =
                estimatedTime;

            while (upperIterations <
                   MaximumArgon2Iterations &&
                   upperTime <
                   targetMilliseconds)
            {
                cancellationToken.ThrowIfCancellationRequested();

                int next =
                    CalculateNextHigherIterations(
                        upperIterations,
                        upperTime,
                        targetMilliseconds);

                if (next <= upperIterations)
                {
                    next =
                        Math.Min(
                            MaximumArgon2Iterations,
                            upperIterations + 1);
                }

                double nextTime =
                    await BenchmarkArgon2CachedAsync(
                        cache,
                        memoryMiB,
                        next,
                        parallelism,
                        safeMaximumMemoryMiB,
                        cancellationToken)
                    .ConfigureAwait(false);

                cancellationToken.ThrowIfCancellationRequested();

                if (!IsValidMeasurement(nextTime))
                {
                    throw new InvalidOperationException(
                        "Argon2 refinement produced an invalid measurement.");
                }

                lowerIterations =
                    upperIterations;

                lowerTime =
                    upperTime;

                upperIterations =
                    next;

                upperTime =
                    nextTime;

                /*
                 * If the direct estimate jumped directly to the maximum,
                 * the loop terminates naturally.
                 */
            }

            /*
             * Target is unreachable with the supported maximum.
             */
            if (upperTime < targetMilliseconds)
            {
                return SelectClosestArgon2Candidate(
                    new Argon2Candidate(
                        memoryMiB,
                        lowerIterations,
                        parallelism,
                        lowerTime),
                    new Argon2Candidate(
                        memoryMiB,
                        upperIterations,
                        parallelism,
                        upperTime),
                    targetMilliseconds);
            }

            /*
             * Target is bracketed.
             */
            return await BinarySearchArgon2IterationsAsync(
                    memoryMiB,
                    parallelism,
                    lowerIterations,
                    lowerTime,
                    upperIterations,
                    upperTime,
                    targetMilliseconds,
                    safeMaximumMemoryMiB,
                    cache,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        // -------------------------------------------------------------
        // Case 2: estimated point is above target.
        //
        // Expand downward until target is bracketed or minimum is reached.
        // -------------------------------------------------------------

        int upperIterationsAbove =
            estimatedIterations;

        double upperTimeAbove =
            estimatedTime;

        int lowerIterationsAbove =
            estimatedIterations;

        double lowerTimeAbove =
            estimatedTime;

        while (lowerIterationsAbove >
                   MinimumArgon2Iterations &&
               lowerTimeAbove >=
                   targetMilliseconds)
        {
            cancellationToken.ThrowIfCancellationRequested();

            int next =
                CalculateNextLowerIterations(
                    lowerIterationsAbove);

            if (next >= lowerIterationsAbove)
            {
                next =
                    Math.Max(
                        MinimumArgon2Iterations,
                        lowerIterationsAbove - 1);
            }

            double nextTime =
                await BenchmarkArgon2CachedAsync(
                    cache,
                    memoryMiB,
                    next,
                    parallelism,
                    safeMaximumMemoryMiB,
                    cancellationToken)
                .ConfigureAwait(false);

            cancellationToken.ThrowIfCancellationRequested();

            if (!IsValidMeasurement(nextTime))
            {
                throw new InvalidOperationException(
                    "Argon2 refinement produced an invalid measurement.");
            }

            upperIterationsAbove =
                lowerIterationsAbove;

            upperTimeAbove =
                lowerTimeAbove;

            lowerIterationsAbove =
                next;

            lowerTimeAbove =
                nextTime;
        }

        /*
         * Target is unreachable below the minimum.
         */
        if (lowerTimeAbove >= targetMilliseconds)
        {
            return SelectClosestArgon2Candidate(
                new Argon2Candidate(
                    memoryMiB,
                    lowerIterationsAbove,
                    parallelism,
                    lowerTimeAbove),
                new Argon2Candidate(
                    memoryMiB,
                    upperIterationsAbove,
                    parallelism,
                    upperTimeAbove),
                targetMilliseconds);
        }

        /*
         * Target is bracketed.
         */
        return await BinarySearchArgon2IterationsAsync(
                memoryMiB,
                parallelism,
                lowerIterationsAbove,
                lowerTimeAbove,
                upperIterationsAbove,
                upperTimeAbove,
                targetMilliseconds,
                safeMaximumMemoryMiB,
                cache,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<Argon2Candidate>
        BinarySearchArgon2IterationsAsync(
            int memoryMiB,
            int parallelism,
            int lowerIterations,
            double lowerTime,
            int upperIterations,
            double upperTime,
            double targetMilliseconds,
            int safeMaximumMemoryMiB,
            Dictionary<Argon2BenchmarkKey, double> cache,
            CancellationToken cancellationToken)
    {
        while (upperIterations -
               lowerIterations >
               1)
        {
            cancellationToken.ThrowIfCancellationRequested();

            int midpoint =
                lowerIterations +
                ((upperIterations -
                  lowerIterations) / 2);

            double midpointTime =
                await BenchmarkArgon2CachedAsync(
                    cache,
                    memoryMiB,
                    midpoint,
                    parallelism,
                    safeMaximumMemoryMiB,
                    cancellationToken)
                .ConfigureAwait(false);

            cancellationToken.ThrowIfCancellationRequested();

            if (!IsValidMeasurement(midpointTime))
            {
                throw new InvalidOperationException(
                    "Argon2 binary search produced an invalid measurement.");
            }

            if (midpointTime <
                targetMilliseconds)
            {
                lowerIterations =
                    midpoint;

                lowerTime =
                    midpointTime;
            }
            else
            {
                upperIterations =
                    midpoint;

                upperTime =
                    midpointTime;
            }
        }

        return SelectClosestArgon2Candidate(
            new Argon2Candidate(
                memoryMiB,
                lowerIterations,
                parallelism,
                lowerTime),
            new Argon2Candidate(
                memoryMiB,
                upperIterations,
                parallelism,
                upperTime),
            targetMilliseconds);
    }

    // =====================================================================
    // PBKDF2 refinement
    // =====================================================================

    private async Task<Pbkdf2OptimizationResult> RefinePbkdf2Async(
        Dictionary<int, double> cache,
        int lowerIterations,
        double lowerTime,
        int upperIterations,
        double upperTime,
        double targetMilliseconds,
        CancellationToken cancellationToken)
    {
        while (upperIterations -
               lowerIterations >
               1)
        {
            cancellationToken.ThrowIfCancellationRequested();

            int midpoint =
                lowerIterations +
                (int)(
                    ((long)upperIterations -
                     lowerIterations) / 2);

            double midpointTime =
                await BenchmarkPbkdf2CachedAsync(
                    cache,
                    midpoint,
                    cancellationToken)
                .ConfigureAwait(false);

            cancellationToken.ThrowIfCancellationRequested();

            if (midpointTime <
                targetMilliseconds)
            {
                lowerIterations =
                    midpoint;

                lowerTime =
                    midpointTime;
            }
            else
            {
                upperIterations =
                    midpoint;

                upperTime =
                    midpointTime;
            }
        }

        bool useLower =
            Math.Abs(
                lowerTime -
                targetMilliseconds)
            <=
            Math.Abs(
                upperTime -
                targetMilliseconds);

        return new Pbkdf2OptimizationResult(
            useLower
                ? lowerIterations
                : upperIterations,
            useLower
                ? lowerTime
                : upperTime,
            targetMilliseconds);
    }

    // =====================================================================
    // PBKDF2 benchmark
    // =====================================================================

    private async Task<double> BenchmarkPbkdf2CachedAsync(
        Dictionary<int, double> cache,
        int iterations,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (iterations <
                MinimumPbkdf2Iterations ||
            iterations >
                MaximumPbkdf2Iterations)
        {
            throw new ArgumentOutOfRangeException(
                nameof(iterations));
        }

        if (cache.TryGetValue(
                iterations,
                out double cached))
        {
            return cached;
        }

        double result =
            await BenchmarkPbkdf2Async(
                iterations,
                cancellationToken)
            .ConfigureAwait(false);

        cache[iterations] =
            result;

        return result;
    }

    private async Task<double> BenchmarkPbkdf2Async(
        int iterations,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return await Task.Run(
            () =>
            {
                cancellationToken.ThrowIfCancellationRequested();

                using var pbkdf2 =
                    new Rfc2898DeriveBytes(
                        _password,
                        _salt,
                        iterations,
                        HashAlgorithmName.SHA256);

                Stopwatch stopwatch =
                    Stopwatch.StartNew();

                byte[] output =
                    pbkdf2.GetBytes(
                        HashOutputBytes);

                stopwatch.Stop();

                CryptographicOperations.ZeroMemory(
                    output);

                return stopwatch.Elapsed.TotalMilliseconds;
            },
            CancellationToken.None)
            .ConfigureAwait(false);
    }

    // =====================================================================
    // Argon2 benchmark
    // =====================================================================

    private async Task<double> BenchmarkArgon2CachedAsync(
        Dictionary<Argon2BenchmarkKey, double> cache,
        int memoryMiB,
        int iterations,
        int parallelism,
        int safeMaximumMemoryMiB,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (memoryMiB <
                MinimumArgon2MemoryMiB ||
            memoryMiB >
                safeMaximumMemoryMiB)
        {
            throw new ArgumentOutOfRangeException(
                nameof(memoryMiB));
        }

        if (iterations <
                MinimumArgon2Iterations ||
            iterations >
                MaximumArgon2Iterations)
        {
            throw new ArgumentOutOfRangeException(
                nameof(iterations));
        }

        if (parallelism <
                MinimumArgon2Parallelism ||
            parallelism >
                MaximumArgon2Parallelism)
        {
            throw new ArgumentOutOfRangeException(
                nameof(parallelism));
        }

        var key =
            new Argon2BenchmarkKey(
                memoryMiB,
                iterations,
                parallelism);

        if (cache.TryGetValue(
                key,
                out double cached))
        {
            return cached;
        }

        double result =
            await BenchmarkArgon2Async(
                memoryMiB,
                iterations,
                parallelism,
                cancellationToken)
            .ConfigureAwait(false);

        cache[key] =
            result;

        return result;
    }

    private async Task<double> BenchmarkArgon2Async(
        int memoryMiB,
        int iterations,
        int parallelism,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        /*
         * Aegis uses MiB internally.
         *
         * Konscious.Security.Cryptography.Argon2 uses 1 KiB blocks.
         */
        int memoryKiB =
            checked(
                memoryMiB *
                1024);

        return await Task.Run(
            async () =>
            {
                cancellationToken.ThrowIfCancellationRequested();

                using var argon2 =
                    new Argon2id(_password)
                    {
                        Salt =
                            _salt,

                        DegreeOfParallelism =
                            parallelism,

                        Iterations =
                            iterations,

                        MemorySize =
                            memoryKiB
                    };

                byte[]? output =
                    null;

                try
                {
                    Stopwatch stopwatch =
                        Stopwatch.StartNew();

                    output =
                        await argon2
                            .GetBytesAsync(
                                HashOutputBytes)
                            .ConfigureAwait(false);

                    stopwatch.Stop();

                    return stopwatch.Elapsed.TotalMilliseconds;
                }
                finally
                {
                    if (output is not null)
                    {
                        CryptographicOperations.ZeroMemory(
                            output);
                    }
                }
            },
            CancellationToken.None)
            .ConfigureAwait(false);
    }

    // =====================================================================
    // Memory selection
    // =====================================================================

    private static Argon2Configuration
        SelectMemoryConfiguration(
            IReadOnlyList<Argon2Configuration> configurations,
            double targetMilliseconds)
    {
        if (configurations.Count == 0)
        {
            throw new ArgumentException(
                "No Argon2 configurations are available.",
                nameof(configurations));
        }

        Argon2Configuration? bestReachable =
            null;

        /*
         * Prefer the highest memory configuration that can theoretically
         * reach the target within the supported 1..64 iteration range.
         */
        foreach (Argon2Configuration configuration
                 in configurations)
        {
            double maximumRuntime =
                configuration.OneIterationMilliseconds *
                MaximumArgon2Iterations;

            if (!IsValidMeasurement(
                    maximumRuntime))
            {
                continue;
            }

            if (maximumRuntime <
                targetMilliseconds)
            {
                continue;
            }

            if (!bestReachable.HasValue ||
                configuration.MemoryMiB >
                bestReachable.Value.MemoryMiB)
            {
                bestReachable =
                    configuration;
            }
        }

        if (bestReachable.HasValue)
        {
            return bestReachable.Value;
        }

        /*
         * Nothing can reach the target.
         *
         * Choose the configuration capable of producing the longest
         * runtime.
         */
        Argon2Configuration strongest =
            configurations[0];

        double strongestRuntime =
            strongest.OneIterationMilliseconds *
            MaximumArgon2Iterations;

        for (int i = 1;
             i < configurations.Count;
             i++)
        {
            Argon2Configuration configuration =
                configurations[i];

            double maximumRuntime =
                configuration.OneIterationMilliseconds *
                MaximumArgon2Iterations;

            if (maximumRuntime >
                strongestRuntime)
            {
                strongest =
                    configuration;

                strongestRuntime =
                    maximumRuntime;
            }
        }

        return strongest;
    }

    private static int[] BuildMemoryLevels(
        int currentMemoryMiB,
        int safeMaximumMemoryMiB)
    {
        var values =
            new SortedSet<int>
            {
                MinimumArgon2MemoryMiB,
                currentMemoryMiB
            };

        foreach (int value in MemoryCandidates)
        {
            if (value >= MinimumArgon2MemoryMiB &&
                value <= safeMaximumMemoryMiB)
            {
                values.Add(value);
            }
        }

        if (safeMaximumMemoryMiB >
            currentMemoryMiB)
        {
            values.Add(
                safeMaximumMemoryMiB);
        }

        return values.ToArray();
    }

    // =====================================================================
    // Memory safety
    // =====================================================================

    private static int CalculateSafeMaximumMemoryMiB()
    {
        long totalBytes =
            GetTotalPhysicalMemoryBytes();

        if (totalBytes <= 0)
        {
            return RoundMemory(
                Math.Min(
                    AbsoluteMaximumMemoryMiB,
                    MaximumArgon2MemoryMiB));
        }

        long totalMiB =
            totalBytes /
            (1024L * 1024L);

        long fractionLimit =
            (long)Math.Floor(
                totalMiB *
                MaximumPhysicalMemoryFraction);

        long reservedLimit =
            totalMiB -
            ReservedMemoryMiB;

        long safe =
            Math.Min(
                fractionLimit,
                reservedLimit);

        safe =
            Math.Min(
                safe,
                AbsoluteMaximumMemoryMiB);

        safe =
            Math.Min(
                safe,
                MaximumArgon2MemoryMiB);

        if (safe <
            MinimumArgon2MemoryMiB)
        {
            throw new InvalidOperationException(
                "The calculated safe Argon2 memory limit is below " +
                "the configured minimum.");
        }

        return RoundMemory(
            checked((int)safe));
    }

    private static long GetTotalPhysicalMemoryBytes()
    {
        var status =
            new MEMORYSTATUSEX
            {
                dwLength =
                    (uint)Marshal.SizeOf<MEMORYSTATUSEX>()
            };

        if (!GlobalMemoryStatusEx(
                ref status))
        {
            return 0;
        }

        return checked(
            (long)status.ullTotalPhys);
    }

    private static int RoundMemory(
        int memoryMiB)
    {
        if (memoryMiB <=
            MinimumArgon2MemoryMiB)
        {
            return MinimumArgon2MemoryMiB;
        }

        int rounded =
            checked(
                (memoryMiB / 128) *
                128);

        return Math.Clamp(
            rounded,
            MinimumArgon2MemoryMiB,
            Math.Min(
                AbsoluteMaximumMemoryMiB,
                MaximumArgon2MemoryMiB));
    }

    // =====================================================================
    // Iteration estimation
    // =====================================================================

    private static int EstimateIterations(
        int measuredIterations,
        double measuredMilliseconds,
        double targetMilliseconds,
        int minimumIterations,
        int maximumIterations)
    {
        if (measuredIterations <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(measuredIterations));
        }

        if (!IsValidMeasurement(
                measuredMilliseconds))
        {
            return measuredIterations;
        }

        ValidateTarget(
            targetMilliseconds);

        double estimate =
            measuredIterations *
            (
                targetMilliseconds /
                measuredMilliseconds
            );

        if (double.IsNaN(estimate) ||
            double.IsInfinity(estimate))
        {
            return maximumIterations;
        }

        return Math.Clamp(
            checked((int)Math.Ceiling(estimate)),
            minimumIterations,
            maximumIterations);
    }

    private static int ClampIterations(
        double estimate)
    {
        if (double.IsNaN(estimate) ||
            double.IsInfinity(estimate))
        {
            return MaximumArgon2Iterations;
        }

        return Math.Clamp(
            checked(
                (int)Math.Ceiling(
                    estimate)),
            MinimumArgon2Iterations,
            MaximumArgon2Iterations);
    }

    // =====================================================================
    // Argon2 iteration search helpers
    // =====================================================================

    private static int CalculateNextHigherIterations(
        int currentIterations,
        double currentMilliseconds,
        double targetMilliseconds)
    {
        if (currentIterations >=
            MaximumArgon2Iterations)
        {
            return MaximumArgon2Iterations;
        }

        if (!IsValidMeasurement(
                currentMilliseconds))
        {
            return Math.Min(
                MaximumArgon2Iterations,
                currentIterations + 1);
        }

        double estimate =
            currentIterations *
            (
                targetMilliseconds /
                currentMilliseconds
            );

        if (double.IsNaN(estimate) ||
            double.IsInfinity(estimate))
        {
            return MaximumArgon2Iterations;
        }

        int next =
            checked(
                (int)Math.Ceiling(
                    estimate));

        /*
         * Always make progress.
         */
        next =
            Math.Max(
                currentIterations + 1,
                next);

        return Math.Min(
            next,
            MaximumArgon2Iterations);
    }

    private static int CalculateNextLowerIterations(
        int currentIterations)
    {
        if (currentIterations <=
            MinimumArgon2Iterations)
        {
            return MinimumArgon2Iterations;
        }

        int next =
            currentIterations / 2;

        if (next >= currentIterations)
        {
            next =
                currentIterations - 1;
        }

        return Math.Max(
            MinimumArgon2Iterations,
            next);
    }

    // =====================================================================
    // Candidate selection
    // =====================================================================

    private static Argon2Candidate
        SelectArgon2Candidate(
            Argon2Candidate first,
            Argon2Candidate second,
            double targetMilliseconds)
    {
        bool firstReaches =
            first.MeasuredMilliseconds >=
            targetMilliseconds;

        bool secondReaches =
            second.MeasuredMilliseconds >=
            targetMilliseconds;

        /*
         * Prefer reaching the requested target.
         */
        if (firstReaches !=
            secondReaches)
        {
            return firstReaches
                ? first
                : second;
        }

        double firstDistance =
            Math.Abs(
                first.MeasuredMilliseconds -
                targetMilliseconds);

        double secondDistance =
            Math.Abs(
                second.MeasuredMilliseconds -
                targetMilliseconds);

        if (firstDistance !=
            secondDistance)
        {
            return firstDistance <=
                   secondDistance
                ? first
                : second;
        }

        /*
         * Equal runtime distance:
         * prefer more memory.
         */
        if (first.MemoryMiB !=
            second.MemoryMiB)
        {
            return first.MemoryMiB >
                   second.MemoryMiB
                ? first
                : second;
        }

        /*
         * Equal memory:
         * prefer greater parallelism.
         */
        if (first.Parallelism !=
            second.Parallelism)
        {
            return first.Parallelism >
                   second.Parallelism
                ? first
                : second;
        }

        return first;
    }

    private static Argon2Candidate
        SelectClosestArgon2Candidate(
            Argon2Candidate lower,
            Argon2Candidate upper,
            double targetMilliseconds)
    {
        double lowerDistance =
            Math.Abs(
                lower.MeasuredMilliseconds -
                targetMilliseconds);

        double upperDistance =
            Math.Abs(
                upper.MeasuredMilliseconds -
                targetMilliseconds);

        if (lowerDistance <
            upperDistance)
        {
            return lower;
        }

        if (upperDistance <
            lowerDistance)
        {
            return upper;
        }

        /*
         * Equal distance:
         * prefer greater memory.
         */
        if (upper.MemoryMiB !=
            lower.MemoryMiB)
        {
            return upper.MemoryMiB >
                   lower.MemoryMiB
                ? upper
                : lower;
        }

        /*
         * Equal memory:
         * prefer greater parallelism.
         */
        if (upper.Parallelism !=
            lower.Parallelism)
        {
            return upper.Parallelism >
                   lower.Parallelism
                ? upper
                : lower;
        }

        return upper;
    }

    private static int FindConfigurationIndex(
        IReadOnlyList<Argon2Configuration> configurations,
        Argon2Configuration selected)
    {
        for (int i = 0;
             i < configurations.Count;
             i++)
        {
            if (configurations[i].MemoryMiB ==
                    selected.MemoryMiB &&
                configurations[i].Parallelism ==
                    selected.Parallelism)
            {
                return i;
            }
        }

        return 0;
    }

    // =====================================================================
    // Validation / utility
    // =====================================================================

    private static bool IsValidMeasurement(
        double milliseconds)
    {
        return milliseconds > 0 &&
               !double.IsNaN(milliseconds) &&
               !double.IsInfinity(milliseconds);
    }

    private static void TryForceCollection()
    {
        try
        {
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
        catch
        {
            /*
             * Cleanup must never replace the original benchmark error.
             *
             * In particular, an OOM candidate must remain an OOM candidate
             * rather than being converted into a GC-related exception.
             */
        }
    }

    private static void ValidateTarget(
        double targetMilliseconds)
    {
        if (double.IsNaN(targetMilliseconds) ||
            double.IsInfinity(targetMilliseconds) ||
            targetMilliseconds <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(targetMilliseconds),
                "Target milliseconds must be greater than zero.");
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(
            _disposed,
            this);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(
            _password);

        CryptographicOperations.ZeroMemory(
            _salt);

        _disposed =
            true;
    }

    // =====================================================================
    // Native memory information
    // =====================================================================

    [StructLayout(LayoutKind.Sequential)]
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
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(
        ref MEMORYSTATUSEX lpBuffer);

    // =====================================================================
    // Internal records
    // =====================================================================

    private readonly record struct Argon2BenchmarkKey(
        int MemoryMiB,
        int Iterations,
        int Parallelism);

    private readonly record struct Argon2Configuration(
        int MemoryMiB,
        int Parallelism,
        double OneIterationMilliseconds,
        double EstimatedIterations)
    {
        public double TargetMilliseconds =>
            EstimatedIterations *
            OneIterationMilliseconds;
    }

    private readonly record struct Argon2Candidate(
        int MemoryMiB,
        int Iterations,
        int Parallelism,
        double MeasuredMilliseconds);
}
