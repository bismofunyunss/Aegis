using System.Diagnostics;
using System.Security;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using Aegis.App.Argon2_Optimization;
using Aegis.App.Crypto;
using Aegis.App.Settings;

namespace Aegis.App.Pages;

public partial class SettingsPage : Page
{
    private const int DefaultKdfTargetMilliseconds =
        10_000;

    private const int MinimumPbkdf2Iterations =
        600_000;

    private const int MinimumArgon2Iterations =
        1;

    private AegisSettingsStore? _settingsStore;

    private AegisSettings? _settings;

    private bool _isLoading;
    private bool _optimizationRunning;


    public SettingsPage()
    {
        InitializeComponent();

        Loaded +=
            SettingsPage_Loaded;
    }


    private void SettingsPage_Loaded(
        object sender,
        RoutedEventArgs e)
    {
        Loaded -=
            SettingsPage_Loaded;

        if (!ClientSessionManager.IsAuthenticated)
        {
            MessageBox.Show(
                "You must be authenticated to access Settings.",
                "Settings",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);

            return;
        }

        try
        {
            string username =
                ClientSessionManager.Current.Username;

            _settingsStore =
                new AegisSettingsStore(
                    username);

            _settings =
                _settingsStore.Load();

            LoadSettings();
        }
        catch (Exception ex)
        {
            FileLogger.Log(
                ex,
                "Failed to load Aegis settings.",
                ClientSessionManager.IsAuthenticated
                    ? ClientSessionManager.Current.Username
                    : "Unknown");

            MessageBox.Show(
                "The Aegis settings could not be loaded.",
                "Settings Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }


    // =========================================================
    // LOAD SETTINGS
    // =========================================================

    private void LoadSettings()
    {
        if (_settings == null)
        {
            throw new InvalidOperationException(
                "Aegis settings have not been loaded.");
        }

        _isLoading = true;

        try
        {
            int pbkdf2Iterations =
                Math.Max(
                    MinimumPbkdf2Iterations,
                    _settings.Pbkdf2Iterations);

            int argon2Iterations =
                Math.Max(
                    MinimumArgon2Iterations,
                    _settings.Argon2Iterations);

            int argon2Memory =
                Math.Max(
                    Argon2Optimizer.MinimumConfiguredMemoryMiB,
                    _settings.Argon2MemoryMiB);

            int argon2Parallelism =
                Math.Max(
                    1,
                    _settings.Argon2Parallelism);

            int targetMilliseconds =
                _settings.KdfTargetMilliseconds;

            if (targetMilliseconds <= 0)
            {
                targetMilliseconds =
                    DefaultKdfTargetMilliseconds;

                _settings.KdfTargetMilliseconds =
                    targetMilliseconds;

                _settingsStore!.Save(
                    _settings);
            }

            Pbkdf2IterationsUpDown.Value =
                pbkdf2Iterations;

            Argon2IterationsUpDown.Value =
                argon2Iterations;

            Argon2MemoryUpDown.Value =
                argon2Memory;

            Argon2ParallelismUpDown.Value =
                argon2Parallelism;

            UseFipsModeCheckBox.IsChecked =
                _settings.Fips;

            KdfTargetMillisecondsUpDown.Value =
                targetMilliseconds;
        }
        finally
        {
            _isLoading = false;
        }
    }


    // =========================================================
    // SAVE
    // =========================================================

    private void Save()
    {
        if (_isLoading)
            return;

        if (_settingsStore == null ||
            _settings == null)
        {
            throw new InvalidOperationException(
                "Aegis settings are not loaded.");
        }

        _settingsStore.Save(
            _settings);
    }

    // =========================================================
    // PBKDF2
    // =========================================================

    private void Pbkdf2IterationsUpDown_ValueChanged(
        object sender,
        RoutedPropertyChangedEventArgs<object> e)
    {
        if (_isLoading ||
            Pbkdf2IterationsUpDown.Value == null ||
            _settings == null)
        {
            return;
        }

        _settings?.Pbkdf2Iterations =
            Pbkdf2IterationsUpDown.Value.Value;

        Save();
    }


    // =========================================================
    // ARGON2 ITERATIONS
    // =========================================================

    private void Argon2IterationsUpDown_ValueChanged(
        object sender,
        RoutedPropertyChangedEventArgs<object> e)
    {
        if (_isLoading ||
            Argon2IterationsUpDown.Value == null ||
            _settings == null)
        {
            return;
        }

        _settings?.Argon2Iterations =
            Argon2IterationsUpDown.Value.Value;

        Save();
    }


    // =========================================================
    // ARGON2 MEMORY
    // =========================================================

    private void Argon2MemoryUpDown_ValueChanged(
        object sender,
        RoutedPropertyChangedEventArgs<object> e)
    {
        if (_isLoading ||
            Argon2MemoryUpDown.Value == null ||
            _settings == null)
        {
            return;
        }

        _settings?.Argon2MemoryMiB =
            Argon2MemoryUpDown.Value.Value;

        Save();
    }


    // =========================================================
    // ARGON2 PARALLELISM
    // =========================================================

    private void Argon2ParallelismUpDown_ValueChanged(
        object sender,
        RoutedPropertyChangedEventArgs<object> e)
    {
        if (_isLoading ||
            Argon2ParallelismUpDown.Value == null ||
            _settings == null)
        {
            return;
        }

        _settings?.Argon2Parallelism =
            Argon2ParallelismUpDown.Value.Value;

        Save();
    }


    // =========================================================
    // FIPS
    // =========================================================

    private void UseFipsModeCheckBox_Changed(
        object sender,
        RoutedEventArgs e)
    {
        if (_isLoading ||
            _settings == null)
        {
            return;
        }

        _settings?.Fips =
            UseFipsModeCheckBox.IsChecked == true;

        Save();
    }

    private void KdfTargetMillisecondsUpDown_ValueChanged(
        object sender,
        RoutedPropertyChangedEventArgs<object> e)
    {
        if (_isLoading ||
            KdfTargetMillisecondsUpDown.Value == null ||
            _settings == null)
        {
            return;
        }

        _settings?.KdfTargetMilliseconds =
            KdfTargetMillisecondsUpDown.Value.Value;

        Save();
    }


    // =========================================================
    // KDF TARGET
    // =========================================================

    private double GetKdfTargetMilliseconds()
    {
        if (KdfTargetMillisecondsUpDown.Value == null)
            throw new InvalidOperationException(
                "KDF target time is not configured.");

        double targetMilliseconds =
            KdfTargetMillisecondsUpDown.Value.Value;

        if (targetMilliseconds <= 0)
            throw new ArgumentOutOfRangeException(
                nameof(targetMilliseconds),
                "KDF target time must be greater than zero.");

        return targetMilliseconds;
    }


    // =========================================================
    // CHANGE PASSWORD
    // =========================================================

    private void ChangePasswordButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (!ClientSessionManager.IsAuthenticated)
        {
            MessageBox.Show(
                "You must be authenticated to change your password.",
                "Change Password",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);

            return;
        }

        var owner =
            Window.GetWindow(this);

        var dialog =
            new ChangePassword
            {
                Owner = owner
            };

        dialog.ShowDialog();
    }


    // =========================================================
    // ARGON2 OPTIMIZATION
    // =========================================================

    private async void OptimizeArgon2Button_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (_optimizationRunning)
            return;

        double targetMilliseconds;

        try
        {
            targetMilliseconds =
                GetKdfTargetMilliseconds();

            _optimizationRunning = true;

            SetOptimizationButtonsEnabled(false);

            Argon2OptimizationStatusText.Text =
                $"Benchmarking Argon2id for a target of " +
                $"{targetMilliseconds:N0} ms.";

            var result =
                await Task.Run(() =>
                    Argon2Optimizer.Optimize(
                        targetMilliseconds));

            // -----------------------------------------------------
            // Update UI
            // -----------------------------------------------------

            Argon2IterationsUpDown.Value =
                result.Iterations;

            Argon2MemoryUpDown.Value =
                result.MemoryMiB;

            Argon2ParallelismUpDown.Value =
                result.Parallelism;


            // -----------------------------------------------------
            // Persist explicitly
            // -----------------------------------------------------

            _settings?.Argon2Iterations =
                result.Iterations;

            _settings?.Argon2MemoryMiB =
                result.MemoryMiB;

            _settings?.Argon2Parallelism =
                result.Parallelism;

            Save();


            // -----------------------------------------------------
            // Status
            // -----------------------------------------------------

            Argon2OptimizationStatusText.Text =
                $"Optimized: " +
                $"{result.MemoryMiB:N0} MiB, " +
                $"{result.Iterations} iterations, " +
                $"{result.Parallelism} lanes, " +
                $"{result.MeasuredMilliseconds:N0} ms.";
        }
        catch (Exception ex)
        {
            FileLogger.Log(
                ex,
                "Argon2id optimization failed.",
                ClientSessionManager.IsAuthenticated
                    ? ClientSessionManager.Current.Username
                    : "Unknown");

            Argon2OptimizationStatusText.Text =
                "Optimization failed.";

            MessageBox.Show(
                "Argon2id optimization could not be completed.",
                "Optimization Failed",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        finally
        {
            _optimizationRunning =
                false;

            SetOptimizationButtonsEnabled(
                true);
        }
    }


    // =========================================================
    // PBKDF2 OPTIMIZATION
    // =========================================================

    private async void OptimizePbkdf2Button_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (_optimizationRunning)
            return;

        try
        {
            var targetMilliseconds =
                GetKdfTargetMilliseconds();

            _optimizationRunning =
                true;

            SetOptimizationButtonsEnabled(
                false);

            Pbkdf2OptimizationStatusText.Text =
                $"Benchmarking PBKDF2-SHA256 for a target of " +
                $"{targetMilliseconds:N0} ms.";

            var optimizedIterations =
                await Task.Run(() =>
                    OptimizePbkdf2Iterations(
                        targetMilliseconds));


            // -----------------------------------------------------
            // Update UI
            // -----------------------------------------------------

            Pbkdf2IterationsUpDown.Value =
                optimizedIterations;


            // -----------------------------------------------------
            // Persist explicitly
            // -----------------------------------------------------

            _settings?.Pbkdf2Iterations =
                optimizedIterations;

            Save();


            // -----------------------------------------------------
            // Status
            // -----------------------------------------------------

            Pbkdf2OptimizationStatusText.Text =
                $"Optimized: " +
                $"{optimizedIterations:N0} iterations.";
        }
        catch (Exception ex)
        {
            FileLogger.Log(
                ex,
                "PBKDF2 optimization failed.",
                ClientSessionManager.IsAuthenticated
                    ? ClientSessionManager.Current.Username
                    : "Unknown");

            Pbkdf2OptimizationStatusText.Text =
                "Optimization failed.";

            MessageBox.Show(
                "PBKDF2-SHA256 optimization could not be completed.",
                "Optimization Failed",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        finally
        {
            _optimizationRunning =
                false;

            SetOptimizationButtonsEnabled(
                true);
        }
    }


    // =========================================================
    // OPTIMIZE BOTH
    // =========================================================

    private async void OptimizeAllKdfButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (_optimizationRunning ||
            _isLoading)
            return;

        try
        {
            var targetMilliseconds =
                GetKdfTargetMilliseconds();

            _optimizationRunning =
                true;

            SetOptimizationButtonsEnabled(
                false);


            // =====================================================
            // PBKDF2
            // =====================================================

            Pbkdf2OptimizationStatusText.Text =
                $"Benchmarking PBKDF2-SHA256 " +
                $"({targetMilliseconds:N0} ms target)...";

            Argon2OptimizationStatusText.Text =
                "Waiting for PBKDF2-SHA256 optimization...";


            var pbkdf2Iterations =
                await Task.Run(() =>
                    OptimizePbkdf2Iterations(
                        targetMilliseconds));


            Pbkdf2IterationsUpDown.Value =
                pbkdf2Iterations;


            _settings?.Pbkdf2Iterations =
                pbkdf2Iterations;


            Pbkdf2OptimizationStatusText.Text =
                $"Optimized: " +
                $"{pbkdf2Iterations:N0} iterations.";


            // =====================================================
            // ARGON2ID
            // =====================================================

            Argon2OptimizationStatusText.Text =
                $"Benchmarking Argon2id " +
                $"({targetMilliseconds:N0} ms target)...";


            var argonResult =
                await Task.Run(() =>
                    Argon2Optimizer.Optimize(
                        targetMilliseconds));


            Argon2IterationsUpDown.Value =
                argonResult.Iterations;

            Argon2MemoryUpDown.Value =
                argonResult.MemoryMiB;

            Argon2ParallelismUpDown.Value =
                argonResult.Parallelism;


            _settings?.Argon2Iterations =
                argonResult.Iterations;

            _settings?.Argon2MemoryMiB =
                argonResult.MemoryMiB;

            _settings?.Argon2Parallelism =
                argonResult.Parallelism;


            // =====================================================
            // SAVE ALL OPTIMIZED SETTINGS
            // =====================================================

            Save();


            // =====================================================
            // STATUS
            // =====================================================

            Argon2OptimizationStatusText.Text =
                $"Optimized: " +
                $"{argonResult.MemoryMiB:N0} MiB, " +
                $"{argonResult.Iterations} iterations, " +
                $"{argonResult.Parallelism} lanes, " +
                $"{argonResult.MeasuredMilliseconds:N0} ms.";


            // =====================================================
            // RESULT MESSAGE
            // =====================================================

            MessageBox.Show(
                $"KDF optimization complete.\n\n" +
                $"Target: " +
                $"{targetMilliseconds:N0} ms\n\n" +
                $"PBKDF2-SHA256:\n" +
                $"{pbkdf2Iterations:N0} iterations\n\n" +
                $"Argon2id:\n" +
                $"{argonResult.MemoryMiB:N0} MiB\n" +
                $"{argonResult.Iterations} iterations\n" +
                $"{argonResult.Parallelism} lanes\n" +
                $"{argonResult.MeasuredMilliseconds:N0} ms",
                "KDF Optimization Complete",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            FileLogger.Log(
                ex,
                "KDF optimization failed.",
                ClientSessionManager.IsAuthenticated
                    ? ClientSessionManager.Current.Username
                    : "Unknown");

            Pbkdf2OptimizationStatusText.Text =
                "Optimization failed.";

            Argon2OptimizationStatusText.Text =
                "Optimization failed.";

            MessageBox.Show(
                "KDF optimization could not be completed.",
                "Optimization Failed",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        finally
        {
            _optimizationRunning =
                false;

            SetOptimizationButtonsEnabled(
                true);
        }
    }


    // =========================================================
    // ENABLE / DISABLE OPTIMIZATION CONTROLS
    // =========================================================

    private void SetOptimizationButtonsEnabled(
        bool enabled)
    {
        OptimizePbkdf2Button.IsEnabled =
            enabled;

        OptimizeArgon2Button.IsEnabled =
            enabled;

        OptimizeAllKdfButton.IsEnabled =
            enabled;

        KdfTargetMillisecondsUpDown.IsEnabled =
            enabled;
    }


    // =========================================================
    // PBKDF2 OPTIMIZER
    // =========================================================

    private static int OptimizePbkdf2Iterations(
        double targetMilliseconds)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(targetMilliseconds);

        const int minimumIterations =
            600_000;

        const int maximumIterations =
            1_000_000_000;

        const int passwordLength =
            32;

        const int saltLength =
            128;

        const int outputLength =
            32;


        var password =
            RandomNumberGenerator.GetBytes(
                passwordLength);

        var salt =
            RandomNumberGenerator.GetBytes(
                saltLength);


        try
        {
            // =====================================================
            // WARM-UP
            // =====================================================

            var warmup =
                Rfc2898DeriveBytes.Pbkdf2(
                    password,
                    salt,
                    10_000,
                    HashAlgorithmName.SHA256,
                    outputLength);

            CryptographicOperations.ZeroMemory(
                warmup);


            // =====================================================
            // BASELINE
            // =====================================================

            const int baselineIterations =
                100_000;

            var baselineMilliseconds =
                BenchmarkPbkdf2(
                    baselineIterations,
                    password,
                    salt,
                    outputLength);

            if (baselineMilliseconds <= 0)
                throw new CryptographicException(
                    "PBKDF2 benchmark returned an invalid timing result.");


            Debug.WriteLine(
                $"PBKDF2 optimizer: " +
                $"Baseline = {baselineIterations:N0} iterations, " +
                $"{baselineMilliseconds:F2} ms.");


            // =====================================================
            // ESTIMATE
            // =====================================================

            var estimatedIterations =
                baselineIterations *
                (
                    targetMilliseconds /
                    baselineMilliseconds);

            var estimatedLong =
                (long)Math.Round(
                    estimatedIterations);

            var estimated =
                (int)Math.Clamp(
                    estimatedLong,
                    minimumIterations,
                    maximumIterations);


            // =====================================================
            // FIND RANGE
            // =====================================================

            var lower =
                minimumIterations;

            var upper =
                estimated;

            var upperTime =
                BenchmarkPbkdf2(
                    upper,
                    password,
                    salt,
                    outputLength);


            if (upperTime <=
                targetMilliseconds)
            {
                lower =
                    upper;

                while (upper <
                       maximumIterations)
                {
                    var nextUpper =
                        upper >
                        maximumIterations / 2
                            ? maximumIterations
                            : upper * 2;


                    var elapsed =
                        BenchmarkPbkdf2(
                            nextUpper,
                            password,
                            salt,
                            outputLength);


                    Debug.WriteLine(
                        $"PBKDF2 optimizer: " +
                        $"{nextUpper:N0} iterations = " +
                        $"{elapsed:F2} ms.");


                    if (elapsed >
                        targetMilliseconds)
                    {
                        upper =
                            nextUpper;

                        upperTime =
                            elapsed;

                        break;
                    }


                    lower =
                        nextUpper;

                    upper =
                        nextUpper;

                    upperTime =
                        elapsed;
                }


                if (lower ==
                    maximumIterations &&
                    upper ==
                    maximumIterations &&
                    upperTime <=
                    targetMilliseconds)
                    return maximumIterations;
            }


            // =====================================================
            // MINIMUM MUST FIT
            // =====================================================

            var minimumTime =
                BenchmarkPbkdf2(
                    minimumIterations,
                    password,
                    salt,
                    outputLength);


            if (minimumTime >
                targetMilliseconds)
                throw new InvalidOperationException(
                    $"The minimum PBKDF2 configuration of " +
                    $"{minimumIterations:N0} iterations requires " +
                    $"approximately {minimumTime:F0} ms, which exceeds " +
                    $"the requested target of " +
                    $"{targetMilliseconds:F0} ms.");


            // =====================================================
            // BINARY SEARCH
            // =====================================================

            var best =
                lower;


            while (lower <=
                   upper)
            {
                var middle =
                    lower +
                    (upper - lower) / 2;


                var elapsed =
                    BenchmarkPbkdf2(
                        middle,
                        password,
                        salt,
                        outputLength);


                Debug.WriteLine(
                    $"PBKDF2 optimizer: " +
                    $"{middle:N0} iterations = " +
                    $"{elapsed:F2} ms.");


                if (elapsed <=
                    targetMilliseconds)
                {
                    best =
                        middle;

                    lower =
                        middle + 1;
                }
                else
                {
                    upper =
                        middle - 1;
                }
            }


            // =====================================================
            // FINAL MEASUREMENT
            // =====================================================

            var finalElapsed =
                BenchmarkPbkdf2(
                    best,
                    password,
                    salt,
                    outputLength,
                    3);


            if (finalElapsed >
                targetMilliseconds)
            {
                var scale =
                    targetMilliseconds /
                    finalElapsed;


                var adjusted =
                    (int)Math.Floor(
                        best *
                        scale *
                        0.98);


                adjusted =
                    Math.Clamp(
                        adjusted,
                        minimumIterations,
                        best);


                best =
                    adjusted;


                finalElapsed =
                    BenchmarkPbkdf2(
                        best,
                        password,
                        salt,
                        outputLength,
                        3);


                while (finalElapsed >
                       targetMilliseconds &&
                       best >
                       minimumIterations)
                {
                    var next =
                        Math.Max(
                            minimumIterations,
                            best -
                            Math.Max(
                                1,
                                best / 100));


                    best =
                        next;


                    finalElapsed =
                        BenchmarkPbkdf2(
                            best,
                            password,
                            salt,
                            outputLength,
                            2);
                }
            }


            Debug.WriteLine(
                $"PBKDF2 optimizer: " +
                $"FINAL = {best:N0} iterations, " +
                $"{finalElapsed:F2} ms.");


            return best;
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
    // PBKDF2 BENCHMARK
    // =========================================================

    private static double BenchmarkPbkdf2(
        int iterations,
        byte[] password,
        byte[] salt,
        int outputLength,
        int samples = 1)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(iterations);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(samples);


        double totalMilliseconds =
            0;


        for (var sample = 0;
             sample < samples;
             sample++)
        {
            var stopwatch =
                Stopwatch.StartNew();


            var output =
                Rfc2898DeriveBytes.Pbkdf2(
                    password,
                    salt,
                    iterations,
                    HashAlgorithmName.SHA256,
                    outputLength);


            stopwatch.Stop();


            CryptographicOperations.ZeroMemory(
                output);


            totalMilliseconds +=
                stopwatch.Elapsed.TotalMilliseconds;
        }


        return
            totalMilliseconds /
            samples;
    }
}