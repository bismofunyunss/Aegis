using System.Diagnostics;
using System.Security;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using Aegis.App;
using Aegis.App.Crypto;
using Aegis.App.Ipc;
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

    private const int MinimumArgon2MemoryMiB =
        256;

    private const int MinimumArgon2Parallelism =
        1;

    private readonly KdfSettingsOptimizer _kdfOptimizer =
        new();

    private AegisSettings? _settings;

    private CancellationTokenSource? _optimizationCancellation;

    private bool _isLoading;

    private bool _optimizationRunning;


    public SettingsPage()
    {
        InitializeComponent();

        Loaded +=
            SettingsPage_Loaded;
    }


    // =========================================================
    // LOAD SETTINGS
    // =========================================================

    private void SettingsPage_Loaded(
        object sender,
        RoutedEventArgs e)
    {
        try
        {
            // -------------------------------------------------
            // Settings are runtime-only on the client.
            //
            // Persistent account cryptographic settings belong
            // to the server-side KeyBlob / keystore.json.
            //
            // CurrentAegisSettings contains the current client
            // runtime snapshot.
            // -------------------------------------------------

            _settings =
                CurrentAegisSettings.Snapshot();

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

            _settings = null;

            MessageBox.Show(
                "The Aegis settings could not be loaded.",
                "Settings Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }


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
                    MinimumArgon2MemoryMiB,
                    _settings.Argon2MemoryMiB);

            int argon2Parallelism =
                Math.Max(
                    MinimumArgon2Parallelism,
                    _settings.Argon2Parallelism);

            int targetMilliseconds =
                _settings.KdfTargetMilliseconds;

            if (targetMilliseconds <= 0)
            {
                targetMilliseconds =
                    DefaultKdfTargetMilliseconds;

                _settings.KdfTargetMilliseconds =
                    targetMilliseconds;
            }

            // -------------------------------------------------
            // Normalize runtime settings.
            // -------------------------------------------------

            bool settingsChanged =
                pbkdf2Iterations !=
                    _settings.Pbkdf2Iterations ||
                argon2Iterations !=
                    _settings.Argon2Iterations ||
                argon2Memory !=
                    _settings.Argon2MemoryMiB ||
                argon2Parallelism !=
                    _settings.Argon2Parallelism ||
                targetMilliseconds !=
                    _settings.KdfTargetMilliseconds;

            if (settingsChanged)
            {
                _settings.Pbkdf2Iterations =
                    pbkdf2Iterations;

                _settings.Argon2Iterations =
                    argon2Iterations;

                _settings.Argon2MemoryMiB =
                    argon2Memory;

                _settings.Argon2Parallelism =
                    argon2Parallelism;

                _settings.KdfTargetMilliseconds =
                    targetMilliseconds;

                CurrentAegisSettings.Apply(
                    _settings);
            }

            // -------------------------------------------------
            // Update UI.
            // -------------------------------------------------

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

        if (_settings == null)
        {
            throw new InvalidOperationException(
                "Aegis settings are not loaded.");
        }

        // -----------------------------------------------------
        // There is intentionally no local settings file.
        //
        // CurrentAegisSettings is the client-side runtime
        // snapshot.
        //
        // During account registration, VaultClientService sends
        // the KDF values to the server.
        //
        // The server stores the account's cryptographic
        // parameters inside KeyBlob, which is persisted in
        // keystore.json.
        // -----------------------------------------------------

        CurrentAegisSettings.Apply(
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

        _settings.Pbkdf2Iterations =
            Math.Max(
                MinimumPbkdf2Iterations,
                Pbkdf2IterationsUpDown.Value.Value);

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

        _settings.Argon2Iterations =
            Math.Max(
                MinimumArgon2Iterations,
                Argon2IterationsUpDown.Value.Value);

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

        _settings.Argon2MemoryMiB =
            Math.Max(
                MinimumArgon2MemoryMiB,
                Argon2MemoryUpDown.Value.Value);

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

        _settings.Argon2Parallelism =
            Math.Max(
                MinimumArgon2Parallelism,
                Argon2ParallelismUpDown.Value.Value);

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

        _settings.Fips =
            UseFipsModeCheckBox.IsChecked == true;

        Save();

        UpdateFipsUi();
    }


    private void UpdateFipsUi()
    {
        if (_settings == null)
            return;

        bool fips =
            _settings.Fips;

        // -----------------------------------------------------
        // Argon2 is not used for FIPS-mode accounts.
        //
        // The values remain visible so the user does not lose
        // their non-FIPS configuration, but the Argon2
        // optimization controls are disabled while FIPS mode
        // is active.
        // -----------------------------------------------------

        Argon2IterationsUpDown.IsEnabled =
            !fips;

        Argon2MemoryUpDown.IsEnabled =
            !fips;

        Argon2ParallelismUpDown.IsEnabled =
            !fips;

        OptimizeArgon2Button.IsEnabled =
            !fips &&
            !_optimizationRunning;

        // PBKDF2 is the active KDF in FIPS mode.

        OptimizePbkdf2Button.IsEnabled =
            !_optimizationRunning;

        OptimizeAllKdfButton.IsEnabled =
            !_optimizationRunning;
    }


    // =========================================================
    // KDF TARGET
    // =========================================================

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

        _settings.KdfTargetMilliseconds =
            KdfTargetMillisecondsUpDown.Value.Value;

        Save();
    }


    private double GetKdfTargetMilliseconds()
    {
        if (KdfTargetMillisecondsUpDown.Value == null)
        {
            throw new InvalidOperationException(
                "KDF target time is not configured.");
        }

        double targetMilliseconds =
            KdfTargetMillisecondsUpDown.Value.Value;

        if (targetMilliseconds <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(targetMilliseconds),
                "KDF target time must be greater than zero.");
        }

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
        if (_optimizationRunning ||
            _settings == null ||
            _settings.Fips)
        {
            return;
        }

        CancelOptimization();

        _optimizationCancellation =
            new CancellationTokenSource();

        CancellationToken cancellationToken =
            _optimizationCancellation.Token;

        _optimizationRunning =
            true;

        SetOptimizationButtonsEnabled(
            false);

        try
        {
            double targetMilliseconds =
                GetKdfTargetMilliseconds();

            Argon2OptimizationStatusText.Text =
                $"Benchmarking Argon2id for a target of " +
                $"{targetMilliseconds:N0} ms...";

            Argon2OptimizationResult result =
                await _kdfOptimizer.OptimizeArgon2Async(
                    targetMilliseconds,
                    _settings.Argon2Iterations,
                    _settings.Argon2MemoryMiB,
                    _settings.Argon2Parallelism,
                    cancellationToken);

            cancellationToken.ThrowIfCancellationRequested();

            if (_settings == null)
                return;

            _isLoading = true;

            try
            {
                _settings.Argon2Iterations =
                    Math.Max(
                        MinimumArgon2Iterations,
                        result.Iterations);

                _settings.Argon2MemoryMiB =
                    Math.Max(
                        MinimumArgon2MemoryMiB,
                        result.MemoryMiB);

                _settings.Argon2Parallelism =
                    Math.Max(
                        MinimumArgon2Parallelism,
                        result.Parallelism);

                Argon2IterationsUpDown.Value =
                    _settings.Argon2Iterations;

                Argon2MemoryUpDown.Value =
                    _settings.Argon2MemoryMiB;

                Argon2ParallelismUpDown.Value =
                    _settings.Argon2Parallelism;
            }
            finally
            {
                _isLoading = false;
            }

            Save();

            Argon2OptimizationStatusText.Text =
                $"Optimized: " +
                $"{_settings.Argon2MemoryMiB:N0} MiB, " +
                $"{_settings.Argon2Iterations:N0} iterations, " +
                $"{_settings.Argon2Parallelism} lanes, " +
                $"{result.MeasuredMilliseconds:N0} ms.";

            MessageBox.Show($"Optimized: " +
                $"{_settings.Argon2MemoryMiB:N0} MiB, " +
                $"{_settings.Argon2Iterations:N0} iterations, " +
                $"{_settings.Argon2Parallelism} lanes, " +
                $"{result.MeasuredMilliseconds:N0} ms.", "Settings optimized.", MessageBoxButton.OK, MessageBoxImage.Information,
                MessageBoxResult.OK);
        }
        catch (OperationCanceledException)
        {
            Argon2OptimizationStatusText.Text =
                "Argon2 optimization cancelled.";
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

            _optimizationCancellation?.Dispose();
            _optimizationCancellation = null;

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
        if (_optimizationRunning ||
            _settings == null)
        {
            return;
        }

        CancelOptimization();

        _optimizationCancellation =
            new CancellationTokenSource();

        CancellationToken cancellationToken =
            _optimizationCancellation.Token;

        _optimizationRunning =
            true;

        SetOptimizationButtonsEnabled(
            false);

        try
        {
            double targetMilliseconds =
                GetKdfTargetMilliseconds();

            Pbkdf2OptimizationStatusText.Text =
                $"Benchmarking PBKDF2-SHA256 for a target of " +
                $"{targetMilliseconds:N0} ms...";

            Pbkdf2OptimizationResult result =
                await _kdfOptimizer.OptimizePbkdf2Async(
                    targetMilliseconds,
                    MinimumPbkdf2Iterations,
                    cancellationToken);

            cancellationToken.ThrowIfCancellationRequested();

            if (_settings == null)
                return;

            _isLoading = true;

            try
            {
                _settings.Pbkdf2Iterations =
                    Math.Max(
                        MinimumPbkdf2Iterations,
                        result.Iterations);

                Pbkdf2IterationsUpDown.Value =
                    _settings.Pbkdf2Iterations;
            }
            finally
            {
                _isLoading = false;
            }

            Save();

            Pbkdf2OptimizationStatusText.Text =
                $"Optimized: " +
                $"{_settings.Pbkdf2Iterations:N0} iterations, " +
                $"{result.MeasuredMilliseconds:N0} ms.";
        }
        catch (OperationCanceledException)
        {
            Pbkdf2OptimizationStatusText.Text =
                "PBKDF2 optimization cancelled.";
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

            _optimizationCancellation?.Dispose();
            _optimizationCancellation = null;

            SetOptimizationButtonsEnabled(
                ClientSessionManager.IsAuthenticated &&
                _settings != null);
        }
    }


    // =========================================================
    // OPTIMIZE ALL
    // =========================================================

    private async void OptimizeAllKdfButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (_optimizationRunning ||
            _isLoading ||
            _settings == null)
        {
            return;
        }

        CancelOptimization();

        _optimizationCancellation =
            new CancellationTokenSource();

        CancellationToken cancellationToken =
            _optimizationCancellation.Token;

        _optimizationRunning =
            true;

        SetOptimizationButtonsEnabled(
            false);

        try
        {
            double targetMilliseconds =
                GetKdfTargetMilliseconds();

            // =================================================
            // FIPS MODE
            //
            // PBKDF2 is the account KDF.
            //
            // Argon2 is deliberately skipped.
            // =================================================

            if (_settings.Fips)
            {
                Pbkdf2OptimizationStatusText.Text =
                    $"FIPS mode: benchmarking PBKDF2-SHA256 " +
                    $"for a target of " +
                    $"{targetMilliseconds:N0} ms...";

                Argon2OptimizationStatusText.Text =
                    "FIPS mode: Argon2id is not used.";

                Pbkdf2OptimizationResult pbkdf2Result =
                    await _kdfOptimizer.OptimizePbkdf2Async(
                        targetMilliseconds,
                        MinimumPbkdf2Iterations,
                        cancellationToken);

                cancellationToken.ThrowIfCancellationRequested();

                if (_settings == null)
                    return;

                _isLoading = true;

                try
                {
                    _settings.Pbkdf2Iterations =
                        Math.Max(
                            MinimumPbkdf2Iterations,
                            pbkdf2Result.Iterations);

                    Pbkdf2IterationsUpDown.Value =
                        _settings.Pbkdf2Iterations;
                }
                finally
                {
                    _isLoading = false;
                }

                Save();

                Pbkdf2OptimizationStatusText.Text =
                    $"Optimized: " +
                    $"{_settings.Pbkdf2Iterations:N0} iterations, " +
                    $"{pbkdf2Result.MeasuredMilliseconds:N0} ms.";

                MessageBox.Show(
                    $"FIPS KDF optimization complete.\n\n" +
                    $"Target: " +
                    $"{targetMilliseconds:N0} ms\n\n" +
                    $"PBKDF2-SHA256:\n" +
                    $"{_settings.Pbkdf2Iterations:N0} iterations\n" +
                    $"{pbkdf2Result.MeasuredMilliseconds:N0} ms",
                    "KDF Optimization Complete",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);

                return;
            }

            // =================================================
            // NON-FIPS MODE
            //
            // Optimize both KDF configurations.
            // =================================================

            Pbkdf2OptimizationStatusText.Text =
                $"Benchmarking PBKDF2-SHA256 " +
                $"({targetMilliseconds:N0} ms target)...";

            Argon2OptimizationStatusText.Text =
                "Waiting for PBKDF2-SHA256 optimization...";

            Pbkdf2OptimizationResult pbkdf2 =
                await _kdfOptimizer.OptimizePbkdf2Async(
                    targetMilliseconds,
                    MinimumPbkdf2Iterations,
                    cancellationToken);

            cancellationToken.ThrowIfCancellationRequested();

            if (_settings == null)
                return;

            _isLoading = true;

            try
            {
                _settings.Pbkdf2Iterations =
                    Math.Max(
                        MinimumPbkdf2Iterations,
                        pbkdf2.Iterations);

                Pbkdf2IterationsUpDown.Value =
                    _settings.Pbkdf2Iterations;
            }
            finally
            {
                _isLoading = false;
            }

            Pbkdf2OptimizationStatusText.Text =
                $"Optimized: " +
                $"{_settings.Pbkdf2Iterations:N0} iterations, " +
                $"{pbkdf2.MeasuredMilliseconds:N0} ms.";

            // =================================================
            // ARGON2ID
            // =================================================

            Argon2OptimizationStatusText.Text =
                $"Benchmarking Argon2id " +
                $"({targetMilliseconds:N0} ms target)...";

            Argon2OptimizationResult argon2 =
                await _kdfOptimizer.OptimizeArgon2Async(
                    targetMilliseconds,
                    _settings.Argon2Iterations,
                    _settings.Argon2MemoryMiB,
                    _settings.Argon2Parallelism,
                    cancellationToken);

            cancellationToken.ThrowIfCancellationRequested();

            if (_settings == null)
                return;

            _isLoading = true;

            try
            {
                _settings.Argon2Iterations =
                    Math.Max(
                        MinimumArgon2Iterations,
                        argon2.Iterations);

                _settings.Argon2MemoryMiB =
                    Math.Max(
                        MinimumArgon2MemoryMiB,
                        argon2.MemoryMiB);

                _settings.Argon2Parallelism =
                    Math.Max(
                        MinimumArgon2Parallelism,
                        argon2.Parallelism);

                Argon2IterationsUpDown.Value =
                    _settings.Argon2Iterations;

                Argon2MemoryUpDown.Value =
                    _settings.Argon2MemoryMiB;

                Argon2ParallelismUpDown.Value =
                    _settings.Argon2Parallelism;
            }
            finally
            {
                _isLoading = false;
            }

            Save();

            Argon2OptimizationStatusText.Text =
                $"Optimized: " +
                $"{_settings.Argon2MemoryMiB:N0} MiB, " +
                $"{_settings.Argon2Iterations:N0} iterations, " +
                $"{_settings.Argon2Parallelism} lanes, " +
                $"{argon2.MeasuredMilliseconds:N0} ms.";

            MessageBox.Show(
                $"KDF optimization complete.\n\n" +
                $"Target: " +
                $"{targetMilliseconds:N0} ms\n\n" +
                $"PBKDF2-SHA256:\n" +
                $"{_settings.Pbkdf2Iterations:N0} iterations\n" +
                $"{pbkdf2.MeasuredMilliseconds:N0} ms\n\n" +
                $"Argon2id:\n" +
                $"{_settings.Argon2MemoryMiB:N0} MiB\n" +
                $"{_settings.Argon2Iterations:N0} iterations\n" +
                $"{_settings.Argon2Parallelism} lanes\n" +
                $"{argon2.MeasuredMilliseconds:N0} ms",
                "KDF Optimization Complete",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (OperationCanceledException)
        {
            Pbkdf2OptimizationStatusText.Text =
                "Optimization cancelled.";

            Argon2OptimizationStatusText.Text =
                "Optimization cancelled.";
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

            _optimizationCancellation?.Dispose();
            _optimizationCancellation = null;

            SetOptimizationButtonsEnabled(
                ClientSessionManager.IsAuthenticated &&
                _settings != null);
        }
    }


    // =========================================================
    // CANCELLATION
    // =========================================================

    private void CancelOptimization()
    {
        _optimizationCancellation?.Cancel();

        _optimizationCancellation?.Dispose();

        _optimizationCancellation = null;
    }


    // =========================================================
    // ENABLE / DISABLE OPTIMIZATION CONTROLS
    // =========================================================

    private void SetOptimizationButtonsEnabled(
        bool enabled)
    {
        bool fips =
            _settings?.Fips == true;

        OptimizePbkdf2Button.IsEnabled =
            enabled &&
            !_optimizationRunning;

        OptimizeArgon2Button.IsEnabled =
            enabled &&
            !fips &&
            !_optimizationRunning;

        OptimizeAllKdfButton.IsEnabled =
            enabled &&
            !_optimizationRunning;

        KdfTargetMillisecondsUpDown.IsEnabled =
            enabled &&
            !_optimizationRunning;

        // -----------------------------------------------------
        // Argon2 controls are disabled when FIPS mode is active.
        // -----------------------------------------------------

        Argon2IterationsUpDown.IsEnabled =
            enabled &&
            !fips;

        Argon2MemoryUpDown.IsEnabled =
            enabled &&
            !fips;

        Argon2ParallelismUpDown.IsEnabled =
            enabled &&
            !fips;
    }


    // =========================================================
    // ENABLE / DISABLE ALL SETTINGS
    // =========================================================

    private void SetSettingsControlsEnabled(
        bool enabled)
    {
        bool fips =
            _settings?.Fips == true;

        Pbkdf2IterationsUpDown.IsEnabled =
            enabled;

        Argon2IterationsUpDown.IsEnabled =
            enabled &&
            !fips;

        Argon2MemoryUpDown.IsEnabled =
            enabled &&
            !fips;

        Argon2ParallelismUpDown.IsEnabled =
            enabled &&
            !fips;

        UseFipsModeCheckBox.IsEnabled =
            enabled;

        KdfTargetMillisecondsUpDown.IsEnabled =
            enabled &&
            !_optimizationRunning;

        OptimizePbkdf2Button.IsEnabled =
            enabled &&
            !_optimizationRunning;

        OptimizeArgon2Button.IsEnabled =
            enabled &&
            !fips &&
            !_optimizationRunning;

        OptimizeAllKdfButton.IsEnabled =
            enabled &&
            !_optimizationRunning;
    }
}