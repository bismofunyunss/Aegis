using Aegis.App.Crypto;
using System.Windows;
using System.Windows.Controls;
using Aegis.App.Argon2_Optimization;

namespace Aegis.App.Pages
{
    public partial class SettingsPage : Page
    {
        private bool _isLoading;

        public SettingsPage()
        {
            InitializeComponent();
            LoadSettings();
        }

        private async void ChangePasswordButton_Click(object sender, RoutedEventArgs e)
        {
            // TODO:
            // 1. Prompt for current password
            // 2. Prompt for new password + confirmation
            // 3. Unseal master key
            // 4. Re-derive password KEK
            // 5. Rewrap master key
            // 6. Zero all intermediates
        }

        private void LoadSettings()
        {
            _isLoading = true;

            Pbkdf2IterationsUpDown.Value = Settings.Default.PBKF2;
            Argon2IterationsUpDown.Value = Settings.Default.Iterations;

            int memory = Math.Max(1024, (int)Settings.Default.Memory);

            Settings.Default.Memory = memory;
            Argon2MemoryUpDown.Value = memory;

            Argon2ParallelismUpDown.Value = Settings.Default.Parallelism;
            UseFipsModeCheckBox.IsChecked = Settings.Default.FIPS;

            _isLoading = false;
        }

        private void Save()
        {
            if (_isLoading) return;
            Settings.Default.Save();
        }

        // ===============================
        // PBKDF2
        // ===============================
        private void Pbkdf2IterationsUpDown_ValueChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
        {
            if (_isLoading || Pbkdf2IterationsUpDown.Value == null) return;
            Settings.Default.PBKF2 = Pbkdf2IterationsUpDown.Value.Value;
            Save();
        }

        // ===============================
        // Argon2id Iterations
        // ===============================
        private void Argon2IterationsUpDown_ValueChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
        {
            if (_isLoading || Argon2IterationsUpDown.Value == null) return;
            Settings.Default.Iterations = Argon2IterationsUpDown.Value.Value;
            Save();
        }

        // ===============================
        // Argon2id Memory
        // ===============================
        private void Argon2MemoryUpDown_ValueChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
        {
            if (_isLoading || Argon2MemoryUpDown.Value == null) return;
            Settings.Default.Memory = Argon2MemoryUpDown.Value.Value;
            Save();
        }

        // ===============================
        // Argon2id Parallelism
        // ===============================
        private void Argon2ParallelismUpDown_ValueChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
        {
            if (_isLoading || Argon2ParallelismUpDown.Value == null) return;
            Settings.Default.Parallelism = Argon2ParallelismUpDown.Value.Value;
            Save();
        }

        // ===============================
        // FIPS Checkbox
        // ===============================
        private void UseFipsModeCheckBox_Changed(object sender, RoutedEventArgs e)
        {
            if (_isLoading) return;
            Settings.Default.FIPS = UseFipsModeCheckBox.IsChecked == true;
            Save();
        }

        private async void OptimizeArgon2Button_Click(
            object sender,
            RoutedEventArgs e)
        {
            OptimizeArgon2Button.IsEnabled =
                false;

            Argon2OptimizationStatusText.Text =
                "Benchmarking your system...";

            try
            {
                var result =
                    await Task.Run(
                        () => Argon2Optimizer.Optimize());

                Argon2IterationsUpDown.Value =
                    result.Iterations;

                Argon2MemoryUpDown.Value =
                    result.MemoryMiB;

                Argon2ParallelismUpDown.Value =
                    result.Parallelism;

                Settings.Default.Save();

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
                OptimizeArgon2Button.IsEnabled =
                    true;
            }
        }
    }
}



