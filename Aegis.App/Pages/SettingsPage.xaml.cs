using System.Windows;
using System.Windows.Controls;
using Xceed.Wpf.Toolkit;

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

            // Load existing values from Settings.Default
            Pbkdf2IterationsUpDown.Value = Settings.Default.PBKF2;
            Argon2IterationsUpDown.Value = Settings.Default.Iterations;
            Argon2MemoryUpDown.Value = (int)Settings.Default.Memory;
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
    }
}


