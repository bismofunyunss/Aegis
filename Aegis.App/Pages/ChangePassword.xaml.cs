using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Windows;

namespace Aegis.App.Pages
{
    public partial class ChangePassword : Window
    {
        public ChangePassword()
        {
            InitializeComponent();
        }

        private void PasswordChanged(object sender, RoutedEventArgs e)
        {
            SecureString pwd = NewPasswordBox.SecurePassword;
            SecureString confirm = ConfirmPasswordBox.SecurePassword;

            var (isValid, entropy) =
                PasswordUtilities.CheckPasswordAndComputeEntropy(pwd, confirm);

            EntropyText.Text = $"Entropy: {(int)entropy} bits";
            EntropyProgress.Value = Math.Min(entropy, EntropyProgress.Maximum);

            ChangeButton.IsEnabled = isValid && entropy >= 80;
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void Change_Click(object sender, RoutedEventArgs e)
        {
            // You already have this flow planned:
            // 1. Unseal master key
            // 2. Re-derive password KEK
            // 3. Rewrap master key
            // 4. Zero all intermediates
            // 5. Persist updated KeyBlob

            DialogResult = true;
            Close();
        }
    }
}

