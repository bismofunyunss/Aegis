using Aegis.App.Core;
using Aegis.App.Crypto;
using Aegis.App.TPM;
using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using Aegis.App.Password;

namespace Aegis.App.Pages
{
    public partial class ChangePassword : Window
    {
        private string _username;
        private byte[] _password;
        public ChangePassword(string username)
        {
            InitializeComponent();
            _username = username;
        }

        private void PasswordChanged(object sender, RoutedEventArgs e)
        {
            SecureString pwd = NewPasswordBox.SecurePassword;
            SecureString confirm = ConfirmPasswordBox.SecurePassword;

            var entropy=
                PasswordUtilities.ComputeEntropyOnly(pwd);

            EntropyText.Text = $"Entropy: {(int)entropy} bits";
            EntropyProgress.Value = Math.Min(entropy, EntropyProgress.Maximum);

            var passwordPolicy = PasswordUtilities.ValidatePasswordPolicy(pwd, confirm);
            ChangeButton.IsEnabled = PasswordUtilities.SecureEquals(pwd, confirm) && passwordPolicy && entropy >= 80;
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private async void Change_Click(object sender, RoutedEventArgs e)
        {
           await PasswordChangeService.ChangePasswordAsync(_username, CurrentPasswordBox.SecurePassword, NewPasswordBox.SecurePassword,
                false);
        }
    }
}

