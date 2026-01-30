using Aegis.App.Crypto;
using Aegis.App.Global;
using Aegis.App.Interfaces;
using Aegis.App.Registration;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Aegis.App.Pages
{
    public partial class RegisterPage : Page, IWindowResizablePage
    {
        public double DesiredWidth => 550;   // width for this page
        public double DesiredHeight => 500;  // height for this page

        private const double MinEntropyBits = 80;
        private const double OptimalEntropyBits = 100;
        public RegisterPage()
        {
            InitializeComponent();
        }

        private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            var pwdSecure = PasswordBox.SecurePassword;

            if (pwdSecure == null || pwdSecure.Length == 0)
            {
                PasswordStrengthBar.Value = 0;
                PasswordEntropyLabel.Text = "Entropy: 0 bits";
                PasswordStrengthBar.Foreground = Brushes.OrangeRed;
                return;
            }

            // Compute entropy
            double entropy = PasswordUtilities.ComputeEntropyOnly(pwdSecure);

            // Update progress bar and label
            PasswordStrengthBar.Value = entropy;
            PasswordEntropyLabel.Text = $"Entropy: {Math.Round(entropy, 1)} bits";

            // Color the bar according to zones
            if (entropy < MinEntropyBits)
                PasswordStrengthBar.Foreground = Brushes.OrangeRed; // below minimum
            else if (entropy < OptimalEntropyBits)
                PasswordStrengthBar.Foreground = Brushes.Gold;      // warning
            else
                PasswordStrengthBar.Foreground = Brushes.LimeGreen; // optimal
        }

        private async void RegisterButton_Click(object sender, RoutedEventArgs e)
        {
            string username = UsernameBox.Text.Trim();

            var password = PasswordBox.SecurePassword;
            var confirmPassword = ConfirmPasswordBox.SecurePassword;

            byte[]? passwordBytes = null;

            try
            {
                if (!PasswordUtilities.ValidatePasswordPolicy(password, confirmPassword))
                {
                    MessageBox.Show(
                        "Password must be 12-64 characters, include uppercase, lowercase, number, special character, and match confirmation.",
                        "Invalid Password",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning
                    );
                    return;
                }


                RegisterButton.IsEnabled = false;

                // Convert password to byte[]
                passwordBytes = SecureStringUtil.ToBytes.ToUtf8Bytes(password);

                // Pass password securely as char[] or byte[] to registration service
                UserRegistrationService userRegistrationService = new UserRegistrationService(username, passwordBytes);
                await userRegistrationService.RegisterAsync();

                MessageBox.Show(
                    "Registration successful!",
                    "Success",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information
                );
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Registration failed: {ex.Message}",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error
                );
            }
            finally
            {
                RegisterButton.IsEnabled = true;

                // Always zero out sensitive data
                MemoryHandling.Clear(passwordBytes);
            }
        }
    }
}

