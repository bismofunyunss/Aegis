using Aegis.App.IO;
using Aegis.App.Ipc;
using Aegis.App.SecureStringUtil;
using Aegis.App.Verification;
using System.Security;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Aegis.App.PcrUtils;

namespace Aegis.App.Pages;

public partial class RegisterPage :
    Page,
    IWindowResizablePage
{
    public double DesiredWidth =>
        550;

    public double DesiredHeight =>
        500;

    private const double MinEntropyBits =
        80;

    private const double OptimalEntropyBits =
        100;


    public RegisterPage()
    {
        InitializeComponent();
    }


    // =========================================================
    // PASSWORD STRENGTH
    // =========================================================

    private void PasswordBox_PasswordChanged(
        object sender,
        RoutedEventArgs e)
    {
        var pwdSecure =
            PasswordBox.SecurePassword;

        if (pwdSecure == null ||
            pwdSecure.Length == 0)
        {
            PasswordStrengthBar.Value =
                0;

            PasswordEntropyLabel.Text =
                "Entropy: 0 bits";

            PasswordStrengthBar.Foreground =
                Brushes.OrangeRed;

            return;
        }

        double entropy =
            PasswordUtilities.ComputeEntropyOnly(
                pwdSecure);

        PasswordStrengthBar.Value =
            entropy;

        PasswordEntropyLabel.Text =
            $"Entropy: {Math.Round(entropy, 1)} bits";

        if (entropy < MinEntropyBits)
        {
            PasswordStrengthBar.Foreground =
                Brushes.OrangeRed;
        }
        else if (entropy < OptimalEntropyBits)
        {
            PasswordStrengthBar.Foreground =
                Brushes.Gold;
        }
        else
        {
            PasswordStrengthBar.Foreground =
                Brushes.LimeGreen;
        }
    }


    // =========================================================
    // REGISTER BUTTON
    // =========================================================

    private async void RegisterButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        try
        {
            await RegisterAsync();
        }
        catch (CryptographicException ex)
        {
            FileLogger.Log(
                ex,
                "A cryptographic error occurred during registration.",
                UsernameBox.Text.Trim());

            MessageBox.Show(
                "A cryptographic error occurred.",
                "Registration Failed",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        catch (SecurityException ex)
        {
            FileLogger.Log(
                ex,
                "A security error occurred during registration.",
                UsernameBox.Text.Trim());

            MessageBox.Show(
                "A security error occurred.",
                "Security Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        catch (JsonException ex)
        {
            FileLogger.Log(
                ex,
                "An invalid JSON response was received during registration.",
                UsernameBox.Text.Trim());

            MessageBox.Show(
                "The registration response was invalid.",
                "Registration Failed",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        catch (TimeoutException ex)
        {
            FileLogger.Log(
                ex,
                "Registration timed out.",
                UsernameBox.Text.Trim());

            MessageBox.Show(
                "The registration service did not respond in time.",
                "Registration Failed",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        catch (Exception ex)
        {
            FileLogger.Log(
                ex,
                "An unexpected error occurred during registration.",
                UsernameBox.Text.Trim());

            MessageBox.Show(
                "Registration failed. Please try again.",
                "Registration Failed",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }


    // =========================================================
    // REGISTRATION WORKFLOW
    // =========================================================

    private async Task RegisterAsync()
    {
        string username =
            UsernameBox.Text.Trim();

        if (string.IsNullOrWhiteSpace(
                username))
        {
            return;
        }

        var password =
            PasswordBox.SecurePassword;

        var confirmPassword =
            ConfirmPasswordBox.SecurePassword;

        byte[]? passwordBytes =
            null;

        try
        {
            // =================================================
            // PASSWORD POLICY
            // =================================================

            if (!PasswordUtilities.ValidatePasswordPolicy(
                    password,
                    confirmPassword))
            {
                MessageBox.Show(
                    "Password must be 12-64 characters, include uppercase, lowercase, number, special character, and match confirmation.",
                    "Invalid Password",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);

                return;
            }

            RegisterButton.IsEnabled =
                false;

            // =================================================
            // PASSWORD CONVERSION
            // =================================================

            passwordBytes =
                ToBytes.ToUtf8Bytes(
                    password);

            // =================================================
            // REGISTER ACCOUNT
            // =================================================

            var enrollment =
                await AppServices.Core.RegisterAsync(
                    passwordBytes,
                    PcrSelection.Pcrs,
                    username);

            // =================================================
            // TOTP ENROLLMENT
            // =================================================

            var totpWindow =
                new TotpRegisterWindow(
                    enrollment);

            bool? totpResult =
                totpWindow.ShowDialog();

            if (totpResult != true)
            {
                bool cleanupSucceeded =
                    true;

                try
                {
                    await SecureFileEraser
                        .SecurelyEraseFileAsync(
                            Folders.GetUserFolder(
                                username));
                }
                catch (Exception cleanupEx)
                {
                    cleanupSucceeded =
                        false;

                    FileLogger.Log(
                        cleanupEx,
                        "CRITICAL: Failed to securely erase registration data after TOTP enrollment was cancelled.",
                        username);
                }

                if (!cleanupSucceeded)
                {
                    MessageBox.Show(
                        "Registration was cancelled, but some temporary registration data could not be securely removed.",
                        "Security Warning",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                }
                else
                {
                    MessageBox.Show(
                        "TOTP enrollment was not completed.",
                        "Registration Incomplete",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                }

                return;
            }

            // =================================================
            // SUCCESS
            // =================================================

            MessageBox.Show(
                "Registration successful!",
                "Success",
                MessageBoxButton.OK,
                MessageBoxImage.Information);

            UsernameBox.Clear();
            PasswordBox.Clear();
            ConfirmPasswordBox.Clear();
        }
        finally
        {
            // =================================================
            // SECURE CLEANUP
            // =================================================

            if (passwordBytes != null)
            {
                CryptographicOperations.ZeroMemory(
                    passwordBytes);
            }

            password.Dispose();
            confirmPassword.Dispose();

            RegisterButton.IsEnabled =
                true;
        }
    }
}

