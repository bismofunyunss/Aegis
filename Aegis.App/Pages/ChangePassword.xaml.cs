using System.Security;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Media;
using Aegis.App.Crypto;
using Aegis.App.Ipc;
using Aegis.App.SecureStringUtil;

namespace Aegis.App.Pages;

public partial class ChangePassword : Window
{
    private const double MinimumPasswordEntropyBits = 80.0;

    private bool _changingPassword;

    public ChangePassword()
    {
        InitializeComponent();

        Loaded +=
            ChangePassword_Loaded;
    }


    // =========================================================
    // WINDOW
    // =========================================================

    private void ChangePassword_Loaded(
        object sender,
        RoutedEventArgs e)
    {
        CurrentPasswordBox.Focus();

        UpdatePasswordState();
    }


    // =========================================================
    // NEW PASSWORD CHANGED
    // =========================================================

    private void NewPasswordBox_PasswordChanged(
        object sender,
        RoutedEventArgs e)
    {
        UpdatePasswordStrength();

        UpdatePasswordState();
    }


    // =========================================================
    // CONFIRM PASSWORD CHANGED
    // =========================================================

    private void ConfirmPasswordBox_PasswordChanged(
        object sender,
        RoutedEventArgs e)
    {
        UpdatePasswordState();
    }


    // =========================================================
    // PASSWORD STRENGTH
    // =========================================================

    private void UpdatePasswordStrength()
    {
        var password =
            NewPasswordBox.SecurePassword;

        if (password.Length == 0)
        {
            PasswordStrengthBar.Value =
                0;

            PasswordEntropyText.Text =
                "Entropy: 0 bits";

            PasswordStrengthBar.Foreground =
                Brushes.Red;

            PasswordRequirementsText.Text =
                "Use a long, unique password containing a mix of character types.";

            return;
        }

        double entropy;

        try
        {
            entropy =
                PasswordUtilities.ComputeEntropyOnly(
                    password);
        }
        catch
        {
            entropy = 0;
        }

        PasswordEntropyText.Text =
            $"Entropy: {Math.Round(entropy, 1)} bits";

        PasswordStrengthBar.Value =
            Math.Clamp(
                entropy,
                0,
                100);

        if (entropy <
            MinimumPasswordEntropyBits)
        {
            PasswordStrengthBar.Foreground =
                Brushes.OrangeRed;

            PasswordRequirementsText.Text =
                "Password strength is below the recommended minimum.";
        }
        else if (entropy < 100)
        {
            PasswordStrengthBar.Foreground =
                Brushes.Gold;

            PasswordRequirementsText.Text =
                "Password is acceptable but stronger passwords are recommended.";
        }
        else
        {
            PasswordStrengthBar.Foreground =
                Brushes.LimeGreen;

            PasswordRequirementsText.Text =
                "Password strength is strong.";
        }
    }


    // =========================================================
    // ENABLE / DISABLE CHANGE BUTTON
    // =========================================================

    private void UpdatePasswordState()
    {
        if (_changingPassword)
        {
            ChangePasswordButton.IsEnabled =
                false;

            return;
        }

        var currentEntered =
            CurrentPasswordBox.SecurePassword.Length > 0;

        var newEntered =
            NewPasswordBox.SecurePassword.Length > 0;

        var confirmEntered =
            ConfirmPasswordBox.SecurePassword.Length > 0;

        var passwordsMatch =
            newEntered &&
            confirmEntered &&
            SecurePasswordEquals(
                NewPasswordBox.SecurePassword,
                ConfirmPasswordBox.SecurePassword);

        ChangePasswordButton.IsEnabled =
            currentEntered &&
            newEntered &&
            confirmEntered &&
            passwordsMatch;
    }


    // =========================================================
    // CHANGE PASSWORD
    // =========================================================

    private async void ChangePasswordButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (_changingPassword)
            return;

        _changingPassword =
            true;

        ChangePasswordButton.IsEnabled =
            false;

        CancelButton.IsEnabled =
            false;

        StatusDot.Fill =
            Brushes.Gold;

        StatusText.Text =
            "Validating password change...";

        byte[]? currentPasswordBytes =
            null;

        byte[]? newPasswordBytes =
            null;

        try
        {
            // =================================================
            // AUTHENTICATION STATE
            // =================================================

            if (!ClientSessionManager.IsAuthenticated)
                throw new SecurityException(
                    "No authenticated user session.");


            // =================================================
            // SECURE PASSWORD REFERENCES
            // =================================================

            var currentPassword =
                CurrentPasswordBox.SecurePassword;

            var newPassword =
                NewPasswordBox.SecurePassword;

            var confirmPassword =
                ConfirmPasswordBox.SecurePassword;


            // =================================================
            // BASIC VALIDATION
            // =================================================

            if (currentPassword.Length == 0)
                throw new ArgumentException(
                    "Current password is required.");

            if (newPassword.Length == 0)
                throw new ArgumentException(
                    "New password is required.");

            if (confirmPassword.Length == 0)
                throw new ArgumentException(
                    "Password confirmation is required.");


            // =================================================
            // PASSWORD POLICY
            // =================================================

            if (!PasswordUtilities.ValidatePasswordPolicy(
                    newPassword,
                    confirmPassword))
                throw new ArgumentException(
                    "The new password does not satisfy the password policy.");


            // =================================================
            // PASSWORD MUST ACTUALLY CHANGE
            // =================================================

            if (SecurePasswordEquals(
                    currentPassword,
                    newPassword))
                throw new ArgumentException(
                    "The new password must be different from the current password.");


            // =================================================
            // CONVERT TO UTF-8 BYTES
            // =================================================

            currentPasswordBytes =
                ToBytes.ToUtf8Bytes(
                    currentPassword);

            newPasswordBytes =
                ToBytes.ToUtf8Bytes(
                    newPassword);


            // =================================================
            // STATUS
            // =================================================

            StatusText.Text =
                "Rewrapping account key material...";


            // =================================================
            // CORE PASSWORD CHANGE
            //
            // The UI does NOT:
            //
            //   unseal master keys
            //   derive KEKs
            //   manipulate AccountRootKey
            //   manipulate FileKey
            //
            // Core/server owns those operations.
            // =================================================

            await AppServices.Core.ChangePasswordAsync(
                currentPasswordBytes,
                newPasswordBytes);


            // =================================================
            // SUCCESS
            // =================================================

            StatusDot.Fill =
                Brushes.LimeGreen;

            StatusText.Text =
                "Password changed successfully.";

            CurrentPasswordBox.Clear();

            NewPasswordBox.Clear();

            ConfirmPasswordBox.Clear();

            MessageBox.Show(
                "Your password has been changed successfully.",
                "Password Changed",
                MessageBoxButton.OK,
                MessageBoxImage.Information);

            DialogResult =
                true;

            Close();
        }
        catch (OperationCanceledException)
        {
            StatusDot.Fill =
                Brushes.Orange;

            StatusText.Text =
                "Password change cancelled.";
        }
        catch (ArgumentException ex)
        {
            StatusDot.Fill =
                Brushes.OrangeRed;

            StatusText.Text =
                "Password validation failed.";

            MessageBox.Show(
                ex.Message,
                "Invalid Password",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
        catch (CryptographicException ex)
        {
            FileLogger.Log(
                ex,
                "Cryptographic failure during password change.",
                ClientSessionManager.IsAuthenticated
                    ? ClientSessionManager.Current.Username
                    : "Unknown");

            StatusDot.Fill =
                Brushes.Red;

            StatusText.Text =
                "Password change failed.";

            MessageBox.Show(
                "The password could not be changed because the cryptographic operation failed.",
                "Password Change Failed",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        catch (SecurityException ex)
        {
            FileLogger.Log(
                ex,
                "Security failure during password change.",
                ClientSessionManager.IsAuthenticated
                    ? ClientSessionManager.Current.Username
                    : "Unknown");

            StatusDot.Fill =
                Brushes.Red;

            StatusText.Text =
                "Security validation failed.";

            MessageBox.Show(
                ex.Message,
                "Security Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        catch (Exception ex)
        {
            FileLogger.Log(
                ex,
                "Unexpected error during password change.",
                ClientSessionManager.IsAuthenticated
                    ? ClientSessionManager.Current.Username
                    : "Unknown");

            StatusDot.Fill =
                Brushes.Red;

            StatusText.Text =
                "Password change failed.";

            MessageBox.Show(
                "An unexpected error occurred while changing the password.",
                "Password Change Failed",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        finally
        {
            if (currentPasswordBytes != null)
                CryptographicOperations.ZeroMemory(
                    currentPasswordBytes);

            if (newPasswordBytes != null)
                CryptographicOperations.ZeroMemory(
                    newPasswordBytes);

            CurrentPasswordBox.Clear();

            /*
             * Clear the confirmation and new password fields
             * even after failure so sensitive material isn't
             * left in the controls.
             */
            NewPasswordBox.Clear();

            ConfirmPasswordBox.Clear();

            _changingPassword =
                false;

            CancelButton.IsEnabled =
                true;

            UpdatePasswordState();
        }
    }


    // =========================================================
    // CANCEL
    // =========================================================

    private void CancelButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (_changingPassword)
            return;

        CurrentPasswordBox.Clear();

        NewPasswordBox.Clear();

        ConfirmPasswordBox.Clear();

        DialogResult =
            false;

        Close();
    }


    // =========================================================
    // SECURE PASSWORD COMPARISON
    // =========================================================

    private static bool SecurePasswordEquals(
        SecureString left,
        SecureString right)
    {
        byte[]? leftBytes =
            null;

        byte[]? rightBytes =
            null;

        try
        {
            leftBytes =
                ToBytes.ToUtf8Bytes(
                    left);

            rightBytes =
                ToBytes.ToUtf8Bytes(
                    right);

            return CryptographicOperations.FixedTimeEquals(
                leftBytes,
                rightBytes);
        }
        finally
        {
            if (leftBytes != null)
                CryptographicOperations.ZeroMemory(
                    leftBytes);

            if (rightBytes != null)
                CryptographicOperations.ZeroMemory(
                    rightBytes);
        }
    }
}