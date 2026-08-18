using Aegis.App.Core;
using Aegis.App.Crypto;
using Aegis.App.Ipc;
using Aegis.App.SecureStringUtil;
using Aegis.App.Verification;
using System.Diagnostics;
using System.Security;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Aegis.App.Vault.VaultEntry;
using VaultState = Aegis.App.Vault.VaultState;

namespace Aegis.App.Pages;

/// <summary>
/// Interaction logic for LoginPage.xaml
/// </summary>
public partial class LoginPage : Page, IWindowResizablePage
{
    internal string _username = string.Empty;

    public LoginPage()
    {
        InitializeComponent();

        Loaded +=
            LoginPage_Loaded;
    }

    public double DesiredWidth =>
        800;

    public double DesiredHeight =>
        650;


    // =========================================================
    // PAGE LOADED
    // =========================================================

    private async void LoginPage_Loaded(
        object sender,
        RoutedEventArgs e)
    {
        await RefreshSecurityStatusAsync();
    }


    // =========================================================
    // SECURITY STATUS
    // =========================================================

    private async Task RefreshSecurityStatusAsync()
    {
        SetSecurityCheckingState();

        SystemSecurity.SecurityStatus status;

        try
        {
            status =
                await Task.Run(
                    SystemSecurity.GetStatus);
        }
        catch (Exception ex)
        {
            Debug.WriteLine(
                $"Security status refresh failed: {ex}");

            SetSecurityUnknownState();

            return;
        }

        UpdateSecurityIndicator(
            SecureBootStatus,
            status.SecureBootState);

        UpdateSecurityIndicator(
            TpmStatus,
            status.Tpm20State);

        UpdateSecurityIndicator(
            VbsStatus,
            status.VbsState);

        UpdateSecurityIndicator(
            HvciStatus,
            status.HvciState);

        UpdateSecurityIndicator(
            CredentialGuardStatus,
            status.CredentialGuardState);

        UpdateSecurityIndicator(
            DmaStatus,
            status.KernelDmaState);
    }


    private static void UpdateSecurityIndicator(
        TextBlock indicator,
        SystemSecurity.SecurityFeatureState state)
    {
        switch (state)
        {
            case SystemSecurity.SecurityFeatureState.Running:

                indicator.Text =
                    "✓";

                indicator.Foreground =
                    Brushes.LimeGreen;

                break;

            case SystemSecurity.SecurityFeatureState.Unknown:
            case SystemSecurity.SecurityFeatureState.NotSupported:
            case SystemSecurity.SecurityFeatureState.NotPresent:
            case SystemSecurity.SecurityFeatureState.Configured:

                indicator.Text =
                    "⚠";

                indicator.Foreground =
                    Brushes.Orange;

                break;

            case SystemSecurity.SecurityFeatureState.Disabled:

                indicator.Text =
                    "✗";

                indicator.Foreground =
                    Brushes.Red;

                break;

            default:

                indicator.Text =
                    "?";

                indicator.Foreground =
                    new SolidColorBrush(
                        Color.FromRgb(
                            150,
                            150,
                            150));

                break;
        }
    }


    private void SetSecurityCheckingState()
    {
        SetSecurityIndicatorChecking(
            SecureBootStatus);

        SetSecurityIndicatorChecking(
            TpmStatus);

        SetSecurityIndicatorChecking(
            VbsStatus);

        SetSecurityIndicatorChecking(
            HvciStatus);

        SetSecurityIndicatorChecking(
            CredentialGuardStatus);

        SetSecurityIndicatorChecking(
            DmaStatus);
    }


    private static void SetSecurityIndicatorChecking(
        TextBlock indicator)
    {
        indicator.Text =
            "...";

        indicator.Foreground =
            new SolidColorBrush(
                Color.FromRgb(
                    150,
                    150,
                    150));
    }


    private void SetSecurityUnknownState()
    {
        SetSecurityIndicatorUnknown(
            SecureBootStatus);

        SetSecurityIndicatorUnknown(
            TpmStatus);

        SetSecurityIndicatorUnknown(
            VbsStatus);

        SetSecurityIndicatorUnknown(
            HvciStatus);

        SetSecurityIndicatorUnknown(
            CredentialGuardStatus);

        SetSecurityIndicatorUnknown(
            DmaStatus);
    }


    private static void SetSecurityIndicatorUnknown(
        TextBlock indicator)
    {
        indicator.Text =
            "?";

        indicator.Foreground =
            new SolidColorBrush(
                Color.FromRgb(
                    150,
                    150,
                    150));
    }


    // =========================================================
    // LOGIN BUTTON
    // =========================================================

    private async void LoginButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        var passwordBytes =
            ToBytes.ToUtf8Bytes(
                PasswordBox.SecurePassword);

        _username =
            UsernameBox.Text.Trim();

        bool result = false;

        try
        {
            result =
                await LoginAsync(
                    passwordBytes,
                    _username);
        }
        catch (CryptographicException ex)
        {
            FileLogger.Log(
                ex,
                "A cryptographic error has occured.",
                _username);

            MessageBox.Show(
                "A cryptographic error has occured.",
                "Login Failed",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        catch (JsonException ex)
        {
            FileLogger.Log(
                ex,
                "A JSON file error has occured.",
                _username);

            MessageBox.Show(
                "A JSON file error has occured.",
                "Login Failed",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        catch (SecurityException ex)
        {
            FileLogger.Log(
                ex,
                "A security error has occured.",
                _username);

            MessageBox.Show(
                "A security error has occured.",
                "Security Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        catch (Exception ex)
        {
            FileLogger.Log(
                ex,
                "An error has occured.",
                _username);

            MessageBox.Show(
                "An error has occured.",
                "Login Failed",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                passwordBytes);

            LoginButton.IsEnabled =
                !result;

            LogoutButton.IsEnabled =
                result;

            UsernameBox.IsEnabled =
                !result;

            PasswordBox.IsEnabled =
                !result;
        }
    }


    // =========================================================
    // LOGIN WORKFLOW
    // =========================================================

    private async Task<bool> LoginAsync(
        byte[] passwordBytes,
        string username)
    {
        if (string.IsNullOrWhiteSpace(
                username))
        {
            return false;
        }

        var authenticationId =
            await AppServices.Core.BeginLoginAsync(
                username,
                passwordBytes);

        if (authenticationId == null)
        {
            MessageBox.Show(
                "Invalid username or password.",
                "Login Failed",
                MessageBoxButton.OK,
                MessageBoxImage.Error);

            return false;
        }

        var totpWindow =
            new TotpLoginWindow(
                authenticationId);

        var totpResult =
            totpWindow.ShowDialog();

        if (totpResult != true)
        {
            MessageBox.Show(
                "Two-factor authentication was not completed.",
                "Login Cancelled",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);

            return false;
        }

        if (!ClientSessionManager.IsAuthenticated)
        {
            throw new SecurityException(
                "TOTP succeeded, but no client session was established.");
        }

        var session =
            ClientSessionManager.Current;

        try
        {
            await VaultService.LoadVaultAsync();

            SessionIdText.Text =
                session.SessionId;

            SessionStatusText.Text =
                "YES";

            PasswordBox.Clear();

            MessageBox.Show(
                "Login successful!",
                "Success",
                MessageBoxButton.OK,
                MessageBoxImage.Information);

            return true;
        }
        catch
        {
            VaultState.Items.Clear();

            VaultState.IsDirty =
                false;

            try
            {
                await AppServices.Core.LogoutAsync();
            }
            catch (Exception logoutEx)
            {
                FileLogger.Log(
                    logoutEx,
                    "Failed to clean up session after vault loading failure.",
                    username);
            }

            SessionIdText.Text =
                string.Empty;

            SessionStatusText.Text =
                "NO";

            PasswordBox.Clear();

            throw;
        }
    }


    // =========================================================
    // LOGOUT
    // =========================================================

    private async void LogoutButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        try
        {
            await AppServices.Core.LogoutAsync();
        }
        catch (Exception ex)
        {
            FileLogger.Log(
                ex,
                "There was a server logout error.",
                _username);
        }
        finally
        {
            ClientSessionManager.Clear();

            VaultState.Items?.Clear();

            VaultState.IsDirty =
                false;

            LoginButton.IsEnabled =
                true;

            LogoutButton.IsEnabled =
                false;

            UsernameBox.IsEnabled =
                true;

            PasswordBox.IsEnabled =
                true;

            SessionIdText.Text =
                string.Empty;

            SessionStatusText.Text =
                "NO";

            PasswordBox.Clear();
        }
    }


    // =========================================================
    // FORGOT PASSWORD / RECOVERY
    // =========================================================

    private void ForgotPasswordButton_Click(
        object sender,
        RoutedEventArgs e)
    {

    }
}
