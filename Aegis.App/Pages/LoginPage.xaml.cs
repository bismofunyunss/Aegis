using System.IO;
using System.Windows;
using System.Windows.Controls;
using Aegis.App.Crypto;
using Aegis.App.Interfaces;
using Aegis.App.IO;
using Aegis.App.Login;
using Aegis.App.PcrUtils;
using Aegis.App.TPM;
using Aegis.App.Vault.VaultEntry;
using static Aegis.App.Session.Session;

namespace Aegis.App.Pages;

/// <summary>
///     Interaction logic for LoginPage.xaml
/// </summary>
public partial class LoginPage : Page, IWindowResizablePage
{
    private static string _username;

    private SecureMasterKey? secureKey;

    public LoginPage()
    {
        InitializeComponent();
    }

    public double DesiredWidth => 550; // width for this page
    public double DesiredHeight => 500; // height for this page

    private async void LoginButton_Click(object sender, RoutedEventArgs e)
    {
        _username = UsernameBox.Text.Trim();
        if (string.IsNullOrEmpty(_username)) return;

        LoginButton.IsEnabled = false;
        byte[]? passwordBytes = null;
        try
        {
            var tpmSealService = new TpmSealService(OpenTpm.CreateTpm2(), PcrSelection.Pcrs);

            using var keystore = new IKeyStore(_username);

            var loginService = new UserLoginService(_username, PasswordBox.SecurePassword);

            var cryptoSession = await loginService.LoginAsync();

            var user = new UserSession(_username);

            SessionManager.Start(user, cryptoSession);

            // Load and decrypt vault
            await LoadVaultOnLoginAsync(cryptoSession, user);

            MessageBox.Show("Login successful!", "Success",
                MessageBoxButton.OK, MessageBoxImage.Information);

            LoginButton.IsEnabled = false;
            UsernameBox.IsEnabled = false;
            PasswordBox.Clear();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Login failed: {ex.Message}",
                "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            LoginButton.IsEnabled = true;
        }
    }


    private void LogoutButton_Click(object sender, RoutedEventArgs e)
    {
        secureKey?.Dispose();

        secureKey = null;

        LoginButton.IsEnabled = true;
        UsernameBox.IsEnabled = true;
    }

    public static async Task LoadVaultOnLoginAsync(CryptoSession session, UserSession userSession)
    {
        var vaultPath = Path.Combine(
            Folders.GetUserFolder(_username),
            "vault.dat"
        );

        if (!File.Exists(vaultPath))
        {
            VaultState.Items.Clear();
            VaultState.IsDirty = false;
            return;
        }

        using var vaultFile = new FileStream(
            vaultPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read
        );

        await VaultService.LoadVaultAsync();
    }

    private void ForgotPasswordButton_Click(object sender, RoutedEventArgs e)
    {
        var recoveryPage = new EnterRecoveryKey(_username);
        recoveryPage.ShowDialog();
    }
}