using Aegis.App;
using Aegis.App.Controls;
using Aegis.App.Core;
using Aegis.App.Crypto;
using Aegis.App.Global;
using Aegis.App.Helpers;
using Aegis.App.Interfaces;
using Aegis.App.Login;
using Aegis.App.Session;
using Aegis.App.Vault.Services;
using Aegis.App.Vault.VaultEntry;
using Org.BouncyCastle.Crypto.Engines;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using Aegis.App.PcrUtils;
using Aegis.App.SecureStringUtil;
using Aegis.App.TPM;
using WinRT;
using static Aegis.App.Pages.VaultPage;

namespace Aegis.App.Pages;

/// <summary>
///     Interaction logic for LoginPage.xaml
/// </summary>
public partial class LoginPage : Page, IWindowResizablePage
{
    private string _username;
    public LoginPage()
    {
        InitializeComponent();
    }

    public double DesiredWidth => 550; // width for this page
    public double DesiredHeight => 500; // height for this page

    private SecureMasterKey? secureKey;

    private async void LoginButton_Click(object sender, RoutedEventArgs e)
    {
        _username = UsernameBox.Text.Trim();
        if (string.IsNullOrEmpty(_username)) return;

        LoginButton.IsEnabled = false;
        byte[]? passwordBytes = null;
        try
        {
            uint[] pcrs = { 0, 2, 4, 7, 11 };
            TpmSealService tpmSealService = new TpmSealService(OpenTpm.CreateTpm2(), _username, PcrSelection.Pcrs);

            var loginService = new UserLoginService(_username);
            using var keystore = new IKeyStore(_username);

            // Obtain raw master key bytes from login
            var secureKey = await MasterKeyManager.LoginAndUnwrapMasterKeyAsync(tpmSealService, await WindowsHelloManager.GetHelloKeyAsync(_username), ToBytes.ToUtf8Bytes(PasswordBox.SecurePassword), _username, keystore.LoadKeyBlob(), pcrs);
            if (secureKey == null || secureKey.Length == 0)
                throw new InvalidOperationException("Failed to retrieve master key.");

            Session.Session.Start(new UserSession(_username), new CryptoSession(secureKey));

            // Load and decrypt vault
            await LoadVaultOnLoginAsync();

            // Update main window UI
            if (Application.Current.MainWindow is MainWindow mainWindow)
            {
                mainWindow.RainbowWelcomeLabel.ShowUsername(_username);
                await mainWindow.TpmKeyStatus.ShowKeyStatusAsync();
            }

            MessageBox.Show("Login successful!", "Success",
                MessageBoxButton.OK, MessageBoxImage.Information);

            LoginButton.IsEnabled = false;
            UsernameBox.IsEnabled = false;
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

        if (Application.Current.MainWindow is MainWindow mainWindow)
        {
            mainWindow.RainbowWelcomeLabel.Visibility = Visibility.Hidden;
            mainWindow.TpmKeyStatus.Visibility = Visibility.Hidden;

        }

        LoginButton.IsEnabled = true;
        UsernameBox.IsEnabled = true;
    }

    public static async Task LoadVaultOnLoginAsync()
    {
        var vaultPath = Path.Combine(
            IO.Folders.GetUserFolder(Session.Session.GetUsername()!),
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
        EnterRecoveryKey recoveryPage = new EnterRecoveryKey(_username);
        recoveryPage.ShowDialog();
    }
}
