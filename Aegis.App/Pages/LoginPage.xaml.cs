using Aegis.App;
using Aegis.App.Controls;
using Aegis.App.Crypto;
using Aegis.App.Global;
using Aegis.App.Interfaces;
using Aegis.App.Login;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using Aegis.App.Helpers;
using Aegis.App.Vault.Services;
using Aegis.App.Vault.VaultEntry;
using Org.BouncyCastle.Crypto.Engines;
using WinRT;
using static Aegis.App.Pages.VaultPage;
using Aegis.App.Core;

namespace Aegis.App.Pages;

/// <summary>
///     Interaction logic for LoginPage.xaml
/// </summary>
public partial class LoginPage : Page, IWindowResizablePage
{
    public LoginPage()
    {
        InitializeComponent();
    }

    public double DesiredWidth => 550; // width for this page
    public double DesiredHeight => 500; // height for this page

    private SecureMasterKey? secureKey;

    private async void LoginButton_Click(object sender, RoutedEventArgs e)
    {
        /*var username = UsernameBox.Text.Trim();
        if (string.IsNullOrEmpty(username)) return;

        LoginButton.IsEnabled = false;
        byte[]? masterKeyBytes = null;

        try
        {
            var loginService = new UserLoginService(username);

            // Obtain raw master key bytes from login
            masterKeyBytes = await MasterKeyManager.CreateAndWrapMasterKeyAsync();
            if (masterKeyBytes == null || masterKeyBytes.Length == 0)
                throw new InvalidOperationException("Failed to retrieve master key.");

            // Dispose any previous SecureMasterKey safely
            secureKey?.Dispose();

            // Create new SecureMasterKey (pins and clones internally)
            secureKey = new SecureMasterKey(masterKeyBytes);

            // Immediately zero the original raw master key bytes
            CryptographicOperations.ZeroMemory(masterKeyBytes);

            // Initialize session CryptoSession with SecureMasterKey
            Session.Instance.Crypto = new Session.CryptoSession(secureKey);

            // Set username in session
            Session.Instance.SetUser(username, masterKeyBytes);

            // Load and decrypt vault
            await LoadVaultOnLoginAsync();

            // Update main window UI
            if (Application.Current.MainWindow is MainWindow mainWindow)
            {
                mainWindow.RainbowWelcomeLabel.ShowUsername(username);
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

            // Extra precaution: clear raw masterKeyBytes reference
            if (masterKeyBytes != null)
                CryptographicOperations.ZeroMemory(masterKeyBytes);
        }
        */
    }



    private void LogoutButton_Click(object sender, RoutedEventArgs e)
    {
        secureKey?.Dispose();

        secureKey = null;

        if (Application.Current.MainWindow is MainWindow mainWindow)
        {
            mainWindow.RainbowWelcomeLabel.Visibility = Visibility.Hidden;
            mainWindow.TpmKeyStatus.Visibility = Visibility.Hidden;

            Session.Instance.Clear();
        }

        LoginButton.IsEnabled = true;
        UsernameBox.IsEnabled = true;
    }

    public static async Task LoadVaultOnLoginAsync()
    {
        var vaultPath = Path.Combine(
            IO.Folders.GetUserFolder(Session.Instance.Username!),
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
}
