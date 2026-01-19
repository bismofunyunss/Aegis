using Aegis.App.Core;
using Aegis.App.Crypto;
using Aegis.App.IO;
using Aegis.App.TPM;
using Aegis.App.Verification;
using OtpNet;
using System.Security.Cryptography;
using System.Windows;
using Aegis.App.PcrUtils;

namespace Aegis.App.Registration;

public class UserRegistrationService
{
    private readonly byte[] _password;
    private readonly string _userFolder;
    private readonly string _username;

    public UserRegistrationService(string username, byte[] password)
    {
        if (string.IsNullOrWhiteSpace(username) || username.Length > 20)
            throw new ArgumentException("Invalid username", nameof(username));
        _password = password;
        _username = username;
        _userFolder = Folders.GetOrCreateUserFolder(username);
    }

    public async Task RegisterAsync()
    {
        var tpmSealService = new TpmSealService(OpenTpm.CreateTpm2(), _username, PcrSelection.Pcrs);

        // After generating the TOTP secret for the user
        byte[] rawTotpSecret = RandomNumberGenerator.GetBytes(20); // 20 bytes is typical for TOTP

        // Save protected secret to keystore
        using var _store = new IKeyStore(_username);

        // Show the TOTP registration window
        var totpWindow = new TotpVerifyWindow(_username, rawTotpSecret)
        {
            Owner = Application.Current.MainWindow
        };

        bool? result = totpWindow.ShowDialog(); // modal dialog

        if (result == true)
        {
            byte[] entropy = RandomNumberGenerator.GetBytes(128);

            byte[] protectedSecret = ProtectedData.Protect(
                rawTotpSecret,
                entropy,
                DataProtectionScope.CurrentUser);

            using var store = new IKeyStore(_username);
            store.AddTotpSecret(_username, protectedSecret, entropy);

            MessageBox.Show(
                "TOTP successfully verified! Registration complete.",
                "Success",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        else
        {
            MessageBox.Show(
                "TOTP verification was cancelled or failed.",
                "Registration Incomplete",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }


        try
        {

            SystemSecurity.EnsureSecurityEnabled();

            var recoveryKey = RandomNumberGenerator.GetBytes(32);

            // Seal the master key using TPM and optional Windows Hello
            var blob = await MasterKeyManager.CreateAndWrapMasterKeyAsync(
                tpmSealService,
                await WindowsHelloManager.CreateHelloKeyAsync(_username),
                _password,
                PcrSelection.Pcrs,
                _username,
                recoveryKey
            );


            // Save directly to keystore
            var keyStore = new IKeyStore(_username);
            keyStore.SaveKeyBlob(blob!);
        }
        catch (Exception ex)
        {
            MessageBox.Show("There was an error during registration.", "Error", MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        finally
        {
            MemoryHandling.Clear(_password);
        }
    }
}