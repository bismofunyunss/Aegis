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
        // Create TPM service once
        var tpmSealService = new TpmSealService(OpenTpm.CreateTpm2(), PcrSelection.Pcrs);

        // 1️⃣ Generate raw TOTP secret (20 bytes typical)
       /* byte[] rawTotpSecret = RandomNumberGenerator.GetBytes(20);

        // 2️⃣ Create a single IKeyStore instance for the whole flow
        using var store = new IKeyStore(_username);

        // 3️⃣ Show TOTP registration window and pass the store
        var totpWindow = new TotpVerifyWindow(store, rawTotpSecret)
        {
            Owner = Application.Current.MainWindow
        };

        bool? result = totpWindow.ShowDialog(); // modal dialog
        if (result != true)
        {
            MessageBox.Show(
                "TOTP verification was cancelled or failed.",
                "Registration Incomplete",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        // 4️⃣ TOTP verified → save protected secret
        byte[] entropy = RandomNumberGenerator.GetBytes(128);
        byte[] protectedSecret = ProtectedData.Protect(
            rawTotpSecret,
            entropy,
            DataProtectionScope.CurrentUser
        );

        store.AddTotpSecret(_username, protectedSecret, entropy);

        MessageBox.Show(
            "TOTP successfully verified!",
            "Success",
            MessageBoxButton.OK,
            MessageBoxImage.Information);

        // 5️⃣ Create and save master key
       */
        try
        {
           SystemSecurity.EnsureSecurityEnabled();

            var recoveryKey = RandomNumberGenerator.GetBytes(32);

            var blob = await MasterKeyManager.CreateAndWrapMasterKeyAsync(
                tpmSealService,
                _password,
                PcrSelection.Pcrs,
                _username,
                recoveryKey
            );
            using var store = new IKeyStore(_username);

        store.SaveKeyBlob(blob); // ✅ saves to same store instance
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                "There was an error during registration. " + ex.Message,
                "Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        finally
        {
            MemoryHandling.Clear(_password);
        }
    }
}