using Aegis.App.Core;
using Aegis.App.Crypto;
using Aegis.App.Helpers;
using Aegis.App.IO;
using Aegis.App.TPM;
using Aegis.App.Verification;
using OtpNet;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using Tpm2Lib;
using static Aegis.App.TPM.TpmSealService;

namespace Aegis.App.Registration;

public class UserRegistrationService
{
    private readonly string _userFolder;
    private readonly string _username;
    private readonly byte[] _password;
    private SoftwareKeyStore _store;

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
        uint[] pcrs = { 0, 2, 4, 7, 11 };
        TpmSealService tpmSealService = new TpmSealService(OpenTpm.CreateTpm2(), _username, pcrs);

        // Generate a recovery key
        byte[] recoveryKey = RandomNumberGenerator.GetBytes(32);

        // Display it to the user
        RecoveryKey window = new RecoveryKey(recoveryKey);
        window.ShowDialog();
        

        try
        {
            SystemSecurity.EnsureSecurityEnabled();

            // Seal the master key using TPM and optional Windows Hello
            KeyBlob? blob = await MasterKeyManager.CreateAndWrapMasterKeyAsync(
                tpmSealService,
                await WindowsHelloManager.CreateHelloKeyAsync(_username),
                _password,
                pcrs,
                recoveryKey
            );
           

            // Save directly to keystore
            IKeyStore keyStore = new IKeyStore(_username);
            keyStore.SaveKeyBlob(blob!);
        }
        catch (Exception ex)
        {
            MessageBox.Show("There was an error during registration.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}