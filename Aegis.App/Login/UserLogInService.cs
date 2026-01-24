using Aegis.App.Core;
using Aegis.App.Crypto;
using Aegis.App.IO;
using Aegis.App.SecureStringUtil;
using Aegis.App.Session;
using Aegis.App.TPM;
using System.IO;
using System.Security;
using System.Windows.Controls;
using Windows.Security.Credentials;
using Aegis.App.PcrUtils;

namespace Aegis.App.Login;

public class UserLoginService
{
    private readonly string _userFolder;
    private readonly string _username;
    private readonly SecureString _password;

    public UserLoginService(string username, SecureString password)
    {
        _username = username;
        _password = password;
        _userFolder = Folders.GetUserFolder(username);
        if (!Directory.Exists(_userFolder))
            throw new InvalidOperationException("User does not exist.");
    }

    internal async Task<Session.Session.CryptoSession> LoginAsync()
    {
        using var keyStore = new IKeyStore(_username);
        var blob = keyStore.LoadKeyBlob();
        TpmSealService sealService = new TpmSealService(OpenTpm.CreateTpm2());

        var secureMasterKey = await MasterKeyManager.LoginAndUnwrapMasterKeyAsync(sealService, ToBytes.ToUtf8Bytes(_password), _username, blob, PcrSelection.Pcrs);

        CryptoSessionManager.StartSession(secureMasterKey);
        return secureMasterKey;
    }
}