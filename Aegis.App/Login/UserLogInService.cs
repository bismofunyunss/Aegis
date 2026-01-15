using System.IO;
using Windows.Security.Credentials;
using Aegis.App.Core;
using Aegis.App.Crypto;
using Aegis.App.IO;
using Aegis.App.TPM;

namespace Aegis.App.Login;

public class UserLoginService
{
    private readonly string _userFolder;
    private readonly string _username;

    public UserLoginService(string username)
    {
        _username = username;
        _userFolder = Folders.GetUserFolder(username);
        if (!Directory.Exists(_userFolder))
            throw new InvalidOperationException("User does not exist.");
    }

    public async Task<SecureMasterKey?> UnsealMasterKey(TpmSealService tpm, KeyBlob blob, KeyCredential helloKey,
        byte[] userPassword, byte[]? recoveryKey = null)
    {
        return await MasterKeyManager.UnsealMasterKeyAsync(tpm, blob, helloKey, userPassword, recoveryKey);
    }
}