using Aegis.App.Core;
using Aegis.App.Crypto;
using Aegis.App.IO;
using Aegis.App.Session;
using Aegis.App.TPM;
using System.IO;
using Windows.Security.Credentials;

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
}