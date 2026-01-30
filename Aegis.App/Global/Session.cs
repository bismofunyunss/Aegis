using Aegis.App.Crypto;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.App.Global;

public sealed class Session
{
    private static readonly Lazy<Session> _instance = new(() => new Session());
    public static Session Instance => _instance.Value;

    public string? Username { get; private set; }
    public SecureMasterKey? MasterKey { get; private set; }
    public CryptoSession? Crypto { get; internal set; }

    private Session() { }

    public void SetUser(string username, byte[] masterKeyBytes)
    {
        Username = username;

        // Dispose existing session
        Crypto?.Dispose();
        MasterKey?.Dispose();

        // Create new SecureMasterKey
        MasterKey = new SecureMasterKey(masterKeyBytes);

        // Initialize CryptoSession with the master key
        Crypto = new CryptoSession(MasterKey);

        // Clear raw master key bytes from memory
        CryptographicOperations.ZeroMemory(masterKeyBytes);

        OnSessionChanged?.Invoke(this, EventArgs.Empty);
    }

    public void Clear()
    {
        Crypto?.Dispose();
        Crypto = null;
        MasterKey?.Dispose();
        MasterKey = null;
        Username = null;
        OnSessionChanged?.Invoke(this, EventArgs.Empty);
    }

    public sealed class CryptoSession : IDisposable
    {
        public SecureMasterKey MasterKey { get; }
        public DerivedKeys Keys { get; }
        private byte[] fileKey;
        public CryptoSession(SecureMasterKey masterKey)
        {
            MasterKey = masterKey;

            // Generate a unique file key salt for vault/file encryption
            byte[] fileKeySalt = RandomNumberGenerator.GetBytes(128);

            // Derive a file key from the master key
            fileKey = masterKey.DeriveKey(
                salt: fileKeySalt,
                info: "Aegis-File-Key"u8.ToArray(),
                length: 64
            );

            var salts = CryptoMethods.SaltGenerator.CreateSalts(128);
            // Derive all encryption keys from the file key
            Keys = KeyDerivation.DeriveKeys(fileKey, salts);

            // Clear ephemeral file key from memory
            CryptographicOperations.ZeroMemory(fileKey);
        }

        public void Dispose()
        {
            Keys.Dispose();
            // Do not dispose MasterKey here; it's managed by Session
        }
    }

    public event EventHandler? OnSessionChanged;
}


