using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Aegis.App.Crypto;

namespace Aegis.App;

public sealed class SoftwareKeyStore : IDisposable
{
    private readonly string _path;
    private bool _disposed;
    internal StoreModel _store;

    public SoftwareKeyStore(string folderPath, string fileName = "keystore.json")
    {
        Directory.CreateDirectory(folderPath);
        _path = Path.Combine(folderPath, fileName);
        _store = Load();
        Lockout = new TotpLockoutManager(this);
    }

    public TotpLockoutManager Lockout { get; }

    #region === Master Key ===

    public WrappedMasterKeyEntry GetWrappedMasterKeyEntry()
    {
        if (_store.MasterKey == null)
            throw new InvalidOperationException("No master key stored.");

        return _store.MasterKey;
    }

    public void StoreMasterKey(
        byte[] wrappedMasterKey,
        byte[] masterKeySalt,
        byte[] wrapKekSalt,
        byte[] gcmKekSalt,
        byte[] nonce,
        byte[] ciphertext,
        byte[] tag)
    {
        _store.MasterKey = new WrappedMasterKeyEntry
        {
            Version = 1,
            CreatedUtc = DateTime.UtcNow,
            MasterSalt = masterKeySalt,
            WrapKekSalt = wrapKekSalt,
            GcmKekSalt = gcmKekSalt,
            NonceHex = Convert.ToHexString(nonce),
            CiphertextHex = Convert.ToHexString(ciphertext),
            TagHex = Convert.ToHexString(tag),
            Info = "AES-GCM wrapped master key"
        };

        Save();

        CryptographicOperations.ZeroMemory(wrappedMasterKey);
        CryptographicOperations.ZeroMemory(nonce);
        CryptographicOperations.ZeroMemory(ciphertext);
        CryptographicOperations.ZeroMemory(tag);
    }

    #endregion

    public TotpLockoutSnapshot GetLockoutSnapshot()
    {
        var userSid = WindowsIdentity.GetCurrent().User!.Value;
        _store.LockoutPerUser.TryGetValue(userSid, out var state);
        state ??= new TotpLockoutState();

        return new TotpLockoutSnapshot
        {
            Failures = state.Failures,
            LockedUntilUtc = state.LockedUntilUtc
        };
    }

    #region === TOTP Secrets ===

    public void AddTotpSecret(string account, byte[] secret)
    {
        if (secret == null || secret.Length != 20)
            throw new ArgumentException("TOTP secret must be exactly 20 bytes");

        _store.Totp = new TotpSecretEntry
        {
            Account = account,
            SecretBase64 = Convert.ToBase64String(secret),
            LastUsedStep = -1
        };

        Save();
    }


    public byte[] LoadTotpSecret(out long lastUsedStep)
    {
        if (_store.Totp == null)
            throw new InvalidOperationException("TOTP secret not enrolled");

        lastUsedStep = _store.Totp.LastUsedStep;

        byte[] protectedSecret = Convert.FromBase64String(_store.Totp.SecretBase64);

        // Decode entropy from Base64 string to byte[]
        byte[] entropy = string.IsNullOrEmpty(_store.Totp.EntropyBase64)
            ? Array.Empty<byte>()
            : Convert.FromBase64String(_store.Totp.EntropyBase64);

        byte[] rawSecret = ProtectedData.Unprotect(protectedSecret, entropy, DataProtectionScope.CurrentUser);

        return rawSecret; // exactly 20 bytes
    }




    /// <summary>
    /// Stores a DPAPI-protected TOTP secret along with its entropy in the keystore.
    /// </summary>
    public void AddEncryptedTotpSecret(string account, byte[] protectedSecret, byte[] entropy)
    {
        if (protectedSecret == null || protectedSecret.Length == 0)
            throw new ArgumentException("Protected TOTP secret cannot be null or empty.");

        if (entropy == null || entropy.Length != 16)
            throw new ArgumentException("TOTP entropy must be 16 bytes.");

        _store.Totp = new TotpSecretEntry
        {
            Account = account,
            SecretBase64 = Convert.ToBase64String(protectedSecret),
            EntropyBase64 = Convert.ToBase64String(entropy),
            LastUsedStep = -1
        };

        Save();
    }


    /// <summary>
    /// Loads and decrypts the DPAPI-protected TOTP secret.
    /// </summary>
    public byte[] LoadDecryptedTotpSecret()
    {
        if (_store.Totp == null)
            throw new InvalidOperationException("TOTP secret not enrolled.");

        byte[] protectedSecret = Convert.FromBase64String(_store.Totp.SecretBase64);
        byte[] entropy = Convert.FromBase64String(_store.Totp.EntropyBase64);

        byte[] secret = ProtectedData.Unprotect(protectedSecret, entropy, DataProtectionScope.CurrentUser);
        return secret; // 20 bytes raw secret
    }



    public void UpdateLastTotpStep(long step)
    {
        if (_store.Totp is null) throw new InvalidOperationException("TOTP not enrolled");
        _store.Totp.LastUsedStep = step;
        Save();
    }

    public sealed class TotpLockoutManager
    {
        private const int MaxAttempts = 5;
        private static readonly TimeSpan BaseLock = TimeSpan.FromSeconds(30);

        private readonly SoftwareKeyStore _store;
        private readonly string _userSid;

        internal TotpLockoutManager(SoftwareKeyStore store)
        {
            _store = store;
            _userSid = WindowsIdentity.GetCurrent().User!.Value;
            if (!_store._store.LockoutPerUser.ContainsKey(_userSid))
                _store._store.LockoutPerUser[_userSid] = new TotpLockoutState();
        }

        private TotpLockoutState State => _store._store.LockoutPerUser[_userSid];

        public void EnsureNotLocked()
        {
            if (State.LockedUntilUtc is { } until && DateTime.UtcNow < until)
                throw new SecurityException($"Locked until {until:u}");
        }

        public void Fail()
        {
            State.Failures++;
            if (State.Failures >= MaxAttempts)
            {
                var level = State.Failures - MaxAttempts + 1;
                State.LockedUntilUtc = DateTime.UtcNow + TimeSpan.FromSeconds(BaseLock.TotalSeconds * level);
            }

            _store.Save();
        }

        public void Success()
        {
            _store._store.LockoutPerUser[_userSid] = new TotpLockoutState();
            _store.Save();
        }
    }

    public sealed class TotpLockoutSnapshot
    {
        public int Failures { get; init; }
        public DateTime? LockedUntilUtc { get; init; }
    }

    #endregion

    #region === Save/Load ===

    private static readonly byte[] HmacKey = SHA256.HashData(Encoding.UTF8.GetBytes(
        WindowsIdentity.GetCurrent().User!.Value));

    public void Save()
    {
        var payloadJson =
            JsonSerializer.SerializeToUtf8Bytes(_store, new JsonSerializerOptions { WriteIndented = true });
        byte[] hmac;
        using (var h = new HMACSHA256(HmacKey))
        {
            hmac = h.ComputeHash(payloadJson);
        }

        var envelope = new KeystoreEnvelope
        {
            Version = 1,
            HmacHex = Convert.ToHexString(hmac),
            Data = _store
        };

        var json = JsonSerializer.Serialize(envelope, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_path, json, new UTF8Encoding(false));
    }

    public StoreModel Load()
    {
        if (!File.Exists(_path))
            return new StoreModel();

        var json = File.ReadAllText(_path, Encoding.UTF8);
        var envelope = JsonSerializer.Deserialize<KeystoreEnvelope>(json) ??
                       throw new SecurityException("Invalid keystore format");

        if (string.IsNullOrWhiteSpace(envelope.HmacHex))
            throw new SecurityException("Missing keystore HMAC");

        var payloadJson =
            JsonSerializer.SerializeToUtf8Bytes(envelope.Data, new JsonSerializerOptions { WriteIndented = true });
        byte[] expectedHmac;
        using (var h = new HMACSHA256(HmacKey))
        {
            expectedHmac = h.ComputeHash(payloadJson);
        }

        var storedHmac = Convert.FromHexString(envelope.HmacHex);

       // if (!CryptographicOperations.FixedTimeEquals(storedHmac, expectedHmac))
         //   throw new SecurityException("Keystore has been modified or corrupted");

        return envelope.Data ?? new StoreModel();
    }

    #endregion

    #region === Payload Models ===

    private sealed class KeystoreEnvelope
    {
        public int Version { get; set; } = 1;
        public string HmacHex { get; set; } = "";
        public string Disclaimer { get; set; } = "---DO NOT MODIFY THIS FILE!---";
        public StoreModel Data { get; set; } = new();
    }

    public sealed class StoreModel
    {
        public TotpSecretEntry? Totp { get; set; }
        public Dictionary<string, TotpLockoutState> LockoutPerUser { get; set; }
            = new(StringComparer.Ordinal);
        public WrappedMasterKeyEntry? MasterKey { get; set; }
    }


    public sealed class TotpSecretEntry
    {
        public string Account { get; set; } = "";
        public string SecretBase64 { get; set; } = "";
        public string EntropyBase64 { get; set; } = "";
        public long LastUsedStep { get; set; } = -1;
    }



    public sealed class TotpLockoutState
    {
        public int Failures { get; set; }
        public DateTime? LockedUntilUtc { get; set; }
    }

    public sealed class WrappedMasterKeyEntry
    {
        public int Version { get; set; }
        public DateTime CreatedUtc { get; set; }

        public byte[] MasterSalt { get; set; } = Array.Empty<byte>();
        public byte[] WrapKekSalt { get; set; } = Array.Empty<byte>();
        public byte[] GcmKekSalt { get; set; } = Array.Empty<byte>();

        public string NonceHex { get; set; } = "";
        public string CiphertextHex { get; set; } = "";
        public string TagHex { get; set; } = "";

        public string Info { get; set; } = "";
    }





    #endregion

    #region IDisposable

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        if (_disposed)
            return;

        if (disposing) _store = null!;

        _disposed = true;
    }

    #endregion
}