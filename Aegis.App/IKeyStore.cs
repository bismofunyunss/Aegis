using Aegis.App.Core;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

public sealed class IKeyStore : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly string _path;
    private readonly byte[] _hmacKey;
    internal StoreModel _store;
    private bool _disposed;

    public TotpLockoutManager Lockout { get; }

    public IKeyStore(string username, string fileName = "keystore.json")
    {
        if (string.IsNullOrWhiteSpace(username))
            throw new ArgumentException(nameof(username));

        _hmacKey = SHA256.HashData(
            Encoding.UTF8.GetBytes("Aegis-Keystore-HMAC|" + username));

        string folder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Aegis",
            "Users",
            username);

        Directory.CreateDirectory(folder);
        _path = Path.Combine(folder, fileName);

        _store = LoadInternal();
        Lockout = new TotpLockoutManager(this);
    }

    // =======================
    // 🔐 KeyBlob
    // =======================
    public void SaveKeyBlob(KeyBlob blob)
    {
        if (blob == null)
            throw new ArgumentNullException(nameof(blob));

        _store.MasterKey = KeyBlobHex.From(blob);
        SaveInternal();
    }

    public KeyBlob? LoadKeyBlob()
        => _store.MasterKey?.ToKeyBlob();

    // =======================
    // 🔑 TOTP
    // =======================
    public void AddTotpSecret(string account, byte[] protectedSecret, byte[] entropy)
    {
        _store.Totp = new TotpHex
        {
            Account = account,
            SecretHex = Convert.ToHexString(protectedSecret),
            EntropyHex = Convert.ToHexString(entropy),
            LastUsedStep = -1
        };
        SaveInternal();
    }

    public byte[] LoadTotpSecret()
    {
        if (_store.Totp == null)
            throw new SecurityException("TOTP not enrolled");

        byte[] protectedSecret = Convert.FromHexString(_store.Totp.SecretHex);
        byte[] entropy = Convert.FromHexString(_store.Totp.EntropyHex);

        try
        {
            return ProtectedData.Unprotect(
                protectedSecret,
                entropy,
                DataProtectionScope.CurrentUser);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(entropy);
        }
    }

    public void UpdateTotpStep(long step)
    {
        if (_store.Totp == null)
            throw new InvalidOperationException();

        _store.Totp.LastUsedStep = step;
        SaveInternal();
    }

    // =======================
    // 🔒 Persistence
    // =======================
    private void SaveInternal()
    {
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(_store, JsonOptions);

        byte[] hmac;
        using (var h = new HMACSHA256(_hmacKey))
            hmac = h.ComputeHash(payload);

        var envelope = new KeystoreEnvelope
        {
            Version = 1,
            HmacHex = Convert.ToHexString(hmac),
            Data = _store
        };

        File.WriteAllText(
            _path,
            JsonSerializer.Serialize(envelope, JsonOptions),
            new UTF8Encoding(false));
    }

    private StoreModel LoadInternal()
    {
        if (!File.Exists(_path))
            return new StoreModel();

        var envelope = JsonSerializer.Deserialize<KeystoreEnvelope>(
            File.ReadAllText(_path))
            ?? throw new SecurityException("Invalid keystore");

        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(envelope.Data, JsonOptions);
        byte[] expected;

        using (var h = new HMACSHA256(_hmacKey))
            expected = h.ComputeHash(payload);

        if (!CryptographicOperations.FixedTimeEquals(
                expected,
                Convert.FromHexString(envelope.HmacHex)))
            throw new SecurityException("Keystore integrity failure");

        envelope.Data.Lockouts ??= new Dictionary<string, LockoutState>();
        return envelope.Data;
    }

    // =======================
    // 🔒 Lockouts
    // =======================
    public sealed class TotpLockoutManager
    {
        private const int MaxFailures = 5;
        private static readonly TimeSpan BaseDelay = TimeSpan.FromSeconds(30);

        private readonly IKeyStore _keystore;
        private readonly string _sid;

        internal TotpLockoutManager(IKeyStore keystore)
        {
            _keystore = keystore;
            _sid = WindowsIdentity.GetCurrent().User!.Value;

            if (!_keystore._store.Lockouts.ContainsKey(_sid))
                _keystore._store.Lockouts[_sid] = new LockoutState();
        }

        private LockoutState State => _keystore._store.Lockouts[_sid];

        public void EnsureNotLocked()
        {
            if (State.LockedUntilUtc is { } until && DateTime.UtcNow < until)
                throw new SecurityException($"Locked until {until:u}");
        }

        public void Fail()
        {
            State.Failures++;

            if (State.Failures >= MaxFailures)
            {
                int level = State.Failures - MaxFailures + 1;
                State.LockedUntilUtc =
                    DateTime.UtcNow + TimeSpan.FromSeconds(BaseDelay.TotalSeconds * level);
            }

            _keystore.SaveInternal();
        }

        public void Success()
        {
            _keystore._store.Lockouts[_sid] = new LockoutState();
            _keystore.SaveInternal();
        }

        public LockoutSnapshot GetSnapshot() => new()
        {
            Failures = State.Failures,
            LockedUntilUtc = State.LockedUntilUtc
        };

        public sealed class LockoutSnapshot
        {
            public int Failures { get; init; }
            public DateTime? LockedUntilUtc { get; init; }
        }
    }

    // =======================
    // Models
    // =======================
    private sealed class KeystoreEnvelope
    {
        public int Version { get; set; }
        public string HmacHex { get; set; } = "";
        public StoreModel Data { get; set; } = new();
    }

    internal sealed class StoreModel
    {
        public KeyBlobHex? MasterKey { get; set; }
        public TotpHex? Totp { get; set; }
        public Dictionary<string, LockoutState> Lockouts { get; set; } = new();
    }

    internal sealed class LockoutState
    {
        public int Failures { get; set; }
        public DateTime? LockedUntilUtc { get; set; }
    }

    internal sealed class TotpHex
    {
        public string Account { get; set; } = "";
        public string SecretHex { get; set; } = "";
        public string EntropyHex { get; set; } = "";
        public long LastUsedStep { get; set; }
    }

    // =======================
    // 🔐 KeyBlob HEX (FIXED)
    // =======================
    internal sealed class KeyBlobHex
    {
        public string LoginCiphertext { get; set; } = "";
        public string LoginNonce { get; set; } = "";
        public string LoginTag { get; set; } = "";
        public string PasswordSalt { get; set; } = "";
        public string HelloSalt { get; set; } = "";
        public string SealedKek { get; set; } = "";
        public string PolicyDigest { get; set; } = "";
        public uint[] Pcrs { get; set; } = Array.Empty<uint>();
        public ulong NvCounter { get; set; }
        public string HkdfSalt { get; set; } = "";
        public string PcrBaseLine { get; set; } = "";
        public string PrivateBlob { get; set; } = "";
        public string RecoveryCiphertext { get; set; } = "";
        public string RecoveryNonce { get; set; } = "";
        public string RecoveryTag { get; set; } = "";

        public static KeyBlobHex From(KeyBlob b) => new()
        {
            LoginCiphertext = Convert.ToHexString(b.LoginCiphertext),
            LoginNonce = Convert.ToHexString(b.LoginNonce),
            LoginTag = Convert.ToHexString(b.LoginTag),
            PasswordSalt = Convert.ToHexString(b.PasswordSalt),
            HelloSalt = Convert.ToHexString(b.HelloSalt),
            SealedKek = Convert.ToHexString(b.SealedKek),
            PolicyDigest = Convert.ToHexString(b.PolicyDigest),
            Pcrs = b.Pcrs,
            NvCounter = b.NvCounter,
            HkdfSalt = Convert.ToHexString(b.HkdfSalt),
            PcrBaseLine = Convert.ToHexString(b.PcrBaseLine),
            PrivateBlob = Convert.ToHexString(b.PrivateBlob),
            RecoveryCiphertext = Convert.ToHexString(b.RecoveryCiphertext),
            RecoveryNonce = Convert.ToHexString(b.RecoveryNonce),
            RecoveryTag = Convert.ToHexString(b.RecoveryTag)
        };

        public KeyBlob ToKeyBlob() => new()
        {
            LoginCiphertext = Convert.FromHexString(LoginCiphertext),
            LoginNonce = Convert.FromHexString(LoginNonce),
            LoginTag = Convert.FromHexString(LoginTag),
            PasswordSalt = Convert.FromHexString(PasswordSalt),
            HelloSalt = Convert.FromHexString(HelloSalt),
            SealedKek = Convert.FromHexString(SealedKek),
            PolicyDigest = Convert.FromHexString(PolicyDigest),
            Pcrs = Pcrs,
            NvCounter = NvCounter,
            HkdfSalt = Convert.FromHexString(HkdfSalt),
            PcrBaseLine = Convert.FromHexString(PcrBaseLine),
            PrivateBlob = Convert.FromHexString(PrivateBlob),
            RecoveryCiphertext = Convert.FromHexString(RecoveryCiphertext),
            RecoveryNonce = Convert.FromHexString(RecoveryNonce),
            RecoveryTag = Convert.FromHexString(RecoveryTag)
        };
    }

    // =======================
    // Dispose
    // =======================
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _store = null!;
        GC.SuppressFinalize(this);
    }
}







