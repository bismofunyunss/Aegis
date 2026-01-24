using Aegis.App.Crypto;
using Aegis.App.PcrUtils;
using Aegis.App.Registration;
using Aegis.App.TPM;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using Tpm2Lib;
using Windows.Security.Credentials;
using Aegis.App.Session;
using static Aegis.App.TPM.TpmSealService;

namespace Aegis.App.Core;

public sealed class MasterKeyManager
{
    public static async Task<KeyBlob> CreateAndWrapMasterKeyAsync(
      TpmSealService tpm,
      byte[] userPassword,
      uint[] pcrs,
      string username,
      byte[] recoveryKey)
    {
        byte[] masterKey = RandomNumberGenerator.GetBytes(64);
        byte[] tpmKek = RandomNumberGenerator.GetBytes(32);

        byte[] passwordSalt = RandomNumberGenerator.GetBytes(128);
        byte[] hkdfSalt = RandomNumberGenerator.GetBytes(128);
        byte[] gcmSalt = RandomNumberGenerator.GetBytes(128);

        // 🔐 Password KEK
        byte[] passwordKek =
            await PasswordDerivation.Argon2Id(userPassword, passwordSalt, 32);

        // 🔐 Final KEK = TPM + Password
        byte[] finalKek = CryptoMethods.HKDF.DeriveKey(
            tpmKek.Concat(passwordKek).ToArray(),
            hkdfSalt,
            "Master-KEK"u8.ToArray(),
            32);

        // 🔐 Wrap master key
        byte[] wrappedMaster = KeyWrap.AesKeyWrap(finalKek, masterKey);

        // 🔐 Login envelope
        byte[] loginNonce = RandomNumberGenerator.GetBytes(12);
        byte[] loginTag = new byte[16];
        byte[] loginCiphertext = new byte[wrappedMaster.Length];

        byte[] gcmKek = CryptoMethods.HKDF.DeriveKey(
            finalKek, gcmSalt, "GCM-KEK"u8.ToArray(), 32);

        using (var gcm = new AesGcm(gcmKek, 16))
            gcm.Encrypt(loginNonce, wrappedMaster, loginCiphertext, loginTag);

        // 🔐 TPM seal KEK
        var counter = new TpmNvCounter(OpenTpm.CreateTpm2(), username, pcrs);
        var srk = tpm.CreateOrLoadSrk();
        var blob = tpm.Seal(tpmKek, srk, counter);

    // 🔐 Recovery envelope
    byte[] recoveryNonce = RandomNumberGenerator.GetBytes(12);
    byte[] recoveryTag = new byte[16];
    byte[] recoveryCiphertext = new byte[masterKey.Length];

    using (var gcm = new AesGcm(recoveryKey, 16))
        gcm.Encrypt(
            recoveryNonce,
            masterKey,
            recoveryCiphertext,
            recoveryTag,
            BitConverter.GetBytes(counter.GetNvCounter()));

    return new KeyBlob
    {
        SealedKek = blob.PrivateBlob,
        PublicBlob = blob.PublicBlob,
        PolicyDigest = blob.PolicyDigest,
        Pcrs = blob.Pcrs,
        NvCounter = counter.GetNvCounter(),

        PasswordSalt = passwordSalt,
        HkdfSalt = hkdfSalt,
        GcmSalt = gcmSalt,

        LoginCiphertext = loginCiphertext,
        LoginNonce = loginNonce,
        LoginTag = loginTag,

        RecoveryCiphertext = recoveryCiphertext,
        RecoveryNonce = recoveryNonce,
        RecoveryTag = recoveryTag
    };
}


    /// <summary>
    ///     Unseals the master key from the TPM, verifies PCR integrity, and optionally unwraps via recovery key.
    /// </summary>
    /// <param name="tpm">TPM instance</param>
    /// <param name="keyBlob">KeyBlob retrieved from keystore</param>
    /// <param name="helloKey">Windows Hello credential</param>
    /// <param name="userPassword">User password</param>
    /// <param name="recoveryKey">Optional recovery key</param>
    /// <returns>SecureMasterKey instance if successful</returns>
    public static async Task<Session.Session.CryptoSession> LoginAndUnwrapMasterKeyAsync(
        TpmSealService tpm,
        byte[] userPassword,
        string username,
        KeyBlob blob,
        uint[] pcrs)
    {
        // 🔐 Password KEK
        byte[] passwordKek =
            await PasswordDerivation.Argon2Id(userPassword, blob.PasswordSalt, 32);

        // 🔐 TPM unseal (Hello authorizes this implicitly)
        var srk = tpm.CreateOrLoadSrk();
        var counter = new TpmNvCounter(OpenTpm.CreateTpm2(), username, pcrs);

        byte[] tpmKek = tpm.Unseal(new KeyBlob
        {
            PrivateBlob = blob.SealedKek,
            PublicBlob = blob.PublicBlob,
            PolicyDigest = blob.PolicyDigest,
            Pcrs = blob.Pcrs,
            NvCounter = blob.NvCounter
        }, srk, counter);

        // 🔐 Final KEK
        byte[] finalKek = CryptoMethods.HKDF.DeriveKey(
            tpmKek.Concat(passwordKek).ToArray(),
            blob.HkdfSalt,
            "Master-KEK"u8.ToArray(),
            32);

        // 🔐 Login unwrap
        byte[] wrappedMaster = new byte[blob.LoginCiphertext.Length];
        byte[] gcmKek = CryptoMethods.HKDF.DeriveKey(
            finalKek, blob.GcmSalt, "GCM-KEK"u8.ToArray(), 32);

        using (var gcm = new AesGcm(gcmKek, 16))
            gcm.Decrypt(
                blob.LoginNonce,
                blob.LoginCiphertext,
                blob.LoginTag,
                wrappedMaster);

        byte[] masterKey = KeyWrap.AesKeyUnwrap(finalKek, wrappedMaster);
        var secureKey = new SecureMasterKey(masterKey);

        return new Session.Session.CryptoSession(secureKey);
    }


    public static SecureRecoveryKey RecoverAndRotateRecoveryKey(
        IntPtr pinnedRecoveryKey,
        int keyLength,
        KeyBlob blob,
        TpmNvCounter counter,
        out SecureMasterKey masterKey)
    {
        if (pinnedRecoveryKey == IntPtr.Zero)
            throw new ArgumentNullException(nameof(pinnedRecoveryKey));
        if (keyLength <= 0)
            throw new ArgumentOutOfRangeException(nameof(keyLength));
        if (blob == null)
            throw new ArgumentNullException(nameof(blob));
        if (counter == null)
            throw new ArgumentNullException(nameof(counter));

        // 1️⃣ Enforce rollback
        counter.EnforceRollback(blob);

        byte[] decryptedMaster = new byte[blob.RecoveryCiphertext.Length];
        byte[] recoveryKeyTemp = new byte[keyLength];
        try
        {
            // 2️⃣ Copy recovery key
            Marshal.Copy(pinnedRecoveryKey, recoveryKeyTemp, 0, keyLength);

            // 3️⃣ Decrypt master key with AES-GCM
            var aad = BitConverter.GetBytes(blob.NvCounter);
            using (var aesGcm = new AesGcm(recoveryKeyTemp, 16))
            {
                aesGcm.Decrypt(blob.RecoveryNonce, blob.RecoveryCiphertext, blob.RecoveryTag, decryptedMaster, aad);
            }

            // Wrap the decrypted master key in a secure object
            masterKey = new SecureMasterKey(decryptedMaster);

            // 4️⃣ Generate a new recovery key and rotate
            var newRecoveryKey = RotateRecoveryKey(counter, blob, masterKey);

            // ✅ NV counter increment and blob update handled inside RotateRecoveryKey
            return newRecoveryKey;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(recoveryKeyTemp);
            CryptographicOperations.ZeroMemory(decryptedMaster); // masterKey now holds the secure copy
        }
    }


    public static SecureRecoveryKey RotateRecoveryKey(
        TpmNvCounter counter,
        KeyBlob blob,
        SecureMasterKey masterKey)
    {
        if (counter == null) throw new ArgumentNullException(nameof(counter));
        if (blob == null) throw new ArgumentNullException(nameof(blob));
        if (masterKey == null) throw new ArgumentNullException(nameof(masterKey));

        // Enforce rollback before rotation
        counter.EnforceRollback(blob);

        // 1️⃣ Generate new random recovery key
        byte[] newRecoveryKey = RandomNumberGenerator.GetBytes(32);

        // 2️⃣ Encrypt master key
        byte[] newRecoveryNonce = RandomNumberGenerator.GetBytes(12);
        byte[] newRecoveryTag = new byte[16];
        byte[] newRecoveryCiphertext = new byte[masterKey.Length];

        var aad = BitConverter.GetBytes(counter.GetNvCounter());
        var masterKeyBytes = masterKey.GetKeySpan();

        using (var aesGcm = new AesGcm(newRecoveryKey, 16))
        {
            aesGcm.Encrypt(newRecoveryNonce, masterKeyBytes, newRecoveryCiphertext, newRecoveryTag, aad);
        }

        // 3️⃣ Increment NV counter **once** and update blob
        ulong newCounterValue = counter.IncrementCounter();

        // 4️⃣ Zero old ciphertext before overwriting
        if (blob.RecoveryCiphertext != null)
            CryptographicOperations.ZeroMemory(blob.RecoveryCiphertext);

        blob.RecoveryCiphertext = newRecoveryCiphertext;
        blob.RecoveryNonce = newRecoveryNonce;
        blob.RecoveryTag = newRecoveryTag;
        blob.NvCounter = newCounterValue;

        // Return new recovery key to user
        return new SecureRecoveryKey(newRecoveryKey);
    }
}