using Aegis.App.Crypto;
using Aegis.App.PcrUtils;
using Aegis.App.TPM;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Windows.Security.Credentials;
using Aegis.App.Registration;
using static Aegis.App.TPM.TpmSealService;

namespace Aegis.App.Core;

public sealed class MasterKeyManager
{
    public static async Task<KeyBlob?> CreateAndWrapMasterKeyAsync(
        TpmSealService tpm,
        KeyCredential helloKey,
        byte[] userPassword,
        uint[] pcrs,
        string username,
        byte[]? recoveryKey)
    {
        if (tpm == null) throw new ArgumentNullException(nameof(tpm));
        if (helloKey == null) throw new ArgumentNullException(nameof(helloKey));
        if (userPassword == null || userPassword.Length == 0)
            throw new ArgumentException("Password required", nameof(userPassword));

        byte[]? masterKey = null;
        byte[]? helloKek = null;
        byte[]? passwordKek = null;
        byte[]? kek = null;

        try
        {
            // 1️⃣ Create master key and seal to TPM
            masterKey = RandomNumberGenerator.GetBytes(64);

            var salt = RandomNumberGenerator.GetBytes(128);

            // 2️⃣ Windows Hello KEK
            var helloSalt = RandomNumberGenerator.GetBytes(128);
            var helloHash = await WindowsHelloManager.GetHelloPublicKeyHashAsync(helloKey);
            helloKek = WindowsHelloManager.DeriveHelloKEK(helloHash, helloSalt);

            // 3️⃣ User password KEK (Argon2id)
            var passwordSalt = RandomNumberGenerator.GetBytes(128);
            passwordKek = await PasswordDerivation.Argon2Id(userPassword, passwordSalt, 32);

            kek = CryptoMethods.HKDF.DeriveKey(helloKek.Concat(passwordKek).ToArray(), salt,
                "Master-Key-Kek"u8.ToArray(), 32);
            var wrappedPassword = KeyWrap.AesKeyWrap(kek, masterKey);

            var gcmSalt = RandomNumberGenerator.GetBytes(128);
            var gcmKek = CryptoMethods.HKDF.DeriveKey(kek, gcmSalt, "Aes-Gcm-Kek"u8.ToArray(), 32);

            var loginNonce = RandomNumberGenerator.GetBytes(12);
            var loginTag = new byte[16];
            var loginCiphertext = new byte[wrappedPassword.Length];

            using (var aesGcm = new AesGcm(gcmKek, 16))
            {
                aesGcm.Encrypt(
                    loginNonce,
                    wrappedPassword,
                    loginCiphertext,
                    loginTag);
            }

            // 4️⃣ Recovery envelope (ALWAYS created)
            var recoveryNonce = RandomNumberGenerator.GetBytes(12);
            var recoveryTag = new byte[16];
            var recoveryCiphertext = new byte[masterKey.Length];

            TpmNvCounter counter = new TpmNvCounter(OpenTpm.CreateTpm2(), username, pcrs);
            var srk = tpm.CreateOrLoadSrk();
            var sealedData = tpm.Seal(kek, srk, counter);

            // Use the NV counter *after seal* as AAD for recovery encryption
            var aad = BitConverter.GetBytes(counter.GetNvCounter());

            using (var aesGcm = new AesGcm(recoveryKey, 16))
            {
                aesGcm.Encrypt(
                    recoveryNonce,
                    masterKey,
                    recoveryCiphertext,
                    recoveryTag,
                    aad
                );
            }


            using var key = new SecureMasterKey(masterKey);
            var pcrValues = PcrUtilities.ReadPcrs(OpenTpm.CreateTpm2(), pcrs);
            var baseline = PcrUtilities.SerializeBaseline(pcrValues);
            var encryptedBaseline = PcrUtilities.EncryptBaseline(key, baseline);


            // 5️⃣ Return fully populated KeyBlob
            return new KeyBlob
            {
                RecoveryCiphertext = recoveryCiphertext,
                RecoveryTag = recoveryTag,
                RecoveryNonce = recoveryNonce,
                PasswordSalt = passwordSalt,
                HelloSalt = helloSalt,
                SealedKek = sealedData.PrivateBlob,
                PolicyDigest = sealedData.PolicyDigest,
                Pcrs = sealedData.Pcrs,
                NvCounter = counter.GetNvCounter(),
                HkdfSalt = salt,
                PcrBaseLine = encryptedBaseline,
                LoginCiphertext = loginCiphertext,
                LoginNonce = loginNonce,
                LoginTag = loginTag,
                GcmSalt = gcmSalt,
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
            CryptographicOperations.ZeroMemory(masterKey);
            CryptographicOperations.ZeroMemory(helloKek);
            CryptographicOperations.ZeroMemory(passwordKek);
        }
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
    public static async Task<SecureMasterKey> LoginAndUnwrapMasterKeyAsync(
        TpmSealService tpm,
        KeyCredential helloKey,
        byte[] userPassword,
        string username,
        KeyBlob blob,
        uint[] pcrs)
    {
        if (tpm == null) throw new ArgumentNullException(nameof(tpm));
        if (helloKey == null) throw new ArgumentNullException(nameof(helloKey));
        if (userPassword == null || userPassword.Length == 0)
            throw new ArgumentException("Password required", nameof(userPassword));
        if (blob == null) throw new ArgumentNullException(nameof(blob));

        byte[]? helloKek = null;
        byte[]? passwordKek = null;
        byte[]? kek = null;
        byte[]? gcmKek = null;
        byte[]? wrappedMasterKey = null;
        byte[]? masterKey = null;

        try
        {
            // 1️⃣ Windows Hello KEK (TPM-backed)
            var helloHash = await WindowsHelloManager.GetHelloPublicKeyHashAsync(helloKey);
            helloKek = WindowsHelloManager.DeriveHelloKEK(helloHash, blob.HelloSalt);

            // 2️⃣ User password KEK (Argon2id)
            passwordKek = await PasswordDerivation.Argon2Id(userPassword, blob.PasswordSalt, 32);

            // 3️⃣ Master KEK (HKDF from Hello + Password)
            kek = CryptoMethods.HKDF.DeriveKey(
                helloKek.Concat(passwordKek).ToArray(),
                blob.HkdfSalt,
                "Master-Key-Kek"u8,
                32);

            // 4️⃣ TPM unseal (PCR + NV enforced)
            var srk = tpm.CreateOrLoadSrk();

            var metadata = new KeyBlob()
            {
                PrivateBlob = blob.SealedKek,
                PolicyDigest = blob.PolicyDigest,
                Pcrs = blob.Pcrs,
                NvCounter = blob.NvCounter
            };

            TpmNvCounter counter = new TpmNvCounter(OpenTpm.CreateTpm2(), username, pcrs);
            var unsealedKek = tpm.Unseal(metadata, srk, counter);

            if (!CryptographicOperations.FixedTimeEquals(kek, unsealedKek))
                throw new SecurityException("TPM KEK mismatch");

            // 5️⃣ AES-GCM login KEK
            gcmKek = CryptoMethods.HKDF.DeriveKey(
                kek,
                blob.GcmSalt,
                "Aes-Gcm-Kek"u8,
                32);

            // 6️⃣ Decrypt wrapped master key (AES-GCM)
            wrappedMasterKey = new byte[blob.LoginCiphertext.Length];
            using (var aesGcm = new AesGcm(gcmKek, 16))
            {
                aesGcm.Decrypt(
                    blob.LoginNonce,
                    blob.LoginCiphertext,
                    blob.LoginTag,
                    wrappedMasterKey);
            }

            // 7️⃣ AES Key Unwrap → master key
            masterKey = KeyWrap.AesKeyUnwrap(kek, wrappedMasterKey);

            // 8️⃣ Verify PCR baseline
            using var secure = new SecureMasterKey(masterKey);
            var currentPcrs = PcrUtilities.ReadPcrs(OpenTpm.CreateTpm2(), pcrs);
            var serialized = PcrUtilities.SerializeBaseline(currentPcrs);
            var baseline = PcrUtilities.DecryptBaseline(secure, blob.PcrBaseLine);

            if (!CryptographicOperations.FixedTimeEquals(serialized, baseline))
                throw new SecurityException("PCR baseline mismatch");

            // ✅ Success
            return secure;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(helloKek);
            CryptographicOperations.ZeroMemory(passwordKek);
            CryptographicOperations.ZeroMemory(kek);
            CryptographicOperations.ZeroMemory(gcmKek);
            CryptographicOperations.ZeroMemory(wrappedMasterKey);
            CryptographicOperations.ZeroMemory(masterKey);
        }
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