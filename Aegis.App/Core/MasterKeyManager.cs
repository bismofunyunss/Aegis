using Aegis.App.Crypto;
using Aegis.App.PcrUtils;
using Aegis.App.TPM;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using Windows.Security.Credentials;

namespace Aegis.App.Core
{
    public sealed class MasterKeyManager
    {
        public static async Task<KeyBlob?> CreateAndWrapMasterKeyAsync(
       TpmSealService tpm,
       KeyCredential helloKey,
       byte[] userPassword,
       uint[] pcrs,
       byte[]? recoveryKey = null)
        {
            if (tpm == null) throw new ArgumentNullException(nameof(tpm));
            if (helloKey == null) throw new ArgumentNullException(nameof(helloKey));
            if (userPassword == null || userPassword.Length == 0) throw new ArgumentException("Password required", nameof(userPassword));

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

                kek = CryptoMethods.HKDF.DeriveKey(helloKek.Concat(passwordKek).ToArray(), salt, "Master-Key-Kek"u8.ToArray(), 32);
                var wrappedPassword = Keys.AesKeyWrap(kek, masterKey);

                var srk = tpm.CreateOrLoadSrk();
                var sealedData = tpm.Seal(kek, srk);

                using SecureMasterKey key = new SecureMasterKey(masterKey);
                var pcrValues = PcrUtilities.ReadPcrs(OpenTpm.CreateTpm2(), pcrs);
                var baseline = PcrUtilities.SerializeBaseline(pcrValues);
                var encryptedBaseline = PcrUtilities.EncryptBaseline(key, baseline);



                // 4️⃣ Optional recovery key (AES-GCM)
                byte[] ciphertext = wrappedPassword;
                byte[] tag = Array.Empty<byte>();
                byte[] nonce = Array.Empty<byte>();

                if (recoveryKey != null)
                {
                    nonce = RandomNumberGenerator.GetBytes(12);
                    tag = new byte[16];
                    ciphertext = new byte[wrappedPassword.Length];

                    using var aesGcm = new AesGcm(recoveryKey, 16);
                    aesGcm.Encrypt(nonce, wrappedPassword, ciphertext, tag);
                }

                // 5️⃣ Return fully populated KeyBlob
                return new KeyBlob
                {
                    Ciphertext = ciphertext,
                    Tag = tag,
                    Nonce = nonce,
                    PasswordSalt = passwordSalt,
                    HelloSalt = helloSalt,
                    SealedKek = sealedData.PrivateBlob,
                    PolicyDigest = sealedData.PolicyDigest,
                    Pcrs = sealedData.Pcrs,
                    NvCounter = sealedData.NvCounterValue,
                    HkdfSalt = salt,
                    PcrBaseLine = encryptedBaseline,
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
        /// Unseals the master key from the TPM, verifies PCR integrity, and optionally unwraps via recovery key.
        /// </summary>
        /// <param name="tpm">TPM instance</param>
        /// <param name="keyBlob">KeyBlob retrieved from keystore</param>
        /// <param name="helloKey">Windows Hello credential</param>
        /// <param name="userPassword">User password</param>
        /// <param name="recoveryKey">Optional recovery key</param>
        /// <returns>SecureMasterKey instance if successful</returns>
        public static async Task<SecureMasterKey?> UnsealMasterKeyAsync(
            TpmSealService tpm,
            KeyBlob keyBlob,
            KeyCredential helloKey,
            byte[] userPassword,
            byte[]? recoveryKey = null)
        {
            if (tpm == null) throw new ArgumentNullException(nameof(tpm));
            if (keyBlob == null) throw new ArgumentNullException(nameof(keyBlob));
            if (helloKey == null) throw new ArgumentNullException(nameof(helloKey));
            if (userPassword == null || userPassword.Length == 0)
                throw new ArgumentException("Password required", nameof(userPassword));

            byte[]? helloKek = null;
            byte[]? passwordKek = null;
            byte[]? kek = null;
            byte[]? wrappedMasterKey = null;
            byte[]? masterKey = null;

            try
            {
                // 1️⃣ Optional recovery key takes precedence
                if (recoveryKey != null && keyBlob.Ciphertext != null && keyBlob.Tag != null && keyBlob.Nonce != null)
                {
                    wrappedMasterKey = new byte[keyBlob.Ciphertext.Length];
                    using var aesGcm = new AesGcm(recoveryKey);
                    aesGcm.Decrypt(keyBlob.Nonce, keyBlob.Ciphertext, keyBlob.Tag, wrappedMasterKey);
                }
                else
                {
                    wrappedMasterKey = keyBlob.Ciphertext;
                }

                if (wrappedMasterKey == null)
                    throw new SecurityException("Missing master key ciphertext");

                // 2️⃣ Derive KEK from Windows Hello + password
                helloKek = WindowsHelloManager.DeriveHelloKEK(
                    await WindowsHelloManager.GetHelloPublicKeyHashAsync(helloKey),
                    keyBlob.HelloSalt);

                passwordKek = await PasswordDerivation.Argon2Id(userPassword, keyBlob.PasswordSalt, 32);

                kek = CryptoMethods.HKDF.DeriveKey(
                    helloKek.Concat(passwordKek).ToArray(),
                    keyBlob.HkdfSalt,
                    "Master-Key-Kek"u8.ToArray(),
                    32);

                // 3️⃣ Unwrap master key
                masterKey = Keys.AesKeyUnwrap(kek, wrappedMasterKey);

                // 4️⃣ TPM tamper check
                SystemSecurity.EnableKernelDmaProtection();
                SystemSecurity.EnsureSecurityEnabled();

                if (!TpmProtection.IsTpmOperational(OpenTpm.CreateTpm2()))
                    throw new SecurityException("TPM not operational");

                // Decrypt PCR baseline
                using var secureMasterKey = new SecureMasterKey(masterKey);
                var baseline = PcrUtilities.DecryptBaseline(secureMasterKey, keyBlob.PcrBaseLine!);

                var baselineDict = PcrUtilities.DeserializeBaseline(baseline);



                // Verify PCRs
                TpmProtection.EnforceTpmIntegrity(
                    OpenTpm.CreateTpm2(),
                    keyBlob.Pcrs!,
                    baselineDict
                );

                // 5️⃣ Return master key securely
                return secureMasterKey;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(masterKey);
                CryptographicOperations.ZeroMemory(kek);
                CryptographicOperations.ZeroMemory(helloKek);
                CryptographicOperations.ZeroMemory(passwordKek);
            }
        }

        public static async Task<byte[]> RecoverAsync(
        KeyBlob blob,
        string userPassword,
        CngKey helloKey,
        byte[] recoveryKey)
        {
            return null;
        }
}

}
