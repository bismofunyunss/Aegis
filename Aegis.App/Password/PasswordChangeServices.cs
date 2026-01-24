using Aegis.App.Core;
using Aegis.App.Crypto;
using Aegis.App.TPM;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using Aegis.App.PcrUtils;
using Aegis.App.Registration;

namespace Aegis.App.Password
{
    internal static class PasswordChangeService
    {
        /// <summary>
        /// Changes the user's password, re-wrapping the master key with a new KEK derived from
        /// the new password + Windows Hello, and reseals the AES-GCM login layer.
        /// Optionally rotates the recovery key.
        /// </summary>
        public static async Task ChangePasswordAsync(
            string username,
            SecureString oldPassword,
            SecureString newPassword,
            uint[] pcrs,
            bool rotateRecoveryKey = true)
        {
            if (string.IsNullOrWhiteSpace(username))
                throw new ArgumentException(nameof(username));
            if (oldPassword == null)
                throw new ArgumentNullException(nameof(oldPassword));
            if (newPassword == null)
                throw new ArgumentNullException(nameof(newPassword));

            using var store = new IKeyStore(username);
            var blob = store.LoadKeyBlob()
                       ?? throw new SecurityException("No master key available");

            // Initialize TPM service for unsealing
            var tpmSeal = new TpmSealService(OpenTpm.CreateTpm2(), PcrSelection.Pcrs);

            // Prepare Windows Hello key
            var helloKey = await WindowsHelloManager.CreateHelloKeyAsync(username);

            // Unseal current master key
            using var cryptoSession = await MasterKeyManager.LoginAndUnwrapMasterKeyAsync(
                tpmSeal,
                SecureStringUtil.ToBytes.ToUtf8Bytes(oldPassword),
                username, blob, pcrs
            );

            // Create a copy of the master key safely
            byte[] tempKey = new byte[cryptoSession.MasterKey.Length];
            cryptoSession.MasterKey.CopyKeyTo(tempKey);

            try
            {
                // --- Derive new KEKs from new password + Windows Hello ---
                byte[] newPasswordKek = await PasswordDerivation.Argon2Id(
                    SecureStringUtil.ToBytes.ToUtf8Bytes(newPassword),
                    blob.PasswordSalt,
                    32
                );

                byte[] helloKek = WindowsHelloManager.DeriveHelloKEK(
                    await WindowsHelloManager.GetHelloPublicKeyHashAsync(helloKey),
                    blob.HelloSalt
                );

                byte[] newMasterKek = CryptoMethods.HKDF.DeriveKey(
                    helloKek.Concat(newPasswordKek).ToArray(),
                    blob.HkdfSalt,
                    "Master-Key-Kek"u8.ToArray(),
                    32
                );

                // --- Re-wrap the master key with new KEK ---
                byte[] rewrappedMasterKey = KeyWrap.AesKeyWrap(newMasterKek, tempKey);

                // --- Re-seal AES-GCM login layer ---
                byte[] gcmSalt = RandomNumberGenerator.GetBytes(128);
                byte[] loginNonce = RandomNumberGenerator.GetBytes(12);
                byte[] loginTag = new byte[16];
                byte[] loginCiphertext = new byte[rewrappedMasterKey.Length];

                using (var aesGcm = new AesGcm(CryptoMethods.HKDF.DeriveKey(
                             newMasterKek, gcmSalt, "Aes-Gcm-Kek"u8.ToArray(), 32), 16))
                {
                    aesGcm.Encrypt(loginNonce, rewrappedMasterKey, loginCiphertext, loginTag);
                }

                // --- Optionally rotate recovery key ---
                byte[]? recoveryKey = null;
                byte[]? recoveryNonce = null;
                byte[]? recoveryTag = null;
                byte[]? recoveryCiphertext = null;

                if (rotateRecoveryKey)
                {
                    recoveryKey = RandomNumberGenerator.GetBytes(32);
                    recoveryNonce = RandomNumberGenerator.GetBytes(12);
                    recoveryTag = new byte[16];
                    recoveryCiphertext = new byte[tempKey.Length];

                    using var aesGcm = new AesGcm(recoveryKey, 16);
                    aesGcm.Encrypt(recoveryNonce, tempKey, recoveryCiphertext, recoveryTag);
                }

                // --- Update KeyBlob with new wrapped key, AES-GCM layer, and optionally recovery key ---
                blob.LoginCiphertext = loginCiphertext;
                blob.LoginNonce = loginNonce;
                blob.LoginTag = loginTag;
                blob.GcmSalt = gcmSalt;

                if (rotateRecoveryKey && recoveryKey != null)
                {
                    blob.RecoveryCiphertext = recoveryCiphertext!;
                    blob.RecoveryNonce = recoveryNonce!;
                    blob.RecoveryTag = recoveryTag!;
                }

                RecoveryKey page = new RecoveryKey(recoveryKey);
                page.ShowDialog();

                // --- Persist KeyBlob ---
                store.SaveKeyBlob(blob);
            }
            finally
            {
                // Zero sensitive buffers
                CryptographicOperations.ZeroMemory(tempKey);
            }
        }
    }

}

