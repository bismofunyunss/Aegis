using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Aegis.CryptoMethods;
using Aegis.TpmSeal;
using Aegis.WindowsHello;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Tpm2Lib;

namespace Aegis.MasterKey
{

    internal static class MasterKeyService
    {
        // AES-GCM encrypt
        public static (byte[] ciphertext, byte[] nonce, byte[] tag) EncryptAesGcm(byte[] data, byte[] key)
        {
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] ciphertext = new byte[data.Length];
            byte[] tag = new byte[16];

            using var aes = new AesGcm(key);
            aes.Encrypt(nonce, data, ciphertext, tag);
            return (ciphertext, nonce, tag);
        }

            /// <summary>
            /// AES-GCM decryption.
            /// </summary>
            public static byte[] DecryptAesGcm(byte[] ciphertext, byte[] key, byte[] nonce, byte[] tag)
            {
                if (key == null || key.Length != 32)
                    throw new ArgumentException("Key must be 256-bit for AES-GCM.");

                byte[] plaintext = new byte[ciphertext.Length];

                using var aes = new AesGcm(key);
                try
                {
                    aes.Decrypt(nonce, ciphertext, tag, plaintext);
                }
                catch (CryptographicException)
                {
                    throw new InvalidOperationException("AES-GCM authentication failed. Data may be corrupted or key is invalid.");
                }

                return plaintext;
            }
    }

    // JSON storage class
    internal class MasterKeyStore
    {
        public byte[] WrappedMasterKey { get; set; } = Array.Empty<byte>();
        public byte[] GcmNonce { get; set; } = Array.Empty<byte>();
        public byte[] GcmTag { get; set; } = Array.Empty<byte>();
        public byte[] PasswordSalt { get; set; } = Array.Empty<byte>();
        public byte[] RecoverySalt { get; set; } = Array.Empty<byte>();
        public string PasswordHash { get; set; } = string.Empty;
    }

}
