using Konscious.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using Aegis.App.Session;

namespace Aegis.App.Crypto
{
    internal static class KeyDerivation
    {
        private const int RequiredSaltCount = 8;

        public static DerivedKeys DeriveKeys(FileKey fileKey, byte[][] salts)
        {
            if (fileKey == null)
                throw new ArgumentNullException(nameof(fileKey));

            if (salts == null || salts.Length != RequiredSaltCount)
                throw new ArgumentException(
                    $"Exactly {RequiredSaltCount} salts are required.",
                    nameof(salts));

            byte[] xChaCha = null!;
            byte[] threefish = null!;
            byte[] serpent = null!;
            byte[] aes = null!;
            byte[] shuffle = null!;
            byte[] threefishHmac = null!;
            byte[] serpentHmac = null!;
            byte[] aesHmac = null!;

            try
            {
                fileKey.WithKey(fileKeyBytes =>
                {
                    xChaCha = CryptoMethods.HKDF.DeriveKey(
                        fileKeyBytes, salts[0], "XChaCha20-Poly1305"u8, 32);

                    threefish = CryptoMethods.HKDF.DeriveKey(
                        fileKeyBytes, salts[1], "Threefish-1024"u8, 128);

                    serpent = CryptoMethods.HKDF.DeriveKey(
                        fileKeyBytes, salts[2], "Serpent-256-Key"u8, 32);

                    aes = CryptoMethods.HKDF.DeriveKey(
                        fileKeyBytes, salts[3], "AES-256"u8, 32);

                    shuffle = CryptoMethods.HKDF.DeriveKey(
                        fileKeyBytes, salts[4], "Shuffle-Layer"u8, 128);

                    threefishHmac = CryptoMethods.HKDF.DeriveKey(
                        fileKeyBytes, salts[5], "Threefish-1024-HMAC"u8, 64);

                    serpentHmac = CryptoMethods.HKDF.DeriveKey(
                        fileKeyBytes, salts[6], "Serpent-256-HMAC"u8, 64);

                    aesHmac = CryptoMethods.HKDF.DeriveKey(
                        fileKeyBytes, salts[7], "AES-256-HMAC"u8, 64);
                });

                return new DerivedKeys(
                    xChaCha,
                    threefish,
                    serpent,
                    aes,
                    shuffle,
                    threefishHmac,
                    serpentHmac,
                    aesHmac,
                    salts);
            }
            catch
            {
                // Zero anything that was derived before failure
                MemoryHandling.Clear(
                    xChaCha,
                    threefish,
                    serpent,
                    aes,
                    shuffle,
                    threefishHmac,
                    serpentHmac,
                    aesHmac);

                throw;
            }
        }
    }

}
