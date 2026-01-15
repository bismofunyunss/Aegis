using Konscious.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Aegis.App.Crypto
{
    public static class KeyDerivation
    {
        public static DerivedKeys DeriveKeys(byte[] fileKey, byte[][] salts)
        {
            var xChaCha = CryptoMethods.HKDF.DeriveKey(
                fileKey, salts[0], "XChaCha20-Poly1305"u8.ToArray(), 32);

            var threefish = CryptoMethods.HKDF.DeriveKey(
                fileKey, salts[1], "Threefish-1024"u8.ToArray(), 128);

            var serpent = CryptoMethods.HKDF.DeriveKey(
                fileKey, salts[2], "Serpent-256-Key"u8.ToArray(), 32);

            var aes = CryptoMethods.HKDF.DeriveKey(
                fileKey, salts[3], "AES-256"u8.ToArray(), 32);

            var shuffle = CryptoMethods.HKDF.DeriveKey(
                fileKey, salts[4], "Shuffle-Layer"u8.ToArray(), 128);

            var threefishHmac = CryptoMethods.HKDF.DeriveKey(
                fileKey, salts[5], "Threefish-1024-HMAC"u8.ToArray(), 64);

            var serpentHmac = CryptoMethods.HKDF.DeriveKey(
                fileKey, salts[6], "Serpent-256-HMAC"u8.ToArray(), 64);

            var aesHmac = CryptoMethods.HKDF.DeriveKey(
                fileKey, salts[7], "AES-256-HMAC"u8.ToArray(), 64);

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

        public static byte[] DeriveHelloKEK(byte[] pubKeyHash, byte[] salt)
     => CryptoMethods.HKDF.DeriveKey(
         pubKeyHash,
         salt,
         Encoding.UTF8.GetBytes("Aegis-HELLO-KEK"),
         64
     );
    }
    }
