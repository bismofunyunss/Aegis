using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Aegis.App.Crypto
{
    internal static class CryptoMethods
    {
        internal static byte[] Rng(int len)
        {
            byte[] bytes = new byte[len];
            RandomNumberGenerator.Fill(bytes);
            return bytes;
        }

        internal static class HKDF
        {
            public static byte[] DeriveKey(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info, int length)
            {
                if (ikm == null || ikm.Length == 0) throw new ArgumentException("IKM is null", nameof(ikm));
                if (info == null) throw new ArgumentNullException(nameof(info));
                if (length <= 0) throw new ArgumentOutOfRangeException(nameof(length));

                // RFC 5869: If salt is null or empty, use zeros of HashLen
                if (salt == null || salt.Length == 0)
                    salt = new byte[64]; // SHA3-512 output length

                // Extract
                byte[] prk;
                using (var hmac = new HMACSHA3_512(salt.ToArray())) // Requires a SHA3-512 HMAC implementation
                {
                    prk = hmac.ComputeHash(ikm.ToArray());
                }

                // Expand
                byte[] okm = new byte[length];
                byte[] previous = Array.Empty<byte>();
                byte counter = 1;
                int offset = 0;

                using (var hmac = new HMACSHA3_512(prk))
                {
                    while (offset < length)
                    {
                        hmac.Initialize();

                        hmac.TransformBlock(previous, 0, previous.Length, null, 0);
                        hmac.TransformBlock(info.ToArray(), 0, info.Length, null, 0);
                        hmac.TransformFinalBlock(new[] { counter }, 0, 1);

                        byte[] hash = hmac.Hash!;
                        int toCopy = Math.Min(hash.Length, length - offset);
                        Buffer.BlockCopy(hash, 0, okm, offset, toCopy);

                        MemoryHandling.Clear(previous);
                        previous = hash;
                        offset += toCopy;
                        counter++;
                    }
                }

                MemoryHandling.Clear(prk);
                MemoryHandling.Clear(previous);
                return okm;
            }
        }

        public static class SaltGenerator
        {
            // Generate salts for keys and hmac keys
            public static byte[][] CreateSalts(int saltLength = 128)
            {
                byte[][] salts = new byte[8][];

                for (int i = 0; i < 8; i++)
                {
                    salts[i] = RandomNumberGenerator.GetBytes(saltLength);
                }

                return salts;
            }
        }
}
}
