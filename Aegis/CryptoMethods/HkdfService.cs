using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.CryptoMethods
{
    internal class HkdfService
    {
        public static byte[] SplitKeyHkdf(byte[] passwordKek, byte[] helloKek, byte[] tpmKek, byte[]? recoveryKek = null, int outputLength = 64)
        {
            int totalLen = passwordKek.Length + helloKek.Length + tpmKek.Length + (recoveryKek?.Length ?? 0);
            byte[] combined = new byte[totalLen];

            int offset = 0;
            Buffer.BlockCopy(passwordKek, 0, combined, offset, passwordKek.Length);
            offset += passwordKek.Length;
            Buffer.BlockCopy(helloKek, 0, combined, offset, helloKek.Length);
            offset += helloKek.Length;
            Buffer.BlockCopy(tpmKek, 0, combined, offset, tpmKek.Length);
            offset += tpmKek.Length;
            if (recoveryKek != null)
                Buffer.BlockCopy(recoveryKek, 0, combined, offset, recoveryKek.Length);

            using var hkdf = new HkdfSha512(combined);
            byte[] finalKek = hkdf.DeriveKey(null, outputLength);

            CryptographicOperations.ZeroMemory(combined);
            return finalKek;
        }
    }

    // Minimal HKDF SHA256 implementation
    internal sealed class HkdfSha512 : IDisposable
    {
        private readonly HMACSHA3_512 _hmac;

        public HkdfSha512(byte[] ikm) => _hmac = new HMACSHA3_512(ikm);

        public byte[] DeriveKey(byte[]? info, int length)
        {
            byte[] okm = new byte[length];
            byte[] t = Array.Empty<byte>();
            int pos = 0;
            byte counter = 1;

            while (pos < length)
            {
                _hmac.Initialize();
                _hmac.TransformBlock(t, 0, t.Length, t, 0);
                if (info != null) _hmac.TransformBlock(info, 0, info.Length, info, 0);
                _hmac.TransformFinalBlock(new[] { counter }, 0, 1);
                t = _hmac.Hash!;
                int toCopy = Math.Min(t.Length, length - pos);
                Array.Copy(t, 0, okm, pos, toCopy);
                pos += toCopy;
                counter++;
            }
            return okm;
        }

        public void Dispose() => _hmac.Dispose();
    }
}
