using Konscious.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.CryptoMethods
{
    internal class PasswordKdfService
    {
        public static async Task<byte[]> Argon2Id(byte[] passWord, byte[] salt, int outputSize)
        {
            if (passWord == null || passWord.Length == 0)
                throw new ArgumentException("Password cannot be null or empty.", nameof(passWord));
            if (salt == null || salt.Length == 0)
                throw new ArgumentException("Salt cannot be null or empty.", nameof(salt));

            using var argon2 = new Argon2id(passWord);
            argon2.Salt = salt;
            argon2.DegreeOfParallelism = Settings.Default.Parallelism;
            argon2.Iterations = Settings.Default.Iterations;
            argon2.MemorySize = (int)Settings.Default.Memory;

            var result = await argon2.GetBytesAsync(outputSize).ConfigureAwait(false);

            return result;
        }

        internal static void Pbkdf2(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Span<byte> destination)
        {
            Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                destination,
                Settings.Default.Iterations,
                HashAlgorithmName.SHA256);
        }
    }
}
