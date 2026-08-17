using Konscious.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Aegis.App.Crypto
{
    internal class PasswordDerivation
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

        public static async Task<byte[]> Pbkdf2Async(byte[] password, byte[] salt, int outputSize)
        {
            if (password == null || password.Length == 0)
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            if (salt == null || salt.Length == 0)
                throw new ArgumentException("Salt cannot be null or empty.", nameof(salt));

            // PBKDF2 derivation using Settings.Default.Pbkdf2Iterations
            return await Task.Run(() =>
            {
                using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Settings.Default.PBKF2, HashAlgorithmName.SHA256);
                return pbkdf2.GetBytes(outputSize);
            }).ConfigureAwait(false);
        }
    }
}
