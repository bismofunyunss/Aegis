using Aegis.CryptoMethods;
using Aegis.MasterKey;
using Aegis.Tpm;
using Aegis.TpmSeal;
using Aegis.WindowsHello;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Tpm2Lib;

namespace Aegis.Registration
{
    internal class UserRegistrationService
    {
        internal async Task<MasterKeyStore> CreateUserAsync(string username, char[] password)
        {
            if (password == null || password.Length == 0)
                throw new ArgumentException("Password required");

            using var tpm = OpenTpm.OpenTPM();
            using var consumer = new PasswordConsumer(password);

            CreateKey newKey = new CreateKey();
            var srk = newKey.GetOrCreateSrk(tpm);

            // 1️⃣ Generate master key
            byte[] masterKey = newKey.GenerateMasterKey();

            try
            {
                // 2️⃣ Derive password-based KEK
                byte[] passwordSalt = RandomNumberGenerator.GetBytes(32);
                byte[] passwordKek = await PasswordKdfService.Argon2Id(
                    consumer.DeriveKey(),
                    passwordSalt,
                    64
                );

                // 3️⃣ Seal master key with password-derived auth in TPM
                var sealedHandle = newKey.CreateSealedMasterKeyWithUserAuth(
                    tpm,
                    passwordKek,
                    out byte[] tpmMasterKey,
                    out _
                );

                // 4️⃣ Derive Windows Hello KEK (prompts user PIN now)
                byte[] helloKek = WindowsHelloService.PromptHelloAndGetKek();

                // 5️⃣ Combine KEKs using HKDF split-key
                byte[] finalKek = HkdfService.SplitKeyHkdf(
                    passwordKek,
                    helloKek,
                    TpmService.DeriveKekFromPcr(tpm, sealedHandle)
                );

                // 6️⃣ AES-GCM encrypt the master key
                var (ciphertext, nonce, tag) = MasterKeyService.EncryptAesGcm(tpmMasterKey, finalKek);

                // 7️⃣ Return all metadata needed for unlock
                return new MasterKeyStore
                {
                    WrappedMasterKey = ciphertext,
                    GcmNonce = nonce,
                    GcmTag = tag,
                    PasswordSalt = passwordSalt,
                };
            }
            finally
            {
                // 8️⃣ Zero sensitive material
                CryptographicOperations.ZeroMemory(masterKey);
               // CryptographicOperations.ZeroMemory(tpmMasterKey);
               // CryptographicOperations.ZeroMemory(helloKek);
               // CryptographicOperations.ZeroMemory(passwordKek);
            }
        }



        public sealed class PasswordConsumer : IDisposable
        {
            private char[] _password;

            public PasswordConsumer(char[] password)
            {
                _password = password ?? throw new ArgumentNullException(nameof(password));
            }

            public byte[] DeriveKey()
            {
                // Convert safely when needed
                return Encoding.UTF8.GetBytes(_password);
            }

            public void Dispose()
            {
                if (_password != null)
                {
                    CryptographicOperations.ZeroMemory(
                        System.Runtime.InteropServices.MemoryMarshal.AsBytes(_password.AsSpan())
                    );
                    _password = null;
                }
            }
        }
    }
}
