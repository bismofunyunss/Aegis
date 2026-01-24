using Aegis.App.Core;
using Aegis.App.Crypto;
using Aegis.App.Global;
using Aegis.App.Helpers;
using Aegis.App.Session;
using Aegis.App.Vault.VaultEntry;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static Aegis.App.Pages.VaultPage;

namespace Aegis.App.Vault.VaultLoader
{
    internal class LoadVault
    {
        public static class VaultConstants
        {
            public static readonly byte[] Signature =
                Encoding.ASCII.GetBytes("AEGIS_VAULT_V1");

            public const int SaltSize = 128;
        }

        public static async Task LoadVaultOnLoginAsync(string username, SecureMasterKey key)
        {
            var vaultPath = Path.Combine(
                IO.Folders.GetUserFolder(username),
                "vault.dat"
            );

            if (!File.Exists(vaultPath))
            {
                VaultState.Items.Clear();
                VaultState.IsDirty = false;
                return;
            }

            using var vaultFile = new FileStream(
                vaultPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read
            );

            await DecryptAndLoadVaultAsync(vaultFile, key);
        }

        private static async Task DecryptAndLoadVaultAsync(Stream encryptedVault, SecureMasterKey key)
        {
            // ---- Read signature ----
            var sig = await HelperMethods.ReadExactAsync(encryptedVault, VaultConstants.Signature.Length);

            if (!sig.SequenceEqual(VaultConstants.Signature))
                throw new CryptographicException("Invalid vault signature.");

            // ---- Read file key salt ----
            var fileKeySalt = await HelperMethods.ReadExactAsync(encryptedVault, VaultConstants.SaltSize);


            // Get active session (must already be logged in)
            var session = CryptoSessionManager.Current;
            if (session == null || !session.IsMasterKeyInitialized)
                throw new SecurityException("No active crypto session.");

            // Derive file key
            using var fileKey = new FileKey(
                fileKeySalt,
                "Vault-File-Key"u8,
                64);

            var Keys = KeyDerivation.DeriveKeys(fileKey, CryptoMethods.SaltGenerator.CreateSalts(128));

            try
            {
                using var decryptedStream = new MemoryStream();

                // ---- Decrypt payload ----
                await ParallelCtrEncryptor.SecureParallelEncryptor.DecryptV3(
                     encryptedVault,
                     decryptedStream,
                     Keys
                );

                decryptedStream.Position = 0;

                // ---- Deserialize into DataGrid ----
                DeserializeVault(decryptedStream);

                VaultState.IsDirty = false;
            }
            finally
            {
                fileKey.Dispose();
                MemoryHandling.Clear(fileKeySalt);
            }
        }

        private static void DeserializeVault(Stream plaintext)
        {
            using var reader = new BinaryReader(plaintext, Encoding.UTF8, leaveOpen: true);

            VaultState.Items.Clear();

            var count = reader.ReadInt32();
            for (int i = 0; i < count; i++)
            {
                var account = reader.ReadString();
                var username = reader.ReadString();
                var email = reader.ReadString();

                // Read password once
                var pwd = reader.ReadString();

                // Best-effort wipe of temporary byte array
                CryptographicOperations.ZeroMemory(Encoding.UTF8.GetBytes(pwd));

                var notes = reader.ReadString();

                // Add to VaultState.Items (ObservableCollection<VaultEntry>)
                VaultState.Items.Add(new VaultEntry.VaultEntry
                {
                    Account = account,
                    Username = username,
                    Email = email,
                    Password = pwd,
                    Notes = notes
                });

            }
        }
    }
}
