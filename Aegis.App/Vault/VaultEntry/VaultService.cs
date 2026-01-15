using Aegis.App.Crypto;
using Aegis.App.Global;
using Aegis.App.Helpers;
using Aegis.App.IO;
using Aegis.App.Vault.VaultEntry;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using Windows.Devices.Geolocation;
using Org.BouncyCastle.Crypto.Engines;
using static Aegis.App.Pages.VaultPage;
using static Aegis.App.ParallelCtrEncryptor;
using static Aegis.App.ParallelCtrEncryptor.SecureParallelEncryptor;
using static Aegis.App.ParallelCtrEncryptor.SecureParallelEncryptor.ParallelCtr;

namespace Aegis.App.Vault.Services
{
    public static class VaultService
    {
        private const string VaultFileName = "vault.dat";
        private const byte VaultMagic = 0xA4;
        private const byte VaultVersion = 0x01;
        private const int FileKeySaltSize = 128;
        private const int NumLayerSalts = 8;
        private const int LayerSaltSize = 128;

        public static async Task SaveVaultAsync(IProgress<double>? progress = null)
        {
            if (!VaultState.Items.Any())
            {
                MessageBox.Show("Vault is empty.", "Nothing to save");
                return;
            }

            string vaultPath = Path.Combine(IO.Folders.GetUserFolder(Session.Instance.Username!), VaultFileName);

            // Serialize entries
            using var plaintext = new MemoryStream();
            JsonSerializer.Serialize(plaintext, VaultState.Items,
                new JsonSerializerOptions { WriteIndented = false });
            plaintext.Position = 0;

            // Generate salts and keys
            var fileKeySalt = RandomNumberGenerator.GetBytes(FileKeySaltSize);
            var fileKey = Session.Instance.MasterKey.DeriveKey(fileKeySalt, "Vault-File-Key"u8.ToArray(), 64);
            var layerSalts = CryptoMethods.SaltGenerator.CreateSalts(LayerSaltSize);
            var keys = KeyDerivation.DeriveKeys(fileKey, layerSalts);

            try
            {
                await using var fileStream = new FileStream(vaultPath, FileMode.Create, FileAccess.Write, FileShare.None);
                await EncryptVaultAsync(plaintext, fileStream, keys, fileKeySalt, layerSalts);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to save vault:\n{ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                MemoryHandling.Clear(fileKey);
                foreach (var salt in layerSalts) MemoryHandling.Clear(salt);
                keys?.Dispose();
            }
        }

        public static async Task LoadVaultAsync(IProgress<double>? progress = null)
        {
            string vaultPath = Path.Combine(IO.Folders.GetUserFolder(Session.Instance.Username!), VaultFileName);

            VaultState.Items.Clear();
            VaultState.IsDirty = false;

            if (!File.Exists(vaultPath)) return;


            try
            {
                await using var fileStream = new FileStream(vaultPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                await using var decryptedStream = new MemoryStream();

                await DecryptVaultAsync(fileStream, decryptedStream);

                decryptedStream.Position = 0;
                var entries = JsonSerializer.Deserialize<List<VaultEntry.VaultEntry>>(decryptedStream)
                              ?? new List<VaultEntry.VaultEntry>();

                foreach (var entry in entries)
                    VaultState.Items.Add(entry);

                VaultState.IsDirty = false;
            }
            catch (CryptographicException)
            {
                MessageBox.Show("Vault file is corrupted or tampered.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to load vault:\n{ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public static async Task EncryptVaultAsync(
            Stream plaintext,
            Stream output,
            DerivedKeys keys,
            byte[] fileKeySalt,
            byte[][] layerSalts)
        {
            // Generate IVs
            byte[] xchachaNonce = RandomNumberGenerator.GetBytes(16);
            byte[] threefishIv = RandomNumberGenerator.GetBytes(120);
            byte[] serpentIv = RandomNumberGenerator.GetBytes(8);
            byte[] aesIv = RandomNumberGenerator.GetBytes(8);

            using var stage1 = new MemoryStream();
            using var stage2 = new MemoryStream();
            using var stage3 = new MemoryStream();
            using var stage4 = new MemoryStream();
            using var stage5 = new MemoryStream();

            // Layered encryption
            await ParallelCtr.ShuffleLayer.ShuffleStreamAsync(plaintext, stage1, keys.ShuffleKey);
            stage1.Position = 0;
            await ParallelCtr.EncryptXChaCha20Poly1305ParallelRawAsync(stage1, stage2, keys.XChaChaKey, xchachaNonce);
            stage2.Position = 0;
            var threefishTag = await ParallelCtr.EncryptParallelAsync(stage2, stage3, keys.ThreefishKey, keys.ThreefishHmacKey, () => new ThreefishEngine(1024), threefishIv);
            stage3.Position = 0;
            var serpentTag = await ParallelCtr.EncryptParallelAsync(stage3, stage4, keys.SerpentKey, keys.SerpentHmacKey, () => new SerpentEngine(), serpentIv);
            stage4.Position = 0;
            var aesTag = await ParallelCtr.EncryptParallelAsync(stage4, stage5, keys.AesKey, keys.AesHmacKey, () => new AesEngine(), aesIv);

            // Write header
            await output.WriteAsync(new byte[] { VaultMagic, VaultVersion });
            await output.WriteAsync(fileKeySalt);
            foreach (var salt in layerSalts) await output.WriteAsync(salt);

            await output.WriteAsync(xchachaNonce);
            await output.WriteAsync(threefishIv);
            await output.WriteAsync(serpentIv);
            await output.WriteAsync(aesIv);

            await output.WriteAsync(threefishTag);
            await output.WriteAsync(serpentTag);
            await output.WriteAsync(aesTag);

            // Write ciphertext
            stage5.Position = 0;
            await stage5.CopyToAsync(output);

            MemoryHandling.Clear(xchachaNonce, threefishIv, serpentIv, aesIv);
        }

        public static async Task DecryptVaultAsync(Stream encryptedVault, Stream output)
        {
            const int FileKeySaltSize = 128;
            const int NumLayerSalts = 8;
            const int LayerSaltSize = 128;

            // Magic + version
            int magic = encryptedVault.ReadByte();
            int version = encryptedVault.ReadByte();
            if (magic != VaultMagic || version != VaultVersion)
                throw new CryptographicException("Invalid vault format.");

            // File key salt
            byte[] fileKeySalt = await HelperMethods.ReadExactAsync(encryptedVault, FileKeySaltSize);
            var fileKey = Session.Instance.Crypto.MasterKey.DeriveKey(fileKeySalt, "Vault-File-Key"u8.ToArray(), 64);

            // Layer salts
            var layerSalts = new byte[NumLayerSalts][];
            for (int i = 0; i < NumLayerSalts; i++)
                layerSalts[i] = await HelperMethods.ReadExactAsync(encryptedVault, LayerSaltSize);

            var keys = KeyDerivation.DeriveKeys(fileKey, layerSalts);

            // IVs
            byte[] xchachaNonce = await HelperMethods.ReadExactAsync(encryptedVault, 16);
            byte[] threefishIv = await HelperMethods.ReadExactAsync(encryptedVault, 120);
            byte[] serpentIv = await HelperMethods.ReadExactAsync(encryptedVault, 8);
            byte[] aesIv = await HelperMethods.ReadExactAsync(encryptedVault, 8);

            // HMAC tags
            byte[] threefishTag = await HelperMethods.ReadExactAsync(encryptedVault, 64);
            byte[] serpentTag = await HelperMethods.ReadExactAsync(encryptedVault, 64);
            byte[] aesTag = await HelperMethods.ReadExactAsync(encryptedVault, 64);

            try
            {
                // Decrypt layers
                using var stage5 = new MemoryStream();
                await encryptedVault.CopyToAsync(stage5);
                stage5.Position = 0;

                using var stage4 = new MemoryStream();
                await ParallelCtr.DecryptParallelAsync(stage5, stage4, keys.AesKey, keys.AesHmacKey,
                    () => new AesEngine(), aesIv, aesTag);

                stage4.Position = 0;
                using var stage3 = new MemoryStream();
                await ParallelCtr.DecryptParallelAsync(stage4, stage3, keys.SerpentKey, keys.SerpentHmacKey,
                    () => new SerpentEngine(), serpentIv, serpentTag);

                stage3.Position = 0;
                using var stage2 = new MemoryStream();
                await ParallelCtr.DecryptParallelAsync(stage3, stage2, keys.ThreefishKey, keys.ThreefishHmacKey,
                    () => new ThreefishEngine(1024), threefishIv, threefishTag);

                stage2.Position = 0;
                using var stage1 = new MemoryStream();
                await ParallelCtr.DecryptXChaCha20Poly1305ParallelRawAsync(stage2, stage1, keys.XChaChaKey,
                    xchachaNonce);

                stage1.Position = 0;
                await ParallelCtr.ShuffleLayer.UnshuffleStreamAsync(stage1, output, keys.ShuffleKey);

                MemoryHandling.Clear(xchachaNonce, threefishIv, serpentIv, aesIv);
            }
            finally
            {
                keys?.Dispose();
            }
        }
    }

}


