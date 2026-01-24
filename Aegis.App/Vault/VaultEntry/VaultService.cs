using Aegis.App.Core;
using Aegis.App.Crypto;
using Aegis.App.Helpers;
using Aegis.App.IO;
using Aegis.App.Session;
using Org.BouncyCastle.Crypto.Engines;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows;
using static Aegis.App.ParallelCtrEncryptor;
using static Aegis.App.Session.Session;

namespace Aegis.App.Vault.VaultEntry;

public static class VaultService
{
    private const string VaultFileName = "vault.dat";
    private const byte VaultMagic = 0xA4;
    private const byte VaultVersion = 0x01;
    private const int FileKeySaltSize = 128;
    private const int NumLayerSalts = 8;
    private const int LayerSaltSize = 128;

    public static async Task SaveVaultAsync(string userName, IProgress<double>? progress = null)
    {
        if (!VaultState.Items.Any())
        {
            MessageBox.Show("Vault is empty.", "Nothing to save");
            return;
        }

        var vaultPath = Path.Combine(Folders.GetUserFolder(userName));

        // Serialize entries
        using var plaintext = new MemoryStream();
        JsonSerializer.Serialize(plaintext, VaultState.Items,
            new JsonSerializerOptions { WriteIndented = false });
        plaintext.Position = 0;

        var session = CryptoSessionManager.Current;


        // Generate salts
        var fileKeySalt = RandomNumberGenerator.GetBytes(128);

        // Get active session (must already be logged in)
        session = CryptoSessionManager.Current;
        if (session == null || !session.IsMasterKeyInitialized)
            throw new SecurityException("No active crypto session.");

        // Derive file key
        using var fileKey = new FileKey(
            fileKeySalt,
            "Vault-File-Key"u8,
            64);

        // Derive layered keys from the file key
        var layerSalts = CryptoMethods.SaltGenerator.CreateSalts();
        var keys = KeyDerivation.DeriveKeys(fileKey, layerSalts);


        try
        {
            await using var fileStream = new FileStream(vaultPath, FileMode.Create, FileAccess.Write, FileShare.None);
            await EncryptVaultAsync(plaintext, fileStream, keys, fileKeySalt, layerSalts);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to save vault:\n{ex.Message}", "Error", MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        finally
        {
            fileKey.Dispose();
            foreach (var salt in layerSalts) MemoryHandling.Clear(salt);
            keys?.Dispose();
        }
    }

    public static async Task LoadVaultAsync(IProgress<double>? progress = null)
    {
        // Get active session (must already be logged in)
        var session = CryptoSessionManager.Current;
        if (session == null || !session.IsMasterKeyInitialized)
            throw new SecurityException("No active crypto session.");


        var vaultPath = Path.Combine(Folders.GetUserFolder(SessionManager.User.Username), VaultFileName);

        VaultState.Items.Clear();
        VaultState.IsDirty = false;

        if (!File.Exists(vaultPath)) return;


        try
        {
            await using var fileStream = new FileStream(vaultPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            await using var decryptedStream = new MemoryStream();

            await DecryptVaultAsync(fileStream, decryptedStream, session);

            decryptedStream.Position = 0;
            var entries = JsonSerializer.Deserialize<List<VaultEntry>>(decryptedStream)
                          ?? new List<VaultEntry>();

            foreach (var entry in entries)
                VaultState.Items.Add(entry);

            VaultState.IsDirty = false;
        }
        catch (CryptographicException)
        {
            MessageBox.Show("Vault file is corrupted or tampered.", "Error", MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to load vault:\n{ex.Message}", "Error", MessageBoxButton.OK,
                MessageBoxImage.Error);
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
        var xchachaNonce = RandomNumberGenerator.GetBytes(16);
        var threefishIv = RandomNumberGenerator.GetBytes(120);
        var serpentIv = RandomNumberGenerator.GetBytes(8);
        var aesIv = RandomNumberGenerator.GetBytes(8);

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
        var threefishTag = await ParallelCtr.EncryptParallelAsync(stage2, stage3, keys.ThreefishKey,
            keys.ThreefishHmacKey, () => new ThreefishEngine(1024), threefishIv);
        stage3.Position = 0;
        var serpentTag = await ParallelCtr.EncryptParallelAsync(stage3, stage4, keys.SerpentKey, keys.SerpentHmacKey,
            () => new SerpentEngine(), serpentIv);
        stage4.Position = 0;
        var aesTag = await ParallelCtr.EncryptParallelAsync(stage4, stage5, keys.AesKey, keys.AesHmacKey,
            () => new AesEngine(), aesIv);

        // Write header
        await output.WriteAsync(new[] { VaultMagic, VaultVersion });
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

    public static async Task DecryptVaultAsync(Stream encryptedVault, Stream output, CryptoSession session)
    {
        const int FileKeySaltSize = 128;
        const int NumLayerSalts = 8;
        const int LayerSaltSize = 128;

        // Magic + version
        var magic = encryptedVault.ReadByte();
        var version = encryptedVault.ReadByte();
        if (magic != VaultMagic || version != VaultVersion)
            throw new CryptographicException("Invalid vault format.");

        // Get active session (must already be logged in)
        session = CryptoSessionManager.Current;
        if (session == null || !session.IsMasterKeyInitialized)
            throw new SecurityException("No active crypto session.");

        // File key salt
        var fileKeySalt = await HelperMethods.ReadExactAsync(encryptedVault, FileKeySaltSize);
        // Derive file key
        using var fileKey = new FileKey(
            fileKeySalt,
            "Vault-File-Key"u8,
            64);

        // Layer salts
        var layerSalts = new byte[NumLayerSalts][];
        for (var i = 0; i < NumLayerSalts; i++)
            layerSalts[i] = await HelperMethods.ReadExactAsync(encryptedVault, LayerSaltSize);

        var keys = KeyDerivation.DeriveKeys(fileKey, layerSalts);

        // IVs
        var xchachaNonce = await HelperMethods.ReadExactAsync(encryptedVault, 16);
        var threefishIv = await HelperMethods.ReadExactAsync(encryptedVault, 120);
        var serpentIv = await HelperMethods.ReadExactAsync(encryptedVault, 8);
        var aesIv = await HelperMethods.ReadExactAsync(encryptedVault, 8);

        // HMAC tags
        var threefishTag = await HelperMethods.ReadExactAsync(encryptedVault, 64);
        var serpentTag = await HelperMethods.ReadExactAsync(encryptedVault, 64);
        var aesTag = await HelperMethods.ReadExactAsync(encryptedVault, 64);

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