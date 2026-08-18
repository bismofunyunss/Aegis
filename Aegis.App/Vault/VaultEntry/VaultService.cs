using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows;

using Aegis.App.Core;
using Aegis.App.Crypto;
using Aegis.App.IO;
using Aegis.App.Ipc;

using Aegis.Contracts;

namespace Aegis.App.Vault.VaultEntry;

internal static class VaultService
{
    private const string VaultFileName =
        "vault.dat";

    private static readonly JsonSerializerOptions JsonOptions =
        new()
        {
            WriteIndented = false
        };


    // ============================================================
    // SAVE VAULT
    // ============================================================

    internal static async Task SaveVaultAsync(
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (Vault.VaultState.Items == null)
        {
            throw new InvalidOperationException(
                "Vault collection is not initialized.");
        }

        if (Vault.VaultState.Items.Count == 0)
        {
            MessageBox.Show(
                "Vault is empty.",
                "Nothing to save",
                MessageBoxButton.OK,
                MessageBoxImage.Information);

            return;
        }

        var username =
            ClientSessionManager.Current.Username;

        if (string.IsNullOrWhiteSpace(username))
        {
            throw new SecurityException(
                "No authenticated user session.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        // ========================================================
        // VAULT PATH
        // ========================================================

        var userFolder =
            Folders.GetUserFolder(
                username);

        Directory.CreateDirectory(
            userFolder);

        var vaultPath =
            Path.Combine(
                userFolder,
                VaultFileName);

        // ========================================================
        // TEMPORARY FILES
        // ========================================================

        string plaintextPath =
            Path.Combine(
                Path.GetTempPath(),
                $"{Guid.NewGuid():N}.vault.json");

        string? encryptedPath = null;

        try
        {
            // ====================================================
            // SERIALIZE VAULT
            // ====================================================

            await using (var plaintext =
                         new FileStream(
                             plaintextPath,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             1024 * 1024,
                             FileOptions.SequentialScan))
            {
                await JsonSerializer.SerializeAsync(
                    plaintext,
                    Vault.VaultState.Items,
                    JsonOptions,
                    cancellationToken);

                await plaintext.FlushAsync(
                    cancellationToken);
            }

            // ====================================================
            // ENCRYPT
            //
            // Core/server handles:
            //
            //   authenticated session
            //   file-key salt
            //   FileKey
            //   layer salts
            //   derived keys
            //   encryption pipeline
            // ====================================================

            var encryptedResult =
                await AppServices.Core.EncryptFile(
                    plaintextPath,
                    progress,
                    cancellationToken);

            if (encryptedResult == null)
            {
                throw new CryptographicException(
                    "Vault encryption failed.");
            }

            encryptedPath =
                encryptedResult.OutputPath;

            if (string.IsNullOrWhiteSpace(
                    encryptedPath))
            {
                throw new CryptographicException(
                    "Encryption returned an invalid output path.");
            }

            if (!File.Exists(
                    encryptedPath))
            {
                throw new IOException(
                    "Encryption completed but the encrypted vault file was not created.");
            }

            // ====================================================
            // REPLACE EXISTING VAULT
            // ====================================================

            File.Move(
                encryptedPath,
                vaultPath,
                overwrite: true);

            // Ownership transferred to vaultPath.
            encryptedPath = null;

            // ====================================================
            // SUCCESS
            // ====================================================

            Vault.VaultState.IsDirty =
                false;
        }
        finally
        {
            // ====================================================
            // SECURELY ERASE PLAINTEXT
            // ====================================================

            if (File.Exists(
                    plaintextPath))
            {
                try
                {
                    await SecureFileEraser
                        .SecurelyEraseFileAsync(
                            plaintextPath);
                }
                catch (Exception cleanupEx)
                {
                    FileLogger.Log(
                        cleanupEx,
                        "Failed to securely erase temporary plaintext vault file.",
                        username);
                }
            }

            // ====================================================
            // REMOVE ORPHANED ENCRYPTED TEMP FILE
            // ====================================================

            if (encryptedPath != null &&
                File.Exists(encryptedPath))
            {
                try
                {
                    File.Delete(
                        encryptedPath);
                }
                catch (Exception cleanupEx)
                {
                    FileLogger.Log(
                        cleanupEx,
                        "Failed to remove orphaned encrypted temporary vault file.",
                        username);
                }
            }
        }
    }


    // ============================================================
    // LOAD VAULT
    // ============================================================

    internal static async Task LoadVaultAsync(
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (Vault.VaultState.Items == null)
        {
            throw new InvalidOperationException(
                "Vault collection is not initialized.");
        }

        var username =
            ClientSessionManager.Current.Username;

        if (string.IsNullOrWhiteSpace(username))
        {
            throw new SecurityException(
                "No authenticated user session.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        // ========================================================
        // CLEAR CURRENT STATE
        // ========================================================

        Vault.VaultState.Items.Clear();

        Vault.VaultState.IsDirty =
            false;

        // ========================================================
        // VAULT PATH
        // ========================================================

        var userFolder =
            Folders.GetUserFolder(
                username);

        var vaultPath =
            Path.Combine(
                userFolder,
                VaultFileName);

        // ========================================================
        // NO VAULT YET
        // ========================================================

        if (!File.Exists(
                vaultPath))
        {
            return;
        }

        string? decryptedPath =
            null;

        try
        {
            // ====================================================
            // DECRYPT
            //
            // Core/server handles:
            //
            //   reading the file-key salt
            //   recreating the FileKey
            //   deriving pipeline keys
            //   authentication
            //   decryption
            //
            // UI receives only the temporary plaintext path.
            // ====================================================

            var result =
                await AppServices.Core.DecryptFile(
                    vaultPath,
                    progress,
                    cancellationToken);

            if (result == null)
            {
                throw new CryptographicException(
                    "Vault decryption failed.");
            }

            decryptedPath =
                result.OutputPath;

            if (string.IsNullOrWhiteSpace(
                    decryptedPath))
            {
                throw new IOException(
                    "Decryption returned an invalid plaintext path.");
            }

            if (!File.Exists(
                    decryptedPath))
            {
                throw new IOException(
                    "Decryption completed but the plaintext vault file was not created.");
            }

            // ====================================================
            // READ DECRYPTED JSON
            // ====================================================

            await using var stream =
                new FileStream(
                    decryptedPath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    1024 * 1024,
                    FileOptions.SequentialScan);

            var entries =
                await JsonSerializer.DeserializeAsync<
                    List<Vault.VaultEntry.VaultEntry>>(
                    stream,
                    JsonOptions,
                    cancellationToken);

            // ====================================================
            // REPOPULATE VAULT
            // ====================================================

            if (entries != null)
            {
                foreach (var entry in entries)
                {
                    if (entry != null)
                    {
                        Vault.VaultState.Items.Add(
                            entry);
                    }
                }
            }

            Vault.VaultState.IsDirty =
                false;
        }
        catch (OperationCanceledException)
        {
            Vault.VaultState.Items.Clear();

            Vault.VaultState.IsDirty =
                false;

            throw;
        }
        catch (CryptographicException)
        {
            Vault.VaultState.Items.Clear();

            Vault.VaultState.IsDirty =
                false;

            throw;
        }
        catch (JsonException)
        {
            Vault.VaultState.Items.Clear();

            Vault.VaultState.IsDirty =
                false;

            throw;
        }
        catch
        {
            Vault.VaultState.Items.Clear();

            Vault.VaultState.IsDirty =
                false;

            throw;
        }
        finally
        {
            // ====================================================
            // SECURELY ERASE DECRYPTED VAULT
            // ====================================================

            if (decryptedPath != null &&
                File.Exists(
                    decryptedPath))
            {
                try
                {
                    await SecureFileEraser
                        .SecurelyEraseFileAsync(
                            decryptedPath);
                }
                catch (Exception cleanupEx)
                {
                    FileLogger.Log(
                        cleanupEx,
                        "Failed to securely erase temporary decrypted vault file.",
                        username);
                }
            }
        }
    }
}


