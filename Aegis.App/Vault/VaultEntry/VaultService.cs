using Aegis.App.Crypto;
using Aegis.App.IO;
using Aegis.App.Ipc;
using Aegis.Contracts;
using System.Diagnostics;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;

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

    public static async Task SaveVaultAsync(
    IProgress<double>? progress = null,
    CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        string username =
            ClientSessionManager.Current.Username;

        if (string.IsNullOrWhiteSpace(username))
        {
            throw new InvalidOperationException(
                "No authenticated user.");
        }

        string userFolder =
            Folders.GetUserFolder(username);

        Directory.CreateDirectory(userFolder);

        string vaultPath =
            Path.Combine(
                userFolder,
                "vault.dat");

        string tempPlaintext =
            Path.Combine(
                Path.GetTempPath(),
                $"aegis-vault-{Guid.NewGuid():N}.json");

        List<VaultEntryDto> dtoEntries = new();

        try
        {
            // ========================================================
            // BUILD DTOs
            // ========================================================

            foreach (SecureVaultEntry entry in VaultState.Items)
            {
                cancellationToken.ThrowIfCancellationRequested();

                byte[] password =
                    entry.GetPasswordBytes();

                byte[] notes =
                    entry.GetNotesBytes();

                try
                {
                    dtoEntries.Add(
                        new VaultEntryDto
                        {
                            Account =
                                entry.Account,

                            Username =
                                entry.Username,

                            Email =
                                entry.Email,

                            Password =
                                password,

                            Notes =
                                notes
                        });

                    Debug.WriteLine(
    $"SAVE ENTRY: {entry.Account}");

                    Debug.WriteLine(
                        $"Password bytes BEFORE serialization: {password.Length}");

                    Debug.WriteLine(
                        $"Notes bytes BEFORE serialization: {notes.Length}");

                    // Ownership moved into the DTO.
                    password =
                        Array.Empty<byte>();

                    notes =
                        Array.Empty<byte>();
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(
                        password);

                    CryptographicOperations.ZeroMemory(
                        notes);
                }
            }

            // ========================================================
            // SERIALIZE
            // ========================================================

            string json =
                JsonSerializer.Serialize(
                    dtoEntries,
                    new JsonSerializerOptions
                    {
                        WriteIndented = false
                    });

            try
            {
                await File.WriteAllTextAsync(
                    tempPlaintext,
                    json,
                    cancellationToken);
            }
            finally
            {
                json = string.Empty;
            }

            // ========================================================
            // CLEAR PLAINTEXT ARRAYS FROM DTOs
            // ========================================================

            foreach (VaultEntryDto dto in dtoEntries)
            {
                CryptographicOperations.ZeroMemory(
                    dto.Password);

                CryptographicOperations.ZeroMemory(
                    dto.Notes);

                dto.Password =
                    Array.Empty<byte>();

                dto.Notes =
                    Array.Empty<byte>();
            }

            cancellationToken.ThrowIfCancellationRequested();

            // ========================================================
            // ENCRYPT TEMPORARY VAULT FILE
            // ========================================================

            FileOperationResult? encryptionResult =
                await AppServices.Core.EncryptFile(
                    tempPlaintext,
                    progress,
                    cancellationToken);

            if (encryptionResult is null)
            {
                throw new InvalidOperationException(
                    "File encryption returned no result.");
            }

            string producedEncrypted =
                encryptionResult.OutputPath;

            if (string.IsNullOrWhiteSpace(producedEncrypted))
            {
                throw new InvalidOperationException(
                    "File encryption returned an empty output path.");
            }

            if (!File.Exists(producedEncrypted))
            {
                throw new FileNotFoundException(
                    "Encrypted vault file was not created.",
                    producedEncrypted);
            }

            // ========================================================
            // MOVE ENCRYPTED FILE INTO USER VAULT FOLDER
            // ========================================================

            File.Move(
                producedEncrypted,
                vaultPath,
                overwrite: true);

            // ========================================================
            // MARK CLEAN
            // ========================================================

            VaultState.IsDirty =
                false;

            VaultSessionManager.Current.Touch();
        }
        finally
        {
            // ========================================================
            // ZERO DTO DATA
            // ========================================================

            foreach (VaultEntryDto dto in dtoEntries)
            {
                CryptographicOperations.ZeroMemory(
                    dto.Password);

                CryptographicOperations.ZeroMemory(
                    dto.Notes);
            }

            dtoEntries.Clear();

            // ========================================================
            // SECURELY ERASE TEMPORARY PLAINTEXT
            // ========================================================

            try
            {
                if (File.Exists(tempPlaintext))
                {
                    await SecureFileEraser
                        .SecurelyEraseFileAsync(
                            tempPlaintext);
                }
            }
            catch
            {
                // Never hide the original exception.
            }
        }
    }


    // ============================================================
    // LOAD VAULT
    // ============================================================

    public static async Task LoadVaultAsync(
     IProgress<double>? progress = null,
     CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        string username =
            ClientSessionManager.Current.Username;

        if (string.IsNullOrWhiteSpace(username))
        {
            throw new InvalidOperationException(
                "No authenticated user.");
        }

        string userFolder =
            Folders.GetUserFolder(username);

        string vaultPath =
            Path.Combine(
                userFolder,
                "vault.dat");

        if (!File.Exists(vaultPath))
        {
            VaultState.Items.Clear();
            VaultState.IsDirty = false;
            return;
        }

        RamCryptoSession ramSession =
            VaultSessionManager.Current.RamSession;

        List<VaultEntryDto>? dtoEntries = null;

        string? decryptedPath = null;

        try
        {
            // ========================================================
            // DECRYPT VAULT
            // ========================================================

            FileOperationResult? decryptResult =
                await AppServices.Core.DecryptFile(
                    vaultPath,
                    progress,
                    cancellationToken);

            if (decryptResult is null)
            {
                throw new InvalidOperationException(
                    "File decryption returned no result.");
            }

            decryptedPath =
                decryptResult.OutputPath;

            if (string.IsNullOrWhiteSpace(decryptedPath))
            {
                throw new InvalidOperationException(
                    "File decryption returned an empty output path.");
            }

            if (!File.Exists(decryptedPath))
            {
                throw new FileNotFoundException(
                    "Decrypted vault file was not created.",
                    decryptedPath);
            }

            cancellationToken.ThrowIfCancellationRequested();

            // ========================================================
            // READ PLAINTEXT JSON
            // ========================================================

            string json =
                await File.ReadAllTextAsync(
                    decryptedPath,
                    cancellationToken);

            try
            {
                dtoEntries =
                    JsonSerializer.Deserialize<List<VaultEntryDto>>(
                        json);

                if (dtoEntries is null)
                {
                    dtoEntries =
                        new List<VaultEntryDto>();
                }
            }
            finally
            {
                json = string.Empty;
            }

            cancellationToken.ThrowIfCancellationRequested();

            // ========================================================
            // CLEAR CURRENT VAULT
            // ========================================================

            foreach (SecureVaultEntry existingEntry
                     in VaultState.Items)
            {
                existingEntry.Dispose();
            }

            VaultState.Items.Clear();

            // ========================================================
            // CREATE SECURE LIVE ENTRIES
            // ========================================================

            foreach (VaultEntryDto dto in dtoEntries)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var entry =
                    new SecureVaultEntry
                    {
                        Account =
                            dto.Account,

                        Username =
                            dto.Username,

                        Email =
                            dto.Email
                    };

                try
                {
                    if (dto.Password.Length > 0)
                    {
                        entry.SetPassword(
                            dto.Password);
                    }

                    if (dto.Notes.Length > 0)
                    {
                        entry.SetNotes(
                            dto.Notes);
                    }

                    VaultState.Items.Add(
                        entry);
                }
                catch
                {
                    entry.Dispose();
                    throw;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(
                        dto.Password);

                    CryptographicOperations.ZeroMemory(
                        dto.Notes);

                    dto.Password =
                        Array.Empty<byte>();

                    dto.Notes =
                        Array.Empty<byte>();
                }
            }

            VaultState.IsDirty =
                false;

            VaultSessionManager.Current.Touch();
        }
        finally
        {
            // ========================================================
            // ZERO ANY REMAINING DTO SENSITIVE DATA
            // ========================================================

            if (dtoEntries is not null)
            {
                foreach (VaultEntryDto dto in dtoEntries)
                {
                    CryptographicOperations.ZeroMemory(
                        dto.Password);

                    CryptographicOperations.ZeroMemory(
                        dto.Notes);
                }

                dtoEntries.Clear();
            }

            // ========================================================
            // SECURELY ERASE DECRYPTED TEMPORARY FILE
            // ========================================================

            if (!string.IsNullOrWhiteSpace(decryptedPath) &&
                File.Exists(decryptedPath))
            {
                try
                {
                    await SecureFileEraser
                        .SecurelyEraseFileAsync(
                            decryptedPath);
                }
                catch
                {
                    // Never hide the original
                    // vault/decryption exception.
                }
            }
        }
    }
}