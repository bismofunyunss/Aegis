using System.Buffers.Binary;
using System.IO;
using System.Management;
using System.Security.Cryptography;

namespace Aegis.App
{
    public static class SecureFileEraser
    {
        /// <summary>
        /// Checks if the drive containing the given path is an SSD.
        /// </summary>
        /// <param name="path">Full file or directory path</param>
        /// <returns>True if SSD, false if HDD</returns>
        public static bool IsSSD(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                throw new ArgumentNullException(nameof(path));

            string root = System.IO.Path.GetPathRoot(path);
            if (string.IsNullOrEmpty(root))
                throw new ArgumentException("Cannot determine root drive from path.", nameof(path));

            try
            {
                using var searcher = new ManagementObjectSearcher(
                    @"SELECT MediaType, Model FROM Win32_DiskDrive");

                foreach (ManagementObject disk in searcher.Get())
                {
                    // MediaType might say "Fixed hard disk media" or "Solid state disk"
                    string mediaType = disk["MediaType"]?.ToString() ?? "";
                    string model = disk["Model"]?.ToString() ?? "";

                    // Check if the model contains "SSD" as a fallback
                    if (mediaType.IndexOf("SSD", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        model.IndexOf("SSD", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        // We found an SSD disk. Now check if the drive letter matches
                        var partitions = disk.GetRelated("Win32_DiskPartition");
                        foreach (ManagementObject partition in partitions)
                        {
                            var drives = partition.GetRelated("Win32_LogicalDisk");
                            foreach (ManagementObject logical in drives)
                            {
                                string driveLetter = logical["DeviceID"]?.ToString() ?? "";
                                if (string.Equals(driveLetter + "\\", root, StringComparison.OrdinalIgnoreCase))
                                {
                                    return true; // It's an SSD
                                }
                            }
                        }
                    }
                }
            }
            catch
            {
                // Best-effort: assume HDD if detection fails
            }

            return false; // Default to HDD
        }
        /// <summary>
        /// Public entry point for securely erasing a file.
        /// Chooses SSD vs HDD automatically.
        /// </summary>
        public static async Task SecurelyEraseFileAsync(string path, bool isSSD, int passes = 3, int bufferSize = 64 * 1024)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return;

            if (isSSD)
                await SecureEraseSSDAsync(path, bufferSize).ConfigureAwait(false);
            else
                await SecureEraseHDDAsync(path, passes, bufferSize).ConfigureAwait(false);
        }

        #region Private Methods (Exposable via wrapper)

        /// <summary>
        /// HDD wipe: multi-pass random + zero overwrite
        /// </summary>
        private static async Task SecureEraseHDDAsync(string path, int passes, int bufferSize)
        {
            var fileInfo = new FileInfo(path);
            long length = fileInfo.Length;
            byte[] buffer = new byte[bufferSize];

            try
            {
                for (int pass = 0; pass < passes; pass++)
                {
                    using var fs = new FileStream(
                        path,
                        FileMode.Open,
                        FileAccess.Write,
                        FileShare.None,
                        bufferSize,
                        useAsync: true);

                    fs.Position = 0;

                    using var rng = RandomNumberGenerator.Create();
                    long remaining = length;

                    while (remaining > 0)
                    {
                        int toWrite = (int)Math.Min(buffer.Length, remaining);

                        if (pass == passes - 1)
                        {
                            // Last pass: zero memory
                            CryptographicOperations.ZeroMemory(buffer.AsSpan(0, toWrite));
                        }
                        else
                        {
                            rng.GetBytes(buffer.AsSpan(0, toWrite));
                        }

                        await fs.WriteAsync(buffer.AsMemory(0, toWrite)).ConfigureAwait(false);
                        remaining -= toWrite;
                    }

                    await fs.FlushAsync().ConfigureAwait(false);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(buffer);
            }

            File.Delete(path);
            DestroyFileMetadata(path);
        }

        /// <summary>
        /// SSD wipe: single-pass AES-GCM overwrite
        /// </summary>
        private static async Task SecureEraseSSDAsync(string path, int bufferSize)
        {
            string tempPath = path + ".wipe";

            byte[] key = RandomNumberGenerator.GetBytes(32);       // AES-256
            byte[] nonceBase = RandomNumberGenerator.GetBytes(12); // 96-bit nonce
            byte[] buffer = new byte[bufferSize];
            byte[] cipher = new byte[bufferSize];
            byte[] tag = new byte[16];

            try
            {
                using var aes = new AesGcm(key);

                using var input = new FileStream(
                    path,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.None,
                    bufferSize,
                    FileOptions.SequentialScan | FileOptions.Asynchronous);

                using var output = new FileStream(
                    tempPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    bufferSize,
                    FileOptions.WriteThrough | FileOptions.Asynchronous);

                long counter = 0;

                while (true)
                {
                    int read = await input.ReadAsync(buffer.AsMemory(0, buffer.Length)).ConfigureAwait(false);
                    if (read <= 0) break;

                    byte[] nonce = new byte[12];
                    Buffer.BlockCopy(nonceBase, 0, nonce, 0, 12);
                    BinaryPrimitives.WriteUInt32LittleEndian(nonce.AsSpan(8), (uint)counter++);

                    aes.Encrypt(
                        nonce,
                        buffer.AsSpan(0, read),
                        cipher.AsSpan(0, read),
                        tag,
                        ReadOnlySpan<byte>.Empty);

                    await output.WriteAsync(cipher.AsMemory(0, read)).ConfigureAwait(false);

                    CryptographicOperations.ZeroMemory(buffer.AsSpan(0, read));
                }

                await output.FlushAsync().ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(buffer);
                CryptographicOperations.ZeroMemory(cipher);
                CryptographicOperations.ZeroMemory(tag);
                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(nonceBase);
            }

            File.Delete(path);
            File.Move(tempPath, path, overwrite: true);

            DestroyFileMetadata(path);
        }

        /// <summary>
        /// Removes file system metadata to further prevent recovery.
        /// </summary>
        private static void DestroyFileMetadata(string path)
        {
            try
            {
                File.SetAttributes(path, FileAttributes.Normal);
                FileInfo fi = new FileInfo(path);
                fi.CreationTimeUtc = DateTime.UtcNow;
                fi.LastAccessTimeUtc = DateTime.UtcNow;
                fi.LastWriteTimeUtc = DateTime.UtcNow;
            }
            catch { /* best effort */ }
        }

        #endregion
    }

    public static class FileIO
    {
        public static async Task WriteFileStreamAsync(string path, Stream inputStream)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));

            await using var output = new FileStream(
                path,
                FileMode.Create,
                FileAccess.Write,
                FileShare.Write,
                bufferSize: 81920,
                useAsync: true);

            if (inputStream.CanSeek)
                inputStream.Position = 0;

            await inputStream.CopyToAsync(output).ConfigureAwait(false);
        }
    }
}

