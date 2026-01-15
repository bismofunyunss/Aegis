using Aegis.App.Crypto;
using Aegis.App.Global;
using Aegis.App.Helpers;
using Aegis.App.Vault.VaultEntry;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Sodium;
using System.Buffers;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Channels;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;
using Path = System.IO.Path;

namespace Aegis.App;

public static class FileLogger
{
    private static readonly string LogFilePath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "crypto-log.txt");

    private static readonly object _lock = new();

    public static void Log(string message)
    {
        try
        {
            var logLine = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} - {message}";
            lock (_lock)
            {
                File.AppendAllText(LogFilePath, logLine + Environment.NewLine);
            }
        }
        catch
        {
            // Fails silently. You can optionally raise an event or add fallback logging.
        }
    }

    public static void LogBytes(string label, byte[] data, int length = 64)
    {
        if (data == null)
        {
            Log($"{label}: <null>");
            return;
        }

        var displayLength = Math.Min(length, data.Length);
        var hex = BitConverter.ToString(data, 0, displayLength).Replace("-", "");
        if (displayLength < data.Length)
            hex += "...";

        Log($"{label} ({data.Length} bytes): {hex}");
    }
}

public static class ParallelCtrEncryptor
{

    // -------------------------- PUBLIC FILE ENCRYPTION --------------------------
   /* public static async Task EncryptFile(
        Stream input,
        Stream output,
        byte[] fileKey,
        byte[] fileKeySalt,
        IProgress<double>? progress = null)
    {
        var tempPaths = new List<string>();

        byte[]? chachaKey = null;
        byte[]? threefishKey = null;
        byte[]? serpentKey = null;
        byte[]? aesKey = null;
        byte[]? shuffleKey = null;
        byte[]? threeFishHmacKey = null;
        byte[]? serpentHmacKey = null;
        byte[]? aesHmacKey = null;

        try
        {
            // Temp file for encryption pipeline
            var tempPath = Path.GetTempFileName();
            tempPaths.Add(tempPath);

            var cryptoSalts = CryptoMethods.SaltGenerator.CreateSalts();

            // Encrypt stream
            chachaKey = CryptoMethods.HKDF.DeriveKey(fileKey, cryptoSalts[0], "xChaCha-Poly1305"u8.ToArray(), 32);
            threefishKey = CryptoMethods.HKDF.DeriveKey(fileKey, cryptoSalts[1], "Threefish-1024"u8.ToArray(), 128);
            serpentKey = CryptoMethods.HKDF.DeriveKey(fileKey, cryptoSalts[2], "Serpent-256-Key"u8.ToArray(), 32);
            aesKey = CryptoMethods.HKDF.DeriveKey(fileKey, cryptoSalts[3], "Aes-256-CBC"u8.ToArray(), 32);
            shuffleKey = CryptoMethods.HKDF.DeriveKey(fileKey, cryptoSalts[4], "Shuffle-Layer"u8.ToArray(), 128);
            threeFishHmacKey =
                CryptoMethods.HKDF.DeriveKey(fileKey, cryptoSalts[5], "Threefish-1024-Hmac"u8.ToArray(), 64);
            serpentHmacKey =
                CryptoMethods.HKDF.DeriveKey(fileKey, cryptoSalts[6], "Serpent-256-Hmac"u8.ToArray(), 64);
            aesHmacKey = CryptoMethods.HKDF.DeriveKey(fileKey, cryptoSalts[7], "Aes-256-Hmac"u8.ToArray(), 64);


            await SecureParallelEncryptor.EncryptV3(input, output, chachaKey, threefishKey, serpentKey, aesKey,
                shuffleKey, threeFishHmacKey, serpentHmacKey, aesHmacKey, progress);

            // Copy final encrypted file to output
            await using var tempRead = File.OpenRead(tempPath);
            await tempRead.CopyToAsync(output).ConfigureAwait(false);

            // cryptoSalts is byte[8][128]
            var allSalts = new byte[8 * 128];
            for (int i = 0; i < 8; i++)
                Buffer.BlockCopy(cryptoSalts[i], 0, allSalts, i * 128, 128);


            // Write all 8 salts at once
            await output.WriteAsync(allSalts);
            await output.WriteAsync(fileKeySalt);
            await output.FlushAsync().ConfigureAwait(false);
        }
        finally
        {
            foreach (var path in tempPaths)
                if (File.Exists(path))
                    SecureFileEraser.SecurelyEraseFileAsync(path, SecureFileEraser.IsSSD(path));

            MemoryHandling.Clear(chachaKey, threefishKey, serpentKey, aesKey, shuffleKey, threeFishHmacKey,
                serpentHmacKey, aesHmacKey);
        }
    }

    public static async Task DecryptFile(
        Stream input,
        Stream output,
        byte[] keyBytes,
        byte[] hkdfSalt,
        IProgress<double>? progress = null)
    {
        var tempPaths = new List<string>();

        try
        {
            var tempPath = Path.GetTempFileName();
            tempPaths.Add(tempPath);

            await using var tempRead = File.OpenRead(tempPath);
            await tempRead.CopyToAsync(output).ConfigureAwait(false);
            await output.FlushAsync().ConfigureAwait(false);
        }
        finally
        {
            foreach (var path in tempPaths)
                if (File.Exists(path))
                    SecureFileEraser.SecurelyEraseFileAsync(path, SecureFileEraser.IsSSD(path));
        }
    }
   */

    // -------------------------- UTILITY METHODS --------------------------

    private static IProgress<long> CreateSegmentedProgress(long totalLength, double startPercent, double endPercent,
        IProgress<double>? parent)
    {
        return new Progress<long>(bytes =>
        {
            parent?.Report(startPercent + (double)bytes / totalLength * (endPercent - startPercent));
        });
    }

    private static async Task<byte[]> ReadExactAsync(Stream s, int length)
    {
        var buffer = new byte[length];
        var read = 0;
        while (read < length)
        {
            var n = await s.ReadAsync(buffer, read, length - read);
            if (n == 0) throw new EndOfStreamException();
            read += n;
        }

        return buffer;
    }

    /// <summary>
    ///     Reads a stream in asynchronous chunks.
    /// </summary>
    private static async IAsyncEnumerable<byte[]> ReadChunksAsync(Stream stream, int chunkSize)
    {
        var buffer = new byte[chunkSize];
        int read;
        while ((read = await stream.ReadAsync(buffer, 0, buffer.Length)) > 0)
        {
            var chunk = new byte[read];
            Buffer.BlockCopy(buffer, 0, chunk, 0, read);
            yield return chunk;
        }

        MemoryHandling.Clear(buffer);
    }


    private sealed class HmacSha3Stream : IDisposable
    {
        private readonly HMac hmac;
        private bool _disposed; // To detect redundant calls

        public HmacSha3Stream(byte[] key, int bits = 512)
        {
            IDigest digest = bits switch
            {
                224 => new Sha3Digest(224),
                256 => new Sha3Digest(256),
                384 => new Sha3Digest(384),
                _ => new Sha3Digest(512)
            };

            hmac = new HMac(digest);
            hmac.Init(new KeyParameter(key));
        }

        // Public dispose method
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public void Update(byte[] buffer, int offset, int count)
        {
            hmac.BlockUpdate(buffer, offset, count);
        }

        public byte[] Final()
        {
            var result = new byte[hmac.GetMacSize()];
            hmac.DoFinal(result, 0);
            hmac.Reset();
            return result;
        }

        // Protected virtual dispose method
        private void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
            }

            _disposed = true;
        }
    }

    // -------------------------- LAYERED ENCRYPTION / DECRYPTION --------------------------
    public static class SecureParallelEncryptor
    {
        public static async Task EncryptV3(
            Stream inputStream,
            Stream outputStream,
            DerivedKeys keys,
            IProgress<double>? progress = null,
            int chunkSize = 64 * 1024)
        {
            // =======================
            // Generate nonces / IVs
            // =======================
            byte[] xchachaNonce = RandomNumberGenerator.GetBytes(16);
            byte[] threefishIv = RandomNumberGenerator.GetBytes(120);
            byte[] serpentIv = RandomNumberGenerator.GetBytes(8);
            byte[] aesIv = RandomNumberGenerator.GetBytes(8);

            // =======================
            // Build authenticated header
            // =======================
            byte[] header;
            byte[] headerMac;

            using (var ms = new MemoryStream())
            {
                ms.WriteByte(0xA3); // Magic
                ms.WriteByte(0x01); // Version
                ms.Write(xchachaNonce);
                ms.Write(threefishIv);
                ms.Write(serpentIv);
                ms.Write(aesIv);
                header = ms.ToArray();
            }

            using var Keys = Session.Instance.Crypto!.Keys;
            {
                using (var hmac = new HMACSHA256(keys.AesHmacKey))
                    headerMac = hmac.ComputeHash(header);

                // =======================
                // Write header
                // =======================
                await outputStream.WriteAsync(BitConverter.GetBytes(header.Length));
                await outputStream.WriteAsync(header);
                await outputStream.WriteAsync(headerMac);

                // =======================
                // Temp files
                // =======================
                string shuffledPath = Path.GetTempFileName();
                string xchachaPath = Path.GetTempFileName();
                string threefishPath = Path.GetTempFileName();
                string serpentPath = Path.GetTempFileName();
                string aesPath = Path.GetTempFileName();

                try
                {
                    // =======================
                    // 1. Shuffle (0–20%)
                    // =======================
                    var shuffleProgress = CreateSegmentedProgress(
                        inputStream.Length, 0, 20, progress);

                    await using (var shuffledOut = File.Create(shuffledPath))
                        await ParallelCtr.ShuffleLayer.ShuffleStreamAsync(
                            inputStream, shuffledOut, keys.ShuffleKey);

                    // =======================
                    // 2. XChaCha20 (20–40%)
                    // =======================
                    var xchachaProgress = CreateSegmentedProgress(
                        new FileInfo(shuffledPath).Length, 20, 40, progress);

                    await using (var xIn = File.OpenRead(shuffledPath))
                    await using (var xOut = File.Create(xchachaPath))
                        await ParallelCtr.EncryptXChaCha20Poly1305ParallelRawAsync(
                            xIn, xOut, keys.XChaChaKey, xchachaNonce, xchachaProgress);

                    // =======================
                    // 3. Threefish CTR + HMAC (40–60%)
                    // =======================
                    var threefishProgress = CreateSegmentedProgress(
                        new FileInfo(xchachaPath).Length, 40, 60, progress);
                    byte[] threeFishTag = new byte[64];
                    await using (var tIn = File.OpenRead(xchachaPath))
                    await using (var tOut = File.Create(threefishPath))
                       threeFishTag = await ParallelCtr.EncryptParallelAsync(
                            tIn, tOut,
                            keys.ThreefishKey, keys.ThreefishHmacKey,
                            () => new ThreefishEngine(1024),
                            threefishIv,
                            threefishProgress,
                            chunkSize);

                    // =======================
                    // 4. Serpent CTR + HMAC (60–80%)
                    // =======================
                    var serpentProgress = CreateSegmentedProgress(
                        new FileInfo(threefishPath).Length, 60, 80, progress);
                    byte[] serpentTag = new byte[64];
                    await using (var sIn = File.OpenRead(threefishPath))
                    await using (var sOut = File.Create(serpentPath))
                       serpentTag = await ParallelCtr.EncryptParallelAsync(
                            sIn, sOut,
                            keys.SerpentKey, keys.SerpentHmacKey,
                            () => new SerpentEngine(),
                            serpentIv,
                            serpentProgress,
                            chunkSize);

                    // =======================
                    // 5. AES CTR + HMAC (80–95%)
                    // =======================
                    var aesProgress = CreateSegmentedProgress(
                        new FileInfo(serpentPath).Length, 80, 95, progress);
                    byte[] aesTag = new byte[64];
                    await using (var aIn = File.OpenRead(serpentPath))
                    await using (var aOut = File.Create(aesPath))
                      aesTag = await ParallelCtr.EncryptParallelAsync(
                            aIn, aOut,
                            keys.AesKey, keys.AesHmacKey,
                            () => new AesEngine(),
                            aesIv,
                            aesProgress,
                            chunkSize);

                    // =======================
                    // 6. Final payload
                    // =======================
                    await outputStream.WriteAsync(xchachaNonce);
                    await outputStream.WriteAsync(threefishIv);
                    await outputStream.WriteAsync(threeFishTag);
                    await outputStream.WriteAsync(serpentIv);
                    await outputStream.WriteAsync(serpentTag);
                    await outputStream.WriteAsync(aesIv);
                    await outputStream.WriteAsync(aesTag);
                    progress.Report(95);

                    await using (var finalCipher = File.OpenRead(aesPath))
                    {
                        await outputStream.FlushAsync().ConfigureAwait(false);
                        await finalCipher.CopyToAsync(outputStream);
                        outputStream.Position = 0;
                        inputStream.Seek(0, SeekOrigin.Begin);
                    }

                    progress.Report(100);
                }
                finally
                {
                    await SecureFileEraser.SecurelyEraseFileAsync(shuffledPath, SecureFileEraser.IsSSD(shuffledPath));
                    await SecureFileEraser.SecurelyEraseFileAsync(xchachaPath, SecureFileEraser.IsSSD(xchachaPath));
                    await SecureFileEraser.SecurelyEraseFileAsync(threefishPath, SecureFileEraser.IsSSD(threefishPath));
                    await SecureFileEraser.SecurelyEraseFileAsync(serpentPath, SecureFileEraser.IsSSD(serpentPath));
                    await SecureFileEraser.SecurelyEraseFileAsync(aesPath, SecureFileEraser.IsSSD(aesPath));

                    MemoryHandling.Clear(xchachaNonce, threefishIv, serpentIv, aesIv);
                }
            }
        }

        public static async Task EncryptV3(
          MemoryStream inputStream,
          MemoryStream outputStream,
          DerivedKeys keys,
          IProgress<double>? progress = null,
          int chunkSize = 64 * 1024)
        {
            // =======================
            // Generate nonces / IVs
            // =======================
            byte[] xchachaNonce = RandomNumberGenerator.GetBytes(16);
            byte[] threefishIv = RandomNumberGenerator.GetBytes(120);
            byte[] serpentIv = RandomNumberGenerator.GetBytes(8);
            byte[] aesIv = RandomNumberGenerator.GetBytes(8);

            // =======================
            // Build authenticated header
            // =======================
            byte[] header;
            byte[] headerMac;

            using (var ms = new MemoryStream())
            {
                ms.WriteByte(0xA3); // Magic
                ms.WriteByte(0x01); // Version
                ms.Write(xchachaNonce);
                ms.Write(threefishIv);
                ms.Write(serpentIv);
                ms.Write(aesIv);
                header = ms.ToArray();
            }

            using var Keys = Session.Instance.Crypto!.Keys;
            {
                using (var hmac = new HMACSHA256(keys.AesHmacKey))
                    headerMac = hmac.ComputeHash(header);

                // =======================
                // Write header
                // =======================
                await outputStream.WriteAsync(BitConverter.GetBytes(header.Length));
                await outputStream.WriteAsync(header);
                await outputStream.WriteAsync(headerMac);

                // =======================
                // Temp files
                // =======================
                string shuffledPath = Path.GetTempFileName();
                string xchachaPath = Path.GetTempFileName();
                string threefishPath = Path.GetTempFileName();
                string serpentPath = Path.GetTempFileName();
                string aesPath = Path.GetTempFileName();

                try
                {
                    // =======================
                    // 1. Shuffle (0–20%)
                    // =======================
                    var shuffleProgress = CreateSegmentedProgress(
                        inputStream.Length, 0, 20, progress);

                    await using (var shuffledOut = File.Create(shuffledPath))
                        await ParallelCtr.ShuffleLayer.ShuffleStreamAsync(
                            inputStream, shuffledOut, keys.ShuffleKey);

                    // =======================
                    // 2. XChaCha20 (20–40%)
                    // =======================
                    var xchachaProgress = CreateSegmentedProgress(
                        new FileInfo(shuffledPath).Length, 20, 40, progress);

                    await using (var xIn = File.OpenRead(shuffledPath))
                    await using (var xOut = File.Create(xchachaPath))
                        await ParallelCtr.EncryptXChaCha20Poly1305ParallelRawAsync(
                            xIn, xOut, keys.XChaChaKey, xchachaNonce, xchachaProgress);

                    // =======================
                    // 3. Threefish CTR + HMAC (40–60%)
                    // =======================
                    var threefishProgress = CreateSegmentedProgress(
                        new FileInfo(xchachaPath).Length, 40, 60, progress);

                    await using (var tIn = File.OpenRead(xchachaPath))
                    await using (var tOut = File.Create(threefishPath))
                        await ParallelCtr.EncryptParallelAsync(
                            tIn, tOut,
                            keys.ThreefishKey, keys.ThreefishHmacKey,
                            () => new ThreefishEngine(1024),
                            threefishIv,
                            threefishProgress,
                            chunkSize);

                    // =======================
                    // 4. Serpent CTR + HMAC (60–80%)
                    // =======================
                    var serpentProgress = CreateSegmentedProgress(
                        new FileInfo(threefishPath).Length, 60, 80, progress);

                    await using (var sIn = File.OpenRead(threefishPath))
                    await using (var sOut = File.Create(serpentPath))
                        await ParallelCtr.EncryptParallelAsync(
                            sIn, sOut,
                            keys.SerpentKey, keys.SerpentHmacKey,
                            () => new SerpentEngine(),
                            serpentIv,
                            serpentProgress,
                            chunkSize);

                    // =======================
                    // 5. AES CTR + HMAC (80–95%)
                    // =======================
                    var aesProgress = CreateSegmentedProgress(
                        new FileInfo(serpentPath).Length, 80, 95, progress);

                    await using (var aIn = File.OpenRead(serpentPath))
                    await using (var aOut = File.Create(aesPath))
                        await ParallelCtr.EncryptParallelAsync(
                            aIn, aOut,
                            keys.AesKey, keys.AesHmacKey,
                            () => new AesEngine(),
                            aesIv,
                            aesProgress,
                            chunkSize);

                    // =======================
                    // 6. Final payload
                    // =======================
                    await using (var finalCipher = File.OpenRead(aesPath))
                        await finalCipher.CopyToAsync(outputStream);

                    progress?.Report(100);
                }
                finally
                {
                    await SecureFileEraser.SecurelyEraseFileAsync(shuffledPath, SecureFileEraser.IsSSD(shuffledPath));
                    await SecureFileEraser.SecurelyEraseFileAsync(xchachaPath, SecureFileEraser.IsSSD(xchachaPath));
                    await SecureFileEraser.SecurelyEraseFileAsync(threefishPath, SecureFileEraser.IsSSD(threefishPath));
                    await SecureFileEraser.SecurelyEraseFileAsync(serpentPath, SecureFileEraser.IsSSD(serpentPath));
                    await SecureFileEraser.SecurelyEraseFileAsync(aesPath, SecureFileEraser.IsSSD(aesPath));

                    MemoryHandling.Clear(xchachaNonce, threefishIv, serpentIv, aesIv);
                }
            }
        }

        public static async Task DecryptV3(
            Stream inputStream,
            Stream outputStream,
            DerivedKeys Keys,
            IProgress<double>? progress = null,
            int chunkSize = 64 * 1024)
        {
            // ---- Read IVs / HMAC tags from header ----
            var xchachaNonce = await ReadExactAsync(inputStream, 16);
            var threefishIv = await ReadExactAsync(inputStream, 120);
            var threefishTag = await ReadExactAsync(inputStream, 64);
            var serpentIv = await ReadExactAsync(inputStream, 8);
            var serpentTag = await ReadExactAsync(inputStream, 64);
            var aesIv = await ReadExactAsync(inputStream, 8);
            var aesTag = await ReadExactAsync(inputStream, 64);

            // Temp files for intermediate layers
            var aesPath = Path.GetTempFileName();
            var serpentPath = Path.GetTempFileName();
            var threefishPath = Path.GetTempFileName();
            var xchachaPath = Path.GetTempFileName();
            var shuffledPath = Path.GetTempFileName();

            try
            {
                // Step 1: Copy AES ciphertext to temp
                await using (var aesOut = File.Create(aesPath))
                {
                    await inputStream.CopyToAsync(aesOut);
                }


                    // Step 2: AES CTR + HMAC verification
                    var aesProgress = CreateSegmentedProgress(new FileInfo(aesPath).Length, 0, 15, progress);
                    await using (var aIn = File.OpenRead(aesPath))
                    await using (var aOut = File.Create(serpentPath))
                    {
                        await ParallelCtr.DecryptParallelAsync(
                            aIn, aOut, Keys.AesKey, Keys.AesHmacKey, () => new AesEngine(), aesIv,
                            aesTag, aesProgress);
                    }

                    // Step 3: Serpent CTR + HMAC verification
                    var serpentProgress = CreateSegmentedProgress(new FileInfo(serpentPath).Length, 15, 35, progress);
                    await using (var sIn = File.OpenRead(serpentPath))
                    await using (var sOut = File.Create(threefishPath))
                    {
                        await ParallelCtr.DecryptParallelAsync(
                            sIn, sOut, Keys.SerpentKey, Keys.SerpentHmacKey,
                            () => new SerpentEngine(), serpentIv,
                            serpentTag, aesProgress);
                    }

                    // Step 4: Threefish CTR + HMAC verification
                    var threefishProgress =
                        CreateSegmentedProgress(new FileInfo(threefishPath).Length, 35, 55, progress);
                    await using (var tIn = File.OpenRead(threefishPath))
                    await using (var tOut = File.Create(xchachaPath))
                    {
                        await ParallelCtr.DecryptParallelAsync(
                            tIn, tOut, Keys.ThreefishKey, Keys.ThreefishHmacKey,
                            () => new ThreefishEngine(1024), threefishIv,
                            threefishTag, aesProgress);
                    }

                    // Step 5: XChaCha20 decryption
                    var xchachaProgress = CreateSegmentedProgress(new FileInfo(xchachaPath).Length, 55, 75, progress);
                    await using (var xIn = File.OpenRead(xchachaPath))
                    await using (var xOut = File.Create(shuffledPath))
                    {
                        await ParallelCtr.DecryptXChaCha20Poly1305ParallelRawAsync(
                            xIn, xOut, Keys.XChaChaKey, xchachaNonce, xchachaProgress);
                    }

                    // Step 6: Unshuffle layer
                    var unshuffleProgress =
                        CreateSegmentedProgress(new FileInfo(shuffledPath).Length, 75, 100, progress);
                    await using (var shuffledIn = File.OpenRead(shuffledPath))
                    await using (var finalOut = outputStream)
                    {
                        await ParallelCtr.ShuffleLayer.UnshuffleStreamAsync(shuffledIn, finalOut,
                            Keys.ShuffleKey,
                            unshuffleProgress);
                    }

                    progress?.Report(100);
            }
            finally
            {
                // Securely erase temp files
                await SecureFileEraser.SecurelyEraseFileAsync(aesPath, SecureFileEraser.IsSSD(aesPath));
                await SecureFileEraser.SecurelyEraseFileAsync(serpentPath, SecureFileEraser.IsSSD(serpentPath));
                await SecureFileEraser.SecurelyEraseFileAsync(threefishPath, SecureFileEraser.IsSSD(threefishPath));
                await SecureFileEraser.SecurelyEraseFileAsync(xchachaPath, SecureFileEraser.IsSSD(xchachaPath));
                await SecureFileEraser.SecurelyEraseFileAsync(shuffledPath, SecureFileEraser.IsSSD(shuffledPath));
            }
        }

        public static async Task DecryptV3(
        MemoryStream inputStream,
        MemoryStream outputStream,
        DerivedKeys Keys,
        IProgress<double>? progress = null,
        int chunkSize = 64 * 1024)
        {
            // ---- Read IVs / HMAC tags from header ----
            var xchachaNonce = await ReadExactAsync(inputStream, 16);
            var threefishIv = await ReadExactAsync(inputStream, 120);
            var threefishTag = await ReadExactAsync(inputStream, 64);
            var serpentIv = await ReadExactAsync(inputStream, 8);
            var serpentTag = await ReadExactAsync(inputStream, 64);
            var aesIv = await ReadExactAsync(inputStream, 8);
            var aesTag = await ReadExactAsync(inputStream, 64);

            // Temp files for intermediate layers
            var aesPath = Path.GetTempFileName();
            var serpentPath = Path.GetTempFileName();
            var threefishPath = Path.GetTempFileName();
            var xchachaPath = Path.GetTempFileName();
            var shuffledPath = Path.GetTempFileName();

            try
            {
                // Step 1: Copy AES ciphertext to temp
                await using (var aesOut = File.Create(aesPath))
                {
                    await inputStream.CopyToAsync(aesOut);
                }


                // Step 2: AES CTR + HMAC verification
                var aesProgress = CreateSegmentedProgress(new FileInfo(aesPath).Length, 0, 15, progress);
                await using (var aIn = File.OpenRead(aesPath))
                await using (var aOut = File.Create(serpentPath))
                {
                    await ParallelCtr.DecryptParallelAsync(
                        aIn, aOut, Keys.AesKey, Keys.AesHmacKey, () => new AesEngine(), aesIv,
                        aesTag, aesProgress);
                }

                // Step 3: Serpent CTR + HMAC verification
                var serpentProgress = CreateSegmentedProgress(new FileInfo(serpentPath).Length, 15, 35, progress);
                await using (var sIn = File.OpenRead(serpentPath))
                await using (var sOut = File.Create(threefishPath))
                {
                    await ParallelCtr.DecryptParallelAsync(
                        sIn, sOut, Keys.SerpentKey, Keys.SerpentHmacKey,
                        () => new SerpentEngine(), serpentIv,
                        serpentTag, aesProgress);
                }

                // Step 4: Threefish CTR + HMAC verification
                var threefishProgress =
                    CreateSegmentedProgress(new FileInfo(threefishPath).Length, 35, 55, progress);
                await using (var tIn = File.OpenRead(threefishPath))
                await using (var tOut = File.Create(xchachaPath))
                {
                    await ParallelCtr.DecryptParallelAsync(
                        tIn, tOut, Keys.ThreefishKey, Keys.ThreefishHmacKey,
                        () => new ThreefishEngine(1024), threefishIv,
                        threefishTag, aesProgress);
                }

                // Step 5: XChaCha20 decryption
                var xchachaProgress = CreateSegmentedProgress(new FileInfo(xchachaPath).Length, 55, 75, progress);
                await using (var xIn = File.OpenRead(xchachaPath))
                await using (var xOut = File.Create(shuffledPath))
                {
                    await ParallelCtr.DecryptXChaCha20Poly1305ParallelRawAsync(
                        xIn, xOut, Keys.XChaChaKey, xchachaNonce, xchachaProgress);
                }

                // Step 6: Unshuffle layer
                var unshuffleProgress =
                    CreateSegmentedProgress(new FileInfo(shuffledPath).Length, 75, 100, progress);
                await using (var shuffledIn = File.OpenRead(shuffledPath))
                await using (var finalOut = outputStream)
                {
                    await ParallelCtr.ShuffleLayer.UnshuffleStreamAsync(shuffledIn, finalOut,
                        Keys.ShuffleKey,
                        unshuffleProgress);
                }

                progress?.Report(100);
            }
            finally
            {
                // Securely erase temp files
                await SecureFileEraser.SecurelyEraseFileAsync(aesPath, SecureFileEraser.IsSSD(aesPath));
                await SecureFileEraser.SecurelyEraseFileAsync(serpentPath, SecureFileEraser.IsSSD(serpentPath));
                await SecureFileEraser.SecurelyEraseFileAsync(threefishPath, SecureFileEraser.IsSSD(threefishPath));
                await SecureFileEraser.SecurelyEraseFileAsync(xchachaPath, SecureFileEraser.IsSSD(xchachaPath));
                await SecureFileEraser.SecurelyEraseFileAsync(shuffledPath, SecureFileEraser.IsSSD(shuffledPath));
            }
        }


        public static class ParallelCtr
        {
            public static async Task EncryptXChaCha20Poly1305ParallelRawAsync(
                Stream input,
                Stream output,
                byte[] key,
                byte[] baseNonce,
                IProgress<long>? progress = null,
                int chunkSize = 64 * 1024,
                int maxParallelism = 4)
            {
                using var semaphore = new SemaphoreSlim(maxParallelism);
                var tasks = new List<Task>();
                var writeLock = new object();
                long chunkIndex = 0;
                long totalBytesProcessed = 0;

                while (true)
                {
                    var buffer = new byte[chunkSize];
                    var bytesRead = await input.ReadAsync(buffer, 0, chunkSize);
                    if (bytesRead <= 0) break;

                    var chunk = new byte[bytesRead];
                    Buffer.BlockCopy(buffer, 0, chunk, 0, bytesRead);
                    CryptoUtilities.ZeroMemory(buffer); // zero plaintext buffer

                    var currentIndex = chunkIndex++;
                    await semaphore.WaitAsync();

                    tasks.Add(Task.Run(() =>
                    {
                        try
                        {
                            var nonce = DeriveNonce(baseNonce, currentIndex, 24);
                            var ciphertext = SecretAeadXChaCha20Poly1305.Encrypt(chunk, nonce, key);

                            lock (writeLock)
                            {
                                var lenBytes = BitConverter.GetBytes(ciphertext.Length);
                                output.Write(lenBytes, 0, lenBytes.Length);
                                output.Write(ciphertext, 0, ciphertext.Length);
                            }

                            Interlocked.Add(ref totalBytesProcessed, chunk.Length);
                            progress?.Report(totalBytesProcessed);
                        }
                        catch (Exception ex)
                        {
                            FileLogger.Log($"Encrypt task error: {ex}");
                            throw; // propagate to Task.WhenAll
                        }
                        finally
                        {
                            CryptoUtilities.ZeroMemory(chunk);
                            semaphore.Release();
                        }
                    }));
                }

                await Task.WhenAll(tasks);
            }

            public static async Task DecryptXChaCha20Poly1305ParallelRawAsync(
                Stream input,
                Stream output,
                byte[] key,
                byte[] baseNonce,
                IProgress<long>? progress = null,
                int chunkSize = 64 * 1024,
                int maxParallelism = 4)
            {
                using var semaphore = new SemaphoreSlim(maxParallelism);
                var tasks = new List<Task>();
                var chunkOutputs = new ConcurrentDictionary<long, byte[]>();
                long chunkIndex = 0;
                long totalBytesProcessed = 0;

                while (input.Position < input.Length)
                {
                    var lenBytes = new byte[4];
                    int lenRead = await input.ReadAsync(lenBytes, 0, 4);
                    if (lenRead < 4) throw new EndOfStreamException("Failed to read chunk length.");
                    int chunkLength = BitConverter.ToInt32(lenBytes, 0);
                    if (chunkLength <= 0 || chunkLength > 100 * 1024 * 1024)
                        throw new InvalidDataException($"Invalid chunk length: {chunkLength}");

                    var buffer = await ReadExactAsync(input, chunkLength);
                    if (buffer.Length != chunkLength)
                        throw new EndOfStreamException("Could not read full chunk.");

                    var currentIndex = chunkIndex++;
                    await semaphore.WaitAsync();

                    tasks.Add(Task.Run(() =>
                    {
                        try
                        {
                            var nonce = DeriveNonce(baseNonce, currentIndex, 24);
                            var plaintext = SecretAeadXChaCha20Poly1305.Decrypt(buffer, nonce, key);

                            chunkOutputs[currentIndex] = plaintext;
                            Interlocked.Add(ref totalBytesProcessed, plaintext.Length);
                            progress?.Report(totalBytesProcessed);
                        }
                        finally
                        {
                            CryptoUtilities.ZeroMemory(buffer); // zero ciphertext
                            semaphore.Release();
                        }
                    }));
                }

                await Task.WhenAll(tasks);

                // Write in order
                for (long i = 0; i < chunkIndex; i++)
                {
                    if (!chunkOutputs.TryGetValue(i, out var chunk))
                        throw new InvalidOperationException($"Missing decrypted chunk {i}");
                    await output.WriteAsync(chunk, 0, chunk.Length);
                    CryptoUtilities.ZeroMemory(chunk);
                }

            }

            private static byte[] DeriveNonce(byte[] baseIv, long index, int requiredLength)
            {
                if (baseIv.Length > requiredLength - 8)
                    throw new ArgumentException("Base IV too long for derived nonce");

                var nonce = new byte[requiredLength];
                Buffer.BlockCopy(baseIv, 0, nonce, 0, baseIv.Length);
                Buffer.BlockCopy(BitConverter.GetBytes((ulong)index), 0, nonce, requiredLength - 8, 8);
                return nonce;
            }

            public static async Task<byte[]> EncryptParallelAsync(
                Stream input,
                Stream output,
                byte[] key,
                byte[] hmacKey,
                Func<IBlockCipher> cipherFactory,
                byte[] baseIv,
                IProgress<long> progress = null,
                int chunkSize = 64 * 1024,
                int maxParallelism = 4)
            {
                FileLogger.Log("=== EncryptParallelAsync: Starting encryption ===");
                FileLogger.Log(
                    $"EncryptParallelAsync: Base IV ({baseIv.Length} bytes): {Convert.ToHexString(baseIv)}");

                using var hmac = new HmacSha3Stream(hmacKey);

                // Configure TPL Dataflow
                var options = new ExecutionDataflowBlockOptions
                {
                    MaxDegreeOfParallelism = maxParallelism,
                    EnsureOrdered = true
                };

                var encryptBlock = new TransformBlock<(byte[] buffer, int bytesRead, long index),
                    (int index, byte[] ciphertext, int length)>(
                    task =>
                    {
                        try
                        {
                            var (buffer, bytesRead, index) = task;

                            var engine = cipherFactory();
                            var cipher = new SicBlockCipher(engine);
                            var blockSize = cipher.GetBlockSize();

                            var nonce = DeriveNonce(baseIv, index, blockSize);
                            cipher.Init(true, new ParametersWithIV(new KeyParameter(key), nonce));

                            var encrypted = new byte[bytesRead];
                            int processed = 0;

                            // Process full blocks
                            var fullBlocks = bytesRead / blockSize;
                            for (int i = 0; i < fullBlocks; i++)
                            {
                                cipher.ProcessBlock(buffer, i * blockSize, encrypted, i * blockSize);
                                processed += blockSize;
                            }

                            // Handle final partial block
                            var remaining = bytesRead - processed;
                            if (remaining > 0)
                            {
                                var keystreamBlock = new byte[blockSize];
                                cipher.ProcessBlock(new byte[blockSize], 0, keystreamBlock, 0);
                                for (int i = 0; i < remaining; i++)
                                    encrypted[processed + i] = (byte)(buffer[processed + i] ^ keystreamBlock[i]);
                                CryptoUtilities.ZeroMemory(keystreamBlock);
                            }

                            CryptoUtilities.ZeroMemory(buffer);

                            return ((int)index, encrypted, bytesRead);
                        }
                        catch (Exception ex)
                        {
                            FileLogger.Log($"encryptBlock exception: {ex}");
                            throw;
                        }
                    }, options);

                long totalBytesProcessed = 0;

                var writeBlock = new ActionBlock<(int index, byte[] ciphertext, int length)>(async result =>
                {
                    try
                    {
                        var (index, ciphertext, length) = result;
                        await output.WriteAsync(ciphertext, 0, length).ConfigureAwait(false);

                        hmac.Update(ciphertext, 0, length);

                        Interlocked.Add(ref totalBytesProcessed, length);
                        progress?.Report(totalBytesProcessed);

                        CryptoUtilities.ZeroMemory(ciphertext);
                    }
                    catch (Exception ex)
                    {
                        FileLogger.Log($"writeBlock exception: {ex}");
                        throw;
                    }
                }, new ExecutionDataflowBlockOptions { MaxDegreeOfParallelism = 1 });

                // Link blocks with completion propagation
                encryptBlock.LinkTo(writeBlock, new DataflowLinkOptions { PropagateCompletion = true });

                // Read input and send chunks
                long chunkIndex = 0;
                while (true)
                {
                    var buffer = new byte[chunkSize];
                    int bytesRead = await input.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                    if (bytesRead == 0) break;

                    if (bytesRead < buffer.Length)
                        Array.Resize(ref buffer, bytesRead);

                    bool sent = await encryptBlock.SendAsync((buffer, bytesRead, chunkIndex)).ConfigureAwait(false);
                    if (!sent) throw new InvalidOperationException("Failed to send data to encrypt block.");

                    chunkIndex++;
                }

                // Signal completion
                encryptBlock.Complete();

                // Await final completion
                await writeBlock.Completion.ConfigureAwait(false);

                // Final HMAC
                var hmacTag = hmac.Final();
                FileLogger.Log("=== EncryptParallelAsync: Completed encryption ===");

                return hmacTag;
            }


            public static async Task DecryptParallelAsync(Stream input,
                Stream output,
                byte[] key,
                byte[] hmacKey,
                Func<IBlockCipher> cipherFactory,
                byte[] baseIv,
                byte[] expectedTag,
                IProgress<long>? progress = null,
                int chunkSize = 64 * 1024,
                int maxParallelism = 4)
            {
                FileLogger.Log("=== DecryptParallelAsync: Starting decryption ===");
                FileLogger.LogBytes("DecryptParallelAsync: Base IV", baseIv);
                FileLogger.LogBytes("DecryptParallelAsync: Expected HMAC Tag", expectedTag);

                using var hmac = new HmacSha3Stream(hmacKey);
                using var sha256 = SHA256.Create();

                var channel = Channel.CreateBounded<(int index, byte[] ciphertext)>(maxParallelism * 2);
                var writer = channel.Writer;
                var reader = channel.Reader;

                var chunkIndex = 0;

                // Producer reads until end of stream
                var producer = Task.Run(async () =>
                {
                    var buffer = new byte[chunkSize];
                    int bytesRead;

                    while ((bytesRead = await input.ReadAsync(buffer, 0, chunkSize).ConfigureAwait(false)) > 0)
                    {
                        var chunk = new byte[bytesRead];
                        Buffer.BlockCopy(buffer, 0, chunk, 0, bytesRead);

                        hmac.Update(chunk, 0, chunk.Length);
                        sha256.TransformBlock(chunk, 0, chunk.Length, null, 0);

                        await writer.WriteAsync((chunkIndex++, chunk)).ConfigureAwait(false);
                    }

                    writer.Complete();
                });

                var processedChunks = new ConcurrentDictionary<int, byte[]>();
                var nextWriteIndex = 0;
                var writeLock = new SemaphoreSlim(1, 1);

                var processors = Enumerable.Range(0, maxParallelism).Select(_ => Task.Run(async () =>
                {
                    await foreach (var (index, ciphertext) in reader.ReadAllAsync())
                    {
                        var engine = cipherFactory();
                        var cipher = new SicBlockCipher(engine);
                        var blockSize = cipher.GetBlockSize();

                        var nonce = DeriveNonce(baseIv, index, blockSize);
                        FileLogger.LogBytes($"DecryptParallelAsync: Nonce [chunk {index}]", nonce);

                        cipher.Init(false, new ParametersWithIV(new KeyParameter(key), nonce));

                        var decrypted = new byte[ciphertext.Length];
                        var processed = 0;

                        var fullBlocks = ciphertext.Length / blockSize;
                        for (var i = 0; i < fullBlocks; i++)
                        {
                            cipher.ProcessBlock(ciphertext, i * blockSize, decrypted, i * blockSize);
                            processed += blockSize;
                        }

                        var remaining = ciphertext.Length - processed;
                        if (remaining > 0)
                        {
                            var keystreamBlock = new byte[blockSize];
                            cipher.ProcessBlock(new byte[blockSize], 0, keystreamBlock, 0);
                            for (var i = 0; i < remaining; i++)
                                decrypted[processed + i] = (byte)(ciphertext[processed + i] ^ keystreamBlock[i]);
                        }

                        processedChunks[index] = decrypted;

                        await writeLock.WaitAsync().ConfigureAwait(false);
                        try
                        {
                            while (processedChunks.TryRemove(nextWriteIndex, out var readyPlaintext))
                            {
                                await output.WriteAsync(readyPlaintext, 0, readyPlaintext.Length).ConfigureAwait(false);
                                progress?.Report(readyPlaintext.Length);
                                nextWriteIndex++;
                            }
                        }
                        finally
                        {
                            writeLock.Release();
                        }
                    }
                })).ToArray();

                await producer.ConfigureAwait(false);
                await Task.WhenAll(processors).ConfigureAwait(false);

                sha256.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                var ciphertextHash = BitConverter.ToString(sha256.Hash!).Replace("-", "");
                FileLogger.Log($"DecryptParallelAsync: Ciphertext SHA256 hash: {ciphertextHash}");

                var actualTag = hmac.Final();

                if (actualTag.Length > expectedTag.Length)
                    actualTag = actualTag.AsSpan(0, expectedTag.Length).ToArray();

                FileLogger.LogBytes("DecryptParallelAsync: Computed HMAC Tag", actualTag);

                if (!CryptographicOperations.FixedTimeEquals(expectedTag, actualTag))
                {
                    FileLogger.Log("DecryptParallelAsync: HMAC verification failed!");
                    throw new CryptographicException("HMAC verification failed.");
                }

                await output.FlushAsync().ConfigureAwait(false);
                FileLogger.Log("=== DecryptParallelAsync: Decryption complete ===");

                writeLock.Dispose();
            }

            public static class ShuffleLayer
            {
                // Chunk size default: 64 KB
                public static async Task ShuffleStreamAsync(
                    Stream input,
                    Stream output,
                    byte[] key,
                    IProgress<long>? progress = null,
                    int chunkSize = 64 * 1024,
                    int maxParallelism = 4)
                {
                    var totalLength = input.Length;
                    long processed = 0;

                    var bufferPool = new BufferPool(chunkSize, maxParallelism);

                    var tasks = new List<Task>();

                    await foreach (var chunk in StreamChunker.ReadChunksAsync(input, chunkSize))
                    {
                        var buffer = bufferPool.Rent();
                        Array.Copy(chunk, buffer, chunk.Length);

                        tasks.Add(Task.Run(async () =>
                        {
                            try
                            {
                                CryptoUtilities.XorTransform(buffer, key); // simple keyed shuffle
                                await output.WriteAsync(buffer, 0, chunk.Length);
                                Interlocked.Add(ref processed, chunk.Length);
                                progress?.Report((long)processed / totalLength * 100);
                            }
                            finally
                            {
                                CryptoUtilities.ZeroMemory(buffer);
                                bufferPool.Return(buffer);
                            }
                        }));

                        if (tasks.Count >= maxParallelism)
                        {
                            await Task.WhenAll(tasks);
                            tasks.Clear();
                        }
                    }

                    if (tasks.Count > 0)
                        await Task.WhenAll(tasks);
                }

                public static async Task UnshuffleStreamAsync(
                    Stream input,
                    Stream output,
                    byte[] key,
                    IProgress<long>? progress = null,
                    int chunkSize = 64 * 1024,
                    int maxParallelism = 4)
                {
                    var totalLength = input.Length;
                    long processed = 0;

                    var bufferPool = new BufferPool(chunkSize, maxParallelism);

                    var tasks = new List<Task>();

                    await foreach (var chunk in StreamChunker.ReadChunksAsync(input, chunkSize))
                    {
                        var buffer = bufferPool.Rent();
                        Array.Copy(chunk, buffer, chunk.Length);

                        tasks.Add(Task.Run(async () =>
                        {
                            try
                            {
                                CryptoUtilities.XorTransform(buffer, key); // reverse shuffle is identical
                                await output.WriteAsync(buffer, 0, chunk.Length);
                                Interlocked.Add(ref processed, chunk.Length);
                                progress?.Report((long)processed / totalLength * 100);
                            }
                            finally
                            {
                                CryptoUtilities.ZeroMemory(buffer);
                                bufferPool.Return(buffer);
                            }
                        }));

                        if (tasks.Count >= maxParallelism)
                        {
                            await Task.WhenAll(tasks);
                            tasks.Clear();
                        }
                    }

                    if (tasks.Count > 0)
                        await Task.WhenAll(tasks);
                }
            }
        }

        internal static class VaultEncryption
        {
            public const int FileKeySaltSize = 128;
            public const int LayerSaltSize = 128;
            public const int NumLayerSalts = 8;

            public static async Task EncryptVaultAsync(
                Stream plaintext,
                Stream output,
                DerivedKeys keys,
                byte[] fileKeySalt,
                byte[][] layerSalts,
                IProgress<double>? progress = null,
                int chunkSize = 64 * 1024)
            {
                // ---------- Generate IVs ----------
                byte[] xchachaNonce = RandomNumberGenerator.GetBytes(16);
                byte[] threefishIv = RandomNumberGenerator.GetBytes(120);
                byte[] serpentIv = RandomNumberGenerator.GetBytes(8);
                byte[] aesIv = RandomNumberGenerator.GetBytes(8);

                // ---------- Temp streams ----------
                using var stage1 = new MemoryStream();
                using var stage2 = new MemoryStream();
                using var stage3 = new MemoryStream();
                using var stage4 = new MemoryStream();
                using var stage5 = new MemoryStream();

                // ---------- Encrypt layers ----------
                await ParallelCtr.ShuffleLayer.ShuffleStreamAsync(plaintext, stage1, keys.ShuffleKey);
                stage1.Position = 0;
                await ParallelCtr.EncryptXChaCha20Poly1305ParallelRawAsync(stage1, stage2, keys.XChaChaKey, xchachaNonce);
                stage2.Position = 0;
                byte[] threefishTag = await ParallelCtr.EncryptParallelAsync(stage2, stage3, keys.ThreefishKey, keys.ThreefishHmacKey, () => new ThreefishEngine(1024), threefishIv);
                stage3.Position = 0;
                byte[] serpentTag = await ParallelCtr.EncryptParallelAsync(stage3, stage4, keys.SerpentKey, keys.SerpentHmacKey, () => new SerpentEngine(), serpentIv);
                stage4.Position = 0;
                byte[] aesTag = await ParallelCtr.EncryptParallelAsync(stage4, stage5, keys.AesKey, keys.AesHmacKey, () => new AesEngine(), aesIv);

                // ---------- Write header ----------
                output.WriteByte(0xA4); // Vault magic
                output.WriteByte(0x01); // Version

                await output.WriteAsync(fileKeySalt);
                foreach (var salt in layerSalts) await output.WriteAsync(salt);

                await output.WriteAsync(xchachaNonce);
                await output.WriteAsync(threefishIv);
                await output.WriteAsync(serpentIv);
                await output.WriteAsync(aesIv);

                await output.WriteAsync(threefishTag);
                await output.WriteAsync(serpentTag);
                await output.WriteAsync(aesTag);

                // ---------- Write ciphertext ----------
                stage5.Position = 0;
                await stage5.CopyToAsync(output);

                MemoryHandling.Clear(xchachaNonce, threefishIv, serpentIv, aesIv);
            }

            public static async Task DecryptVaultAsync(
      Stream encryptedVault,
      Stream output,
      DerivedKeys keys,
      IProgress<double>? progress = null,
      int chunkSize = 64 * 1024)
            {
                // ---------- Read magic + version ----------
                int magic = encryptedVault.ReadByte();
                int version = encryptedVault.ReadByte();

                if (magic != 0xA4 || version != 0x01)
                    throw new CryptographicException("Invalid vault format.");

                // ---------- Read IVs ----------
                byte[] xchachaNonce = await HelperMethods.ReadExactAsync(encryptedVault, 16);
                byte[] threefishIv = await HelperMethods.ReadExactAsync(encryptedVault, 120);
                byte[] serpentIv = await HelperMethods.ReadExactAsync(encryptedVault, 8);
                byte[] aesIv = await HelperMethods.ReadExactAsync(encryptedVault, 8);

                // ---------- Read HMAC tags ----------
                byte[] threefishTag = await HelperMethods.ReadExactAsync(encryptedVault, 64);
                byte[] serpentTag = await HelperMethods.ReadExactAsync(encryptedVault, 64);
                byte[] aesTag = await HelperMethods.ReadExactAsync(encryptedVault, 64);

                // ---------- Decrypt layers in reverse order ----------
                using var stage5 = new MemoryStream();
                await encryptedVault.CopyToAsync(stage5);
                stage5.Position = 0;

                using var stage4 = new MemoryStream();
                await ParallelCtr.DecryptParallelAsync(
                    stage5,
                    stage4,
                    keys.AesKey,
                    keys.AesHmacKey,
                    () => new AesEngine(),
                    aesIv,
                    aesTag
                );

                stage4.Position = 0;
                using var stage3 = new MemoryStream();
                await ParallelCtr.DecryptParallelAsync(
                    stage4,
                    stage3,
                    keys.SerpentKey,
                    keys.SerpentHmacKey,
                    () => new SerpentEngine(),
                    serpentIv,
                    serpentTag
                );

                stage3.Position = 0;
                using var stage2 = new MemoryStream();
                await ParallelCtr.DecryptParallelAsync(
                    stage3,
                    stage2,
                    keys.ThreefishKey,
                    keys.ThreefishHmacKey,
                    () => new ThreefishEngine(1024),
                    threefishIv,
                    threefishTag
                );

                stage2.Position = 0;
                using var stage1 = new MemoryStream();
                await ParallelCtr.DecryptXChaCha20Poly1305ParallelRawAsync(
                    stage2,
                    stage1,
                    keys.XChaChaKey,
                    xchachaNonce
                );

                stage1.Position = 0;
                await ParallelCtr.ShuffleLayer.UnshuffleStreamAsync(
                    stage1,
                    output,
                    keys.ShuffleKey
                );

                // ---------- Clear sensitive buffers ----------
                MemoryHandling.Clear(xchachaNonce, threefishIv, serpentIv, aesIv);
            }

        }


        // Simple buffer pool for parallel tasks
        public sealed class BufferPool
            {
                private readonly int bufferSize;
                private readonly ConcurrentBag<byte[]> pool = new();

                public BufferPool(int bufferSize, int preAllocate = 4)
                {
                    this.bufferSize = bufferSize;
                    for (var i = 0; i < preAllocate; i++)
                        pool.Add(new byte[bufferSize]);
                }

                public byte[] Rent()
                {
                    return pool.TryTake(out var buffer) ? buffer : new byte[bufferSize];
                }

                public void Return(byte[] buffer)
                {
                    CryptoUtilities.ZeroMemory(buffer);
                    pool.Add(buffer);
                }
            }

// Chunked async reader for streams
            public static class StreamChunker
            {
                public static async IAsyncEnumerable<byte[]> ReadChunksAsync(Stream input, int chunkSize)
                {
                    var buffer = new byte[chunkSize];
                    int read;
                    while ((read = await input.ReadAsync(buffer, 0, chunkSize)) > 0)
                        if (read < chunkSize)
                        {
                            var tmp = new byte[read];
                            Array.Copy(buffer, tmp, read);
                            yield return tmp;
                        }
                        else
                        {
                            yield return buffer.ToArray();
                        }

                    CryptoUtilities.ZeroMemory(buffer);
                }
            }

// XOR-based keyed transform (shuffle)
            public static class CryptoUtilities
            {
                public static void XorTransform(byte[] data, byte[] key)
                {
                    var keyLen = key.Length;
                    for (var i = 0; i < data.Length; i++)
                        data[i] ^= key[i % keyLen];
                }

                public static void ZeroMemory(params byte[][] buffers)
                {
                    foreach (var b in buffers)
                        if (b != null)
                            Array.Clear(b, 0, b.Length);
                }
            }
        }
    }