using System.Security.Cryptography;

namespace Aegis.App.Vault
{
    public sealed class RamCryptoSession : IDisposable
    {
        private SecureBuffer? _key;
        private bool _disposed;

        public RamCryptoSession(byte[] key)
        {
            ArgumentNullException.ThrowIfNull(key);

            if (key.Length != 32)
            {
                throw new ArgumentException(
                    "RamCryptoSession requires a 256-bit key.",
                    nameof(key));
            }

            // SecureBuffer takes ownership of the key
            // and zeroes the source array.
            _key = new SecureBuffer(key);
        }

        private ReadOnlySpan<byte> Key
        {
            get
            {
                ThrowIfDisposed();

                return _key!.AsReadOnlySpan();
            }
        }

        public byte[] Encrypt(
            ReadOnlySpan<byte> plaintext)
        {
            ThrowIfDisposed();

            const int NonceSize = 12;
            const int TagSize = 16;

            byte[] nonce =
                RandomNumberGenerator.GetBytes(
                    NonceSize);

            byte[] result =
                new byte[
                    NonceSize +
                    plaintext.Length +
                    TagSize];

            try
            {
                Span<byte> ciphertext =
                    result.AsSpan(
                        NonceSize,
                        plaintext.Length);

                Span<byte> tag =
                    result.AsSpan(
                        NonceSize + plaintext.Length,
                        TagSize);

                using var aes =
                    new AesGcm(
                        Key,
                        TagSize);

                aes.Encrypt(
                    nonce,
                    plaintext,
                    ciphertext,
                    tag);

                // Result format:
                //
                // [12-byte nonce]
                // [ciphertext]
                // [16-byte tag]
                //
                return result;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(
                    result);

                throw;
            }
        }

        public byte[] Decrypt(
            ReadOnlySpan<byte> encrypted)
        {
            ThrowIfDisposed();

            const int NonceSize = 12;
            const int TagSize = 16;
            const int MinimumSize =
                NonceSize + TagSize;

            if (encrypted.Length < MinimumSize)
            {
                throw new CryptographicException(
                    "Invalid encrypted data.");
            }

            ReadOnlySpan<byte> nonce =
                encrypted[..NonceSize];

            ReadOnlySpan<byte> ciphertext =
                encrypted[
                    NonceSize..^TagSize];

            ReadOnlySpan<byte> tag =
                encrypted[^TagSize..];

            byte[] plaintext =
                new byte[ciphertext.Length];

            try
            {
                using var aes =
                    new AesGcm(
                        Key,
                        TagSize);

                aes.Decrypt(
                    nonce,
                    ciphertext,
                    tag,
                    plaintext);

                return plaintext;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(
                    plaintext);

                throw;
            }
        }

        private void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(
                _disposed,
                this);
        }

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            _key?.Dispose();
            _key = null;

            GC.SuppressFinalize(this);
        }
    }
}
