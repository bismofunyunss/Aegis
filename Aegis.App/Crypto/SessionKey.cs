using System.Security.Cryptography;

namespace Aegis.App.Crypto;

public sealed class SessionKey : IDisposable
{
    private const int KeySize = 32;

    private readonly Lock _lock = new();

    private byte[]? _key;

    private bool _disposed;

    public SessionKey(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);

        if (key.Length != KeySize)
        {
            throw new ArgumentException(
                "Invalid session key.",
                nameof(key));
        }

        _key = new byte[KeySize];

        Buffer.BlockCopy(
            key,
            0,
            _key,
            0,
            KeySize);
    }

    public byte[] Export()
    {
        lock (_lock)
        {
            ObjectDisposedException.ThrowIf(
                _disposed,
                this);

            byte[] key = _key!;

            byte[] copy =
                new byte[key.Length];

            Buffer.BlockCopy(
                key,
                0,
                copy,
                0,
                key.Length);

            return copy;
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            if (_disposed)
                return;

            _disposed = true;

            byte[]? key =
                _key;

            _key = null;

            if (key is not null)
            {
                CryptographicOperations.ZeroMemory(
                    key);
            }
        }

        GC.SuppressFinalize(this);
    }
}
