using System.Security;
using System.Security.Cryptography;
using static Aegis.App.Session.Session;

namespace Aegis.App.Crypto;

public sealed class FileKey : IDisposable
{
    private bool _disposed;
    private byte[] _key;

    internal FileKey(
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> info,
        int length)
    {
        if (length <= 0 || length > 128)
            throw new ArgumentOutOfRangeException(nameof(length));

        var session = SessionManager.Crypto;

        if (session == null || !session.IsMasterKeyInitialized)
            throw new SecurityException("No active crypto session.");

        _key = session.DeriveKey(salt, info, length);
    }


    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        CryptographicOperations.ZeroMemory(_key);
        _key = Array.Empty<byte>();
    }

    /// Controlled key usage — no copying
    public void WithKey(Action<ReadOnlySpan<byte>> action)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(FileKey));

        action(_key);
    }
}