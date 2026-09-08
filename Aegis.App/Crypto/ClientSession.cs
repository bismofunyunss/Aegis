using Aegis.Contracts;
using System.Security;

namespace Aegis.App.Crypto;

public sealed class ClientSession : IDisposable
{
    private SessionKey? _sessionKey;

    private bool _disposed;

    private ulong _counter;

    private readonly Lock _counterLock = new();

    public string Username { get; }

    public string? SessionId { get; private set; }

    public DateTime CreatedUtc { get; }

    public DateTime ExpiresUtc { get; }

    public string ProtocolVersion { get; }

    public ClientSession(
        string username,
        string sessionId,
        byte[] sessionKey,
        DateTime createdUtc,
        DateTime expiresUtc,
        string protocolVersion)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            username);

        ArgumentException.ThrowIfNullOrWhiteSpace(
            sessionId);

        ArgumentNullException.ThrowIfNull(
            sessionKey);

        ArgumentException.ThrowIfNullOrWhiteSpace(
            protocolVersion);

        ValidateSessionId(
            sessionId);

        if (sessionKey.Length !=
            IpcProtocol.SessionKeySize)
        {
            throw new SecurityException(
                "Invalid session key.");
        }

        if (expiresUtc <= createdUtc)
        {
            throw new SecurityException(
                "Invalid session lifetime.");
        }

        if (expiresUtc <= DateTime.UtcNow)
        {
            throw new SecurityException(
                "Session has already expired.");
        }

        Username =
            username;

        SessionId =
            sessionId;

        CreatedUtc =
            createdUtc;

        ExpiresUtc =
            expiresUtc;

        ProtocolVersion =
            protocolVersion;

        try
        {
            _sessionKey =
                new SessionKey(
                    sessionKey);

            _counter = 0;
        }
        catch
        {
            _sessionKey?.Dispose();
            _sessionKey = null;
            SessionId = null;
            throw;
        }
    }

    public SessionKey SessionKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(
                _disposed,
                this);

            return _sessionKey
                   ?? throw new ObjectDisposedException(
                       nameof(ClientSession));
        }
    }

    internal ulong NextCounter()
    {
        lock (_counterLock)
        {
            ObjectDisposedException.ThrowIf(
                _disposed,
                this);

            if (_counter == ulong.MaxValue)
            {
                throw new SecurityException(
                    "IPC counter exhausted.");
            }

            return ++_counter;
        }
    }

    internal bool IsExpired()
    {
        lock (_counterLock)
        {
            ObjectDisposedException.ThrowIf(
                _disposed,
                this);

            return DateTime.UtcNow >=
                   ExpiresUtc;
        }
    }

    public void Dispose()
    {
        lock (_counterLock)
        {
            if (_disposed)
                return;

            _disposed = true;

            _counter = 0;

            SessionKey? sessionKey =
                _sessionKey;

            _sessionKey = null;

            SessionId = null;

            sessionKey?.Dispose();
        }

        GC.SuppressFinalize(this);
    }

    private static void ValidateSessionId(
        string sessionId)
    {
        if (sessionId.Length != 32)
        {
            throw new SecurityException(
                "Invalid session.");
        }

        foreach (char c in sessionId)
        {
            bool hex =
                c is >= '0' and <= '9'
                or >= 'A' and <= 'F'
                or >= 'a' and <= 'f';

            if (!hex)
            {
                throw new SecurityException(
                    "Invalid session.");
            }
        }
    }
}
