using System.Security;
using Aegis.App.Crypto;

namespace Aegis.App.Ipc;

public static class ClientSessionManager
{
    private static readonly Lock SyncRoot = new();

    private static ClientSession? _current;

    public static bool IsAuthenticated
    {
        get
        {
            ClientSession? session;

            lock (SyncRoot)
            {
                session = _current;
            }

            if (session is null)
                return false;

            try
            {
                if (session.IsExpired())
                {
                    Clear();
                    return false;
                }

                return true;
            }
            catch (ObjectDisposedException)
            {
                return false;
            }
        }
    }

    public static ClientSession Current
    {
        get
        {
            ClientSession? session;

            lock (SyncRoot)
            {
                session =
                    _current
                    ?? throw new SecurityException(
                        "No authenticated session.");
            }

            try
            {
                if (session.IsExpired())
                {
                    ClearIfCurrent(session);

                    throw new SecurityException(
                        "Session expired.");
                }

                return session;
            }
            catch (ObjectDisposedException)
            {
                throw new SecurityException(
                    "No authenticated session.");
            }
        }
    }

    public static void Set(
        ClientSession session)
    {
        ArgumentNullException.ThrowIfNull(
            session);

        ClientSession? oldSession;

        lock (SyncRoot)
        {
            oldSession = _current;
            _current = session;
        }

        if (oldSession is not null &&
            !ReferenceEquals(
                oldSession,
                session))
        {
            oldSession.Dispose();
        }
    }

    public static void Clear()
    {
        ClientSession? oldSession;

        lock (SyncRoot)
        {
            oldSession = _current;
            _current = null;
        }

        oldSession?.Dispose();
    }

    private static void ClearIfCurrent(
        ClientSession session)
    {
        bool shouldDispose = false;

        lock (SyncRoot)
        {
            if (ReferenceEquals(
                    _current,
                    session))
            {
                _current = null;
                shouldDispose = true;
            }
        }

        if (shouldDispose)
        {
            session.Dispose();
        }
    }
}
