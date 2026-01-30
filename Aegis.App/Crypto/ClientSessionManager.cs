using Aegis.Contracts;
using System;
using System.Collections.Generic;
using System.Security;
using System.Text;

namespace Aegis.App.Crypto
{
    public static class ClientSessionManager
    {
        private static readonly object SyncRoot = new();

        private static ClientSession? _current;

        public static ClientSession Current
        {
            get
            {
                lock (SyncRoot)
                {
                    return _current
                           ?? throw new SecurityException(
                               "No authenticated user session.");
                }
            }
        }

        public static bool IsAuthenticated
        {
            get
            {
                lock (SyncRoot)
                {
                    return _current != null;
                }
            }
        }

        public static void Set(
            ClientSession session)
        {
            ArgumentNullException.ThrowIfNull(session);

            ClientSession? oldSession;

            lock (SyncRoot)
            {
                oldSession = _current;
                _current = session;
            }

            oldSession?.Dispose();
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
    }
}
