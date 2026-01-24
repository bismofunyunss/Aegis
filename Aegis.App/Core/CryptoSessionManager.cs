using Aegis.App.Session;
using System;
using System.Collections.Generic;
using System.Security;
using System.Text;

namespace Aegis.App.Core
{
    public static class CryptoSessionManager
    {
        private static Session.Session.CryptoSession _current;
        private static readonly object _lock = new();

        public static bool IsAuthenticated
        {
            get
            {
                lock (_lock)
                    return _current?.IsMasterKeyInitialized == true;
            }
        }

        public static Session.Session.CryptoSession Current
        {
            get
            {
                lock (_lock)
                {
                    if (_current == null || !_current.IsMasterKeyInitialized)
                        throw new SecurityException("No active crypto session.");
                    return _current;
                }
            }
        }

        public static void StartSession(Session.Session.CryptoSession session)
        {
            if (session == null)
                throw new ArgumentNullException(nameof(session));

            lock (_lock)
            {
                _current?.Dispose(); // kill any previous session
                _current = session;
            }
        }

        public static void EndSession()
        {
            lock (_lock)
            {
                _current?.Dispose();
                _current = null;
            }
        }
    }

}
