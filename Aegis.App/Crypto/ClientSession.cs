using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;

namespace Aegis.App.Crypto
{
    public sealed class ClientSession : IDisposable
    {
        private SessionKey? _sessionKey;

        private bool _disposed;

        private ulong _counter;

        private readonly object _counterLock = new();

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
            Username = username;
            SessionId = sessionId;
            CreatedUtc = createdUtc;
            ExpiresUtc = expiresUtc;
            ProtocolVersion = protocolVersion;

            _sessionKey =
                new SessionKey(sessionKey);

            _counter = 0;
        }


        public SessionKey SessionKey =>
            _sessionKey ??
            throw new ObjectDisposedException(
                nameof(ClientSession));


        internal ulong NextCounter()
        {
            lock (_counterLock)
            {
                ObjectDisposedException.ThrowIf(
                    _disposed,
                    this);

                return ++_counter;
            }
        }


        public void Dispose()
        {
            if (_disposed)
                return;

            lock (_counterLock)
            {
                if (_disposed)
                    return;

                _disposed = true;
                _counter = 0;
            }

            _sessionKey?.Dispose();
            _sessionKey = null;

            SessionId = null;

            GC.SuppressFinalize(this);
        }
    }
}
