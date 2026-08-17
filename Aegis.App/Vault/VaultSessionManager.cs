using System;
using System.Collections.Generic;
using System.Security;
using System.Text;

namespace Aegis.App.Vault
{
    public sealed class VaultSessionManager : IDisposable
    {
        private static VaultSessionManager? _instance;
        private static readonly object _lock = new();

        public static VaultSessionManager Current =>
            _instance ?? throw new SecurityException("Vault locked.");

        private RamCryptoSession? _ramSession;
        private Timer? _timer;
        private readonly TimeSpan _timeout;

        private VaultSessionManager(TimeSpan timeout)
        {
            _timeout = timeout;
        }

        public static void Unlock(RamCryptoSession session, TimeSpan timeout)
        {
            lock (_lock)
            {
                _instance?.Dispose();
                _instance = new VaultSessionManager(timeout)
                {
                    _ramSession = session
                };
                _instance.ResetTimer();
            }
        }

        public RamCryptoSession RamSession => _ramSession!;

        private void ResetTimer()
        {
            _timer?.Dispose();
            _timer = new Timer(_ => Lock(), null, _timeout, Timeout.InfiniteTimeSpan);
        }

        public void Lock()
        {
            _ramSession?.Dispose();
            _ramSession = null;
        }

        public void Dispose() => Lock();
    }

}
