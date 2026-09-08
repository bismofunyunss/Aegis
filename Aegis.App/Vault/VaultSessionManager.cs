using Aegis.App.Vault.VaultEntry;
using System;
using System.Collections.Generic;
using System.Security;
using System.Text;
using System.Windows;

namespace Aegis.App.Vault
{
    public sealed class VaultSessionManager : IDisposable
    {
        private static VaultSessionManager? _instance;

        private static readonly object _sync = new();

        private RamCryptoSession? _ramSession;

        private Timer? _timer;

        private readonly TimeSpan _timeout;

        private bool _locked;
        private bool _disposed;

        private VaultSessionManager(TimeSpan timeout)
        {
            if (timeout <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(timeout));
            }

            _timeout = timeout;
        }

        public static VaultSessionManager Current
        {
            get
            {
                lock (_sync)
                {
                    if (_instance is null ||
                        _instance._locked ||
                        _instance._disposed)
                    {
                        throw new SecurityException(
                            "Vault is locked.");
                    }

                    return _instance;
                }
            }
        }

        public RamCryptoSession RamSession
        {
            get
            {
                lock (_sync)
                {
                    if (_locked ||
                        _disposed ||
                        _ramSession is null)
                    {
                        throw new SecurityException(
                            "Vault is locked.");
                    }

                    return _ramSession;
                }
            }
        }

        public static void Unlock(
            RamCryptoSession session,
            TimeSpan timeout)
        {
            ArgumentNullException.ThrowIfNull(session);

            VaultSessionManager? oldInstance;

            lock (_sync)
            {
                oldInstance = _instance;

                var manager =
                    new VaultSessionManager(timeout)
                    {
                        _ramSession = session,
                        _locked = false,
                        _disposed = false
                    };

                _instance = manager;

                manager.ResetTimer();
            }

            oldInstance?.Dispose();
        }

        public void Touch()
        {
            lock (_sync)
            {
                if (_locked || _disposed)
                    return;

                ResetTimer();
            }
        }

        private void ResetTimer()
        {
            _timer?.Dispose();

            _timer = new Timer(
                TimerCallback,
                null,
                _timeout,
                Timeout.InfiniteTimeSpan);
        }

        private void TimerCallback(object? state)
        {
            RequestLock();
        }

        public void Lock()
        {
            RequestLock();
        }

        private void RequestLock()
        {
            if (Application.Current?.Dispatcher is { } dispatcher)
            {
                if (dispatcher.CheckAccess())
                {
                    LockCore();
                }
                else
                {
                    _ = dispatcher.InvokeAsync(LockCore);
                }
            }
            else
            {
                LockCore();
            }
        }

        private void LockCore()
        {
            lock (_sync)
            {
                if (_locked || _disposed)
                    return;

                _locked = true;

                _timer?.Dispose();
                _timer = null;
            }

            // Clear UI-bound collection on UI thread.
            foreach (SecureVaultEntry entry in VaultState.Items)
            {
                entry.Dispose();
            }

            VaultState.Items.Clear();

            lock (_sync)
            {
                _ramSession?.Dispose();
                _ramSession = null;
            }
        }

        public void Dispose()
        {
            LockCore();

            lock (_sync)
            {
                if (_disposed)
                    return;

                _disposed = true;

                _timer?.Dispose();
                _timer = null;

                _ramSession?.Dispose();
                _ramSession = null;

                if (ReferenceEquals(_instance, this))
                {
                    _instance = null;
                }
            }

            GC.SuppressFinalize(this);
        }
    }
}
