using Aegis.App.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Aegis.App.Session
{
    public static class Session
    {
        private static UserSession _userSession;
        private static CryptoSession _cryptoSession;

        // ---------------------------
        // Session management
        // ---------------------------
        public static void Start(UserSession user, CryptoSession crypto)
        {
            _cryptoSession?.Dispose();      // dispose any previous crypto session
            _cryptoSession = crypto ?? throw new ArgumentNullException(nameof(crypto));
            _userSession = user ?? throw new ArgumentNullException(nameof(user));
        }

        public static void End()
        {
            _cryptoSession?.Dispose();
            _cryptoSession = null;
            _userSession = null;
        }

        // ---------------------------
        // Lambda-style accessors
        // ---------------------------
        public static Func<string?> GetUsername => () => _userSession?.Username;

        public static Func<byte[]?> GetUserId => () => _userSession?.UserId;

        public static Func<CryptoSession?> GetCryptoSession => () => _cryptoSession;

        public static Func<bool> IsMasterKeyInitialized => () =>
            _cryptoSession?.IsMasterKeyInitialized == true;

        public static Action DisposeCryptoSession => () =>
        {
            _cryptoSession?.Dispose();
            _cryptoSession = null;
        };

        public static Action DisposeUserSession => () =>
        {
            DisposeCryptoSession();
            _userSession = null;
        };
    }

    public sealed class UserSession
    {
        public string Username { get; }
        public byte[] UserId { get; }   // optional, better than username long-term

        public UserSession(string username, byte[] userId = null)
        {
            Username = username ?? throw new ArgumentNullException(nameof(username));
            UserId = userId;
        }
    }
    public interface IUserSessionService
    {
        UserSession Current { get; }
    }

    public sealed class UserSessionService : IUserSessionService
    {
        public UserSession Current { get; private set; }

        public void StartSession(UserSession session)
        {
            Current = session;
        }

        public void EndSession()
        {
            Current = null;
        }
    }

    public sealed class CryptoSession : IDisposable
    {
        private SecureMasterKey _masterKey;
        private bool _disposed;

        /// <summary>
        /// The current secure master key. Null if not initialized.
        /// </summary>
        public SecureMasterKey MasterKey => _disposed ? null : _masterKey;

        /// <summary>
        /// Indicates if a master key is loaded and usable.
        /// </summary>
        public bool IsMasterKeyInitialized => _masterKey?.IsInitialized == true && !_disposed;

        /// <summary>
        /// Initializes a new crypto session with a SecureMasterKey.
        /// </summary>
        public CryptoSession(SecureMasterKey masterKey)
        {
            _masterKey = masterKey ?? throw new ArgumentNullException(nameof(masterKey));
        }

        /// <summary>
        /// Safely replaces the current master key with a new one, disposing the old.
        /// </summary>
        public void SetMasterKey(SecureMasterKey newMasterKey)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(CryptoSession));

            _masterKey?.Dispose();
            _masterKey = newMasterKey ?? throw new ArgumentNullException(nameof(newMasterKey));
        }

        /// <summary>
        /// Clears the master key from memory and disposes the session.
        /// </summary>
        public void Dispose()
        {
            if (_disposed) return;

            _masterKey?.Dispose();
            _masterKey = null;

            _disposed = true;
            GC.SuppressFinalize(this);
        }

        ~CryptoSession() => Dispose();
    }
}
