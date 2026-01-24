using Aegis.App.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Aegis.App.Session
{
    public class Session
    {
        public static class SessionManager
        {
            private static UserSession? _user;
            private static CryptoSession? _crypto;

            public static void Start(UserSession user, CryptoSession crypto)
            {
                _crypto?.Dispose();
                _user = user ?? throw new ArgumentNullException(nameof(user));
                _crypto = crypto ?? throw new ArgumentNullException(nameof(crypto));
            }

            public static void End()
            {
                _crypto?.Dispose();
                _crypto = null;
                _user = null;
            }

            public static CryptoSession Crypto =>
                _crypto ?? throw new SecurityException("Not logged in.");

            public static UserSession User =>
                _user ?? throw new SecurityException("Not logged in.");
        }



        public sealed class UserSession
        {
            public string Username { get; }
            public byte[] UserId { get; } // optional, better than username long-term

            public UserSession(string username, byte[] userId = null)
            {
                Username = username ?? throw new ArgumentNullException(nameof(username));
                UserId = userId;
            }
        }

        public sealed class CryptoSession : IDisposable
        {
            private SecureMasterKey? _masterKey;
            private bool _disposed;

            public bool IsMasterKeyInitialized =>
                !_disposed && _masterKey?.IsInitialized == true;

            public CryptoSession(SecureMasterKey masterKey)
            {
                _masterKey = masterKey ?? throw new ArgumentNullException(nameof(masterKey));
            }

            public SecureMasterKey MasterKey =>
                _masterKey ?? throw new ObjectDisposedException(nameof(CryptoSession));

            public SecureMasterKey CloneMasterKey()
            {
                EnsureAlive();
                return CloneMasterKey(_masterKey!);
            }

            public static SecureMasterKey CloneMasterKey(SecureMasterKey original)
            {
                if (original == null || !original.IsInitialized)
                    throw new SecurityException("Master key unavailable.");

                var span = original.GetKeySpan();
                var buffer = new byte[span.Length];
                span.CopyTo(buffer);

                return new SecureMasterKey(buffer);
            }

            public byte[] DeriveKey(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info, int length)
            {
                EnsureAlive();
                return _masterKey!.DeriveKey(salt, info, length);
            }

            private void EnsureAlive()
            {
                if (_disposed || _masterKey == null || !_masterKey.IsInitialized)
                    throw new ObjectDisposedException(nameof(CryptoSession));
            }

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
}
