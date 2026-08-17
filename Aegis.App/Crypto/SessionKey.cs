using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Aegis.App.Crypto
{
    public sealed class SessionKey : IDisposable
    {
        private byte[]? _key;

        private bool _disposed;


        public SessionKey(byte[] key)
        {
            if (key == null ||
                key.Length == 0)
            {
                throw new ArgumentException(
                    "Invalid session key.",
                    nameof(key));
            }

            _key = new byte[key.Length];

            Buffer.BlockCopy(
                key,
                0,
                _key,
                0,
                key.Length);
        }


        public byte[] Export()
        {
            if (_disposed ||
                _key == null)
            {
                throw new ObjectDisposedException(
                    nameof(SessionKey));
            }


            byte[] copy =
                new byte[_key.Length];

            Buffer.BlockCopy(
                _key,
                0,
                copy,
                0,
                _key.Length);

            return copy;
        }


        public void Dispose()
        {
            if (_disposed)
                return;


            _disposed = true;


            if (_key != null)
            {
                CryptographicOperations.ZeroMemory(
                    _key);

                _key = null;
            }

            GC.SuppressFinalize(this);
        }
    }
}
