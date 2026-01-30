using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Aegis.App.Crypto
{
    public sealed class FileKey : IDisposable
    {
        private byte[] _key;
        private bool _disposed;

        internal FileKey(
            SecureMasterKey masterKey,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            int length)
        {
            if (masterKey == null || !masterKey.IsInitialized)
                throw new SecurityException("Master key unavailable.");

            if (length <= 0 || length > 128)
                throw new ArgumentOutOfRangeException(nameof(length));

            _key = masterKey.DeriveKey(salt, info, length);
        }


        /// <summary>
        /// Controlled key usage. Prevents copying and caching.
        /// </summary>
        public void WithKey(Action<ReadOnlySpan<byte>> action)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(FileKey));

            if (action == null)
                throw new ArgumentNullException(nameof(action));

            action(_key);
        }


        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;
            CryptographicOperations.ZeroMemory(_key);
            _key = Array.Empty<byte>();
        }
    }


    public sealed class CryptoMasterKey : IDisposable
    {
        private readonly IntPtr _ptr;
        private readonly int _length;
        private bool _disposed;

        public bool IsInitialized => _ptr != IntPtr.Zero && !_disposed;

        public CryptoMasterKey(ReadOnlySpan<byte> masterKeyMaterial)
        {
            if (masterKeyMaterial.IsEmpty)
                throw new ArgumentException("Master key material cannot be empty.");

            _length = masterKeyMaterial.Length;
            _ptr = Marshal.AllocHGlobal(_length);

            unsafe
            {
                masterKeyMaterial.CopyTo(
                    new Span<byte>((void*)_ptr, _length));
            }
        }

        /// <summary>
        /// INTERNAL DERIVATION SURFACE — DO NOT EXPOSE
        /// Only FileKey may call this.
        /// </summary>
        internal void Derive(
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            int length)
        {
            EnsureAlive();

            unsafe
            {
                var ikm = new ReadOnlySpan<byte>((void*)_ptr, _length);
                CryptoMethods.HKDF.DeriveKey(
                    ikm,
                    salt,
                    info,
                    length);
            }
        }

        private void EnsureAlive()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(CryptoMasterKey));
        }

        public void Dispose()
        {
            if (_disposed)
                return;

            unsafe
            {
                CryptographicOperations.ZeroMemory(
                    new Span<byte>((void*)_ptr, _length));
            }

            Marshal.FreeHGlobal(_ptr);
            _disposed = true;
            GC.SuppressFinalize(this);
        }

        ~CryptoMasterKey() => Dispose();
    }

}
