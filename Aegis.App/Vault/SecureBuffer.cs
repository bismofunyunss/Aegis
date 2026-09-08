using Aegis.App.Crypto;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Xceed.Wpf.Toolkit.PropertyGrid.Attributes;

namespace Aegis.App.Vault
{
    #region SecureBuffer

    public sealed unsafe class SecureBuffer : IDisposable
    {
        private IntPtr _ptr;
        private readonly int _length;
        private bool _locked;
        private bool _disposed;

        public int Length => _length;

        public SecureBuffer(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);

            _length = data.Length;

            if (_length == 0)
                return;

            _ptr = Marshal.AllocHGlobal(_length);

            try
            {
                Marshal.Copy(
                    data,
                    0,
                    _ptr,
                    _length);

                _locked =
                    NativeMemory.VirtualLock(
                        _ptr,
                        (UIntPtr)_length);
            }
            catch
            {
                if (_ptr != IntPtr.Zero)
                {
                    CryptographicOperations.ZeroMemory(
                        new Span<byte>(
                            (void*)_ptr,
                            _length));

                    Marshal.FreeHGlobal(_ptr);
                    _ptr = IntPtr.Zero;
                }

                throw;
            }

            // The SecureBuffer now owns the contents.
            CryptographicOperations.ZeroMemory(data);
        }

        public Span<byte> AsSpan()
        {
            ThrowIfDisposed();

            return new Span<byte>(
                (void*)_ptr,
                _length);
        }

        public ReadOnlySpan<byte> AsReadOnlySpan()
        {
            ThrowIfDisposed();

            return new ReadOnlySpan<byte>(
                (void*)_ptr,
                _length);
        }

        public byte[] ToArrayCopy()
        {
            ThrowIfDisposed();

            if (_length == 0)
                return Array.Empty<byte>();

            byte[] copy = new byte[_length];

            Marshal.Copy(
                _ptr,
                copy,
                0,
                _length);

            return copy;
        }

        public void Clear()
        {
            ThrowIfDisposed();

            AsSpan().Clear();
        }

        private void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(
                _disposed,
                this);
        }

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            if (_ptr != IntPtr.Zero)
            {
                CryptographicOperations.ZeroMemory(
                    new Span<byte>(
                        (void*)_ptr,
                        _length));

                if (_locked)
                {
                    NativeMemory.VirtualUnlock(
                        _ptr,
                        (UIntPtr)_length);
                }

                Marshal.FreeHGlobal(_ptr);
                _ptr = IntPtr.Zero;
            }

            _locked = false;

            GC.SuppressFinalize(this);
        }
    }

    internal static class NativeMemory
    {
        [DllImport(
            "kernel32.dll",
            SetLastError = true)]
        public static extern bool VirtualLock(
            IntPtr lpAddress,
            UIntPtr dwSize);

        [DllImport(
            "kernel32.dll",
            SetLastError = true)]
        public static extern bool VirtualUnlock(
            IntPtr lpAddress,
            UIntPtr dwSize);
    }
}

    #endregion
