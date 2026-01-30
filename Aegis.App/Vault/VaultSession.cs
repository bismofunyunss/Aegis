using Aegis.App.Crypto;
using System;
using System.Collections.Generic;
using System.ComponentModel;
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

        public int Length => _length;

        public SecureBuffer(byte[] data)
        {
            _length = data.Length;
            _ptr = Marshal.AllocHGlobal(_length);
            Marshal.Copy(data, 0, _ptr, _length);
            CryptographicOperations.ZeroMemory(data);
            _locked = NativeMemory.VirtualLock(_ptr, (UIntPtr)_length);
        }

        public Span<byte> AsSpan() => new((void*)_ptr, _length);

        public byte[] ToArray()
        {
            var arr = new byte[_length];
            Marshal.Copy(_ptr, arr, 0, _length);
            return arr;
        }

        public void Clear() => AsSpan().Clear();

        public void Dispose()
        {
            if (_ptr == IntPtr.Zero) return;
            Clear();
            if (_locked) NativeMemory.VirtualUnlock(_ptr, (UIntPtr)_length);
            Marshal.FreeHGlobal(_ptr);
            _ptr = IntPtr.Zero;
        }
    }

    internal static class NativeMemory
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualLock(IntPtr lpAddress, UIntPtr dwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualUnlock(IntPtr lpAddress, UIntPtr dwSize);
    }
    #endregion

    #region RamCryptoSession
    public sealed partial class RamCryptoSession : IDisposable
    {
        private SecureBuffer _key;

        public RamCryptoSession(byte[] key) => _key = new SecureBuffer(key);
        private Span<byte> Key => _key.AsSpan();

        public byte[] Encrypt(ReadOnlySpan<byte> plain)
        {
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] cipher = new byte[plain.Length];
            byte[] tag = new byte[16];

            using var aes = new AesGcm(Key, 16);
            aes.Encrypt(nonce, plain, cipher, tag);

            return nonce.Concat(cipher).Concat(tag).ToArray();
        }

        public byte[] Decrypt(ReadOnlySpan<byte> data)
        {
            if (data.Length < 12 + 16)
                throw new ArgumentException("Invalid encrypted data.");

            var nonce = data[..12];
            var tag = data[^16..];
            var cipher = data[12..^16];

            byte[] plain = new byte[cipher.Length];
            using var aes = new AesGcm(Key, 16);
            aes.Decrypt(nonce, cipher, tag, plain);
            return plain;
        }

        public void Dispose() => _key.Dispose();
    }
    #endregion

    #region VaultEntry
    public class SecureVaultEntry : INotifyPropertyChanged, IDisposable
    {
        private SecureBuffer? _password;
        private SecureBuffer? _notes;
        private RamCryptoSession _session;

        public SecureVaultEntry(RamCryptoSession session) => _session = session;

        public string Account { get; set; } = "";
        public string Username { get; set; } = "";
        public string Email { get; set; } = "";

        // UI-bound editable plaintext
        private string _plainPassword = "";
        public string PlainPassword
        {
            get => _plainPassword;
            set
            {
                _plainPassword = value;
                SetPassword(System.Text.Encoding.UTF8.GetBytes(_plainPassword));
                OnPropertyChanged(nameof(PlainPassword));
            }
        }

        private string _plainNotes = "";
        public string PlainNotes
        {
            get => _plainNotes;
            set
            {
                _plainNotes = value;
                SetNotes(System.Text.Encoding.UTF8.GetBytes(_plainNotes));
                OnPropertyChanged(nameof(PlainNotes));
            }
        }

        // Encrypt / decrypt
        public void SetPassword(byte[] plain)
        {
            _password?.Dispose();
            _password = new SecureBuffer(_session.Encrypt(plain));
            CryptographicOperations.ZeroMemory(plain);
        }

        public byte[] GetPasswordBytes()
        {
            if (_password == null) return Array.Empty<byte>();
            var enc = _password.ToArray();
            var plain = _session.Decrypt(enc);
            CryptographicOperations.ZeroMemory(enc);
            return plain;
        }

        public void SetNotes(byte[] plain)
        {
            _notes?.Dispose();
            _notes = new SecureBuffer(_session.Encrypt(plain));
            CryptographicOperations.ZeroMemory(plain);
        }

        public byte[] GetNotesBytes()
        {
            if (_notes == null) return Array.Empty<byte>();
            var enc = _notes.ToArray();
            var plain = _session.Decrypt(enc);
            CryptographicOperations.ZeroMemory(enc);
            return plain;
        }

        public void ClearSensitive()
        {
            _password?.Dispose();
            _notes?.Dispose();
            _password = null;
            _notes = null;
            _plainPassword = "";
            _plainNotes = "";
        }

        public void Dispose() => ClearSensitive();

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged(string prop) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(prop));
    }
    #endregion

    #region DTO
    public class VaultEntryDto
    {
        public string Account { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public byte[] Password { get; set; } = Array.Empty<byte>();
        public byte[] Notes { get; set; } = Array.Empty<byte>();
    }
#endregion DTO
}
