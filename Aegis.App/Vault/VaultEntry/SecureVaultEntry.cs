using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.App.Vault
{
    public sealed class SecureVaultEntry : INotifyPropertyChanged, IDisposable
    {
        private SecureBuffer? _password;
        private SecureBuffer? _notes;

        private string _account = string.Empty;
        private string _username = string.Empty;
        private string _email = string.Empty;

        private bool _disposed;

        // ============================================================
        // NON-SENSITIVE FIELDS
        // ============================================================

        public string Account
        {
            get
            {
                ThrowIfDisposed();
                return _account;
            }
            set
            {
                ThrowIfDisposed();

                value ??= string.Empty;

                if (_account == value)
                    return;

                _account = value;

                OnPropertyChanged();
                VaultState.IsDirty = true;
            }
        }

        public string Username
        {
            get
            {
                ThrowIfDisposed();
                return _username;
            }
            set
            {
                ThrowIfDisposed();

                value ??= string.Empty;

                if (_username == value)
                    return;

                _username = value;

                OnPropertyChanged();
                VaultState.IsDirty = true;
            }
        }

        public string Email
        {
            get
            {
                ThrowIfDisposed();
                return _email;
            }
            set
            {
                ThrowIfDisposed();

                value ??= string.Empty;

                if (_email == value)
                    return;

                _email = value;

                OnPropertyChanged();
                VaultState.IsDirty = true;
            }
        }

        // ============================================================
        // PASSWORD
        // ============================================================

        public string Password
        {
            get
            {
                ThrowIfDisposed();

                if (_password is null)
                    return string.Empty;

                byte[] plaintext =
                    GetPasswordBytes();

                try
                {
                    return Encoding.UTF8.GetString(
                        plaintext);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(
                        plaintext);
                }
            }
            set
            {
                ThrowIfDisposed();

                value ??= string.Empty;

                byte[] plaintext =
                    Encoding.UTF8.GetBytes(value);

                try
                {
                    SetPassword(plaintext);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(
                        plaintext);
                }

                OnPropertyChanged();
                OnPropertyChanged(nameof(HasPassword));

                VaultState.IsDirty = true;
            }
        }

        // ============================================================
        // NOTES
        // ============================================================

        public string Notes
        {
            get
            {
                ThrowIfDisposed();

                if (_notes is null)
                    return string.Empty;

                byte[] plaintext =
                    GetNotesBytes();

                try
                {
                    return Encoding.UTF8.GetString(
                        plaintext);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(
                        plaintext);
                }
            }
            set
            {
                ThrowIfDisposed();

                value ??= string.Empty;

                byte[] plaintext =
                    Encoding.UTF8.GetBytes(value);

                try
                {
                    SetNotes(plaintext);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(
                        plaintext);
                }

                OnPropertyChanged();
                OnPropertyChanged(nameof(HasNotes));

                VaultState.IsDirty = true;
            }
        }

        public bool HasPassword
        {
            get
            {
                ThrowIfDisposed();
                return _password is not null;
            }
        }

        public bool HasNotes
        {
            get
            {
                ThrowIfDisposed();
                return _notes is not null;
            }
        }

        // ============================================================
        // PASSWORD STORAGE
        // ============================================================

        public void SetPassword(
            ReadOnlySpan<byte> plaintext)
        {
            ThrowIfDisposed();

            byte[] copy =
                plaintext.ToArray();

            try
            {
                var newBuffer =
                    new SecureBuffer(copy);

                _password?.Dispose();

                _password =
                    newBuffer;
            }
            finally
            {
                // SecureBuffer consumes and clears
                // its constructor input.
                CryptographicOperations.ZeroMemory(
                    copy);
            }

            OnPropertyChanged(nameof(Password));
            OnPropertyChanged(nameof(HasPassword));
        }

        public byte[] GetPasswordBytes()
        {
            ThrowIfDisposed();

            if (_password is null)
                return Array.Empty<byte>();

            return _password.ToArrayCopy();
        }

        // ============================================================
        // NOTES STORAGE
        // ============================================================

        public void SetNotes(
            ReadOnlySpan<byte> plaintext)
        {
            ThrowIfDisposed();

            byte[] copy =
                plaintext.ToArray();

            try
            {
                var newBuffer =
                    new SecureBuffer(copy);

                _notes?.Dispose();

                _notes =
                    newBuffer;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    copy);
            }

            OnPropertyChanged(nameof(Notes));
            OnPropertyChanged(nameof(HasNotes));
        }

        public byte[] GetNotesBytes()
        {
            ThrowIfDisposed();

            if (_notes is null)
                return Array.Empty<byte>();

            return _notes.ToArrayCopy();
        }

        // ============================================================
        // CLEAR
        // ============================================================

        public void ClearSensitive()
        {
            if (_disposed)
                return;

            _password?.Dispose();
            _password = null;

            _notes?.Dispose();
            _notes = null;

            OnPropertyChanged(nameof(Password));
            OnPropertyChanged(nameof(Notes));
            OnPropertyChanged(nameof(HasPassword));
            OnPropertyChanged(nameof(HasNotes));
        }

        // ============================================================
        // DISPOSE
        // ============================================================

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            _password?.Dispose();
            _password = null;

            _notes?.Dispose();
            _notes = null;

            _account = string.Empty;
            _username = string.Empty;
            _email = string.Empty;

            GC.SuppressFinalize(this);
        }

        // ============================================================
        // HELPERS
        // ============================================================

        private void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(
                _disposed,
                this);
        }

        public event PropertyChangedEventHandler?
            PropertyChanged;

        private void OnPropertyChanged(
            [CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(
                this,
                new PropertyChangedEventArgs(
                    propertyName));
        }
    }
}