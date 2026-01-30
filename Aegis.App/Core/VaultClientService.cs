using System.Security;
using Aegis.App.Crypto;
using Aegis.App.Ipc;
using Aegis.Contracts;

namespace Aegis.App.Core
{
    public sealed class VaultClientService
    {
        private readonly IpcClient _ipc;

        public VaultClientService(IpcClient ipc)
        {
            _ipc =
                ipc ?? throw new ArgumentNullException(
                    nameof(ipc));
        }

        // =========================================================
        // TOTP ENROLLMENT
        // =========================================================

        public async Task ConfirmTotpEnrollmentAsync(
            string enrollmentId,
            string code)
        {
            await _ipc.ConfirmTotpEnrollmentAsync(
                code, enrollmentId);
        }

        // =========================================================
        // REGISTER
        // =========================================================

        public async Task<TotpEnrollment> RegisterAsync(
            byte[] userPassword,
            uint[] pcrs,
            string username)
        {
            ValidateUsername(username);

            ValidatePcrs(pcrs);

            var settings =
                BuildCryptoSettings();

            return await _ipc.RegisterAsync(
                username,
                userPassword,
                settings,
                pcrs);
        }

        // =========================================================
        // LOGIN
        // =========================================================

        public async Task<string?> BeginLoginAsync(
            string username,
            byte[] password)
        {
            ValidateUsername(username);

            return await _ipc.BeginLoginAsync(
                username,
                password);
        }

        public async Task<bool> ConfirmLoginTotpAsync(
            string authenticationId,
            string code)
        {
            var session =
                await _ipc.ConfirmLoginTotpAsync(
                    authenticationId,
                    code);

            if (session == null)
                return false;

            _ipc.SetSession(session);
            ClientSessionManager.Set(session);

            return true;
        }

        // =========================================================
        // FILE ENCRYPTION
        // =========================================================

        public async Task<FileOperationResult> EncryptFile(
            string inputPath,
            IProgress<double>? progress = null,
            CancellationToken cancellationToken = default)
        {
            return await _ipc.EncryptFileAsync(
                inputPath,
                null,
                cancellationToken);
        }

        // =========================================================
        // FILE ENCRYPTION
        // =========================================================

        public async Task<FileOperationResult> DecryptFile(
            string inputPath, IProgress<double>? progress = null,
            CancellationToken cancellationToken = default)
        {
            return await _ipc.DecryptFileAsync(
                inputPath);
        }

        // =========================================================
        // LOGOUT
        // =========================================================

        public async Task LogoutAsync(
            CancellationToken cancellationToken = default)
        {
            try
            {
                await _ipc.LogoutAsync(
                    cancellationToken);
            }
            finally
            {
                ClientSessionManager.Clear();
            }
        }

        // =========================================================
        // INTERNAL POLICY HELPERS
        // =========================================================

        private CryptoSettings BuildCryptoSettings()
        {
            return new CryptoSettings
            {
                ArgonIterations =
                    Settings.Default.Iterations,

                ArgonParallelism =
                    Settings.Default.Parallelism,

                ArgonMemoryKb =
                    (int)Settings.Default.Memory
            };
        }

        private void ValidateUsername(
            string username)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                throw new SecurityException(
                    "Invalid username.");
            }

            if (username.Length > 64)
            {
                throw new SecurityException(
                    "Username too long.");
            }
        }

        private void ValidatePcrs(
            uint[] pcrs)
        {
            if (pcrs == null || pcrs.Length == 0)
            {
                throw new SecurityException(
                    "Invalid PCR set.");
            }

            if (pcrs.Length > 24)
            {
                throw new SecurityException(
                    "PCR set too large.");
            }

            for (var i = 0; i < pcrs.Length; i++)
            {
                if (pcrs[i] > 23)
                {
                    throw new SecurityException(
                        "Invalid PCR index.");
                }
            }
        }

        private void ValidateBlob(
            KeyBlob blob)
        {
            if (blob == null)
            {
                throw new SecurityException(
                    "Missing KeyBlob.");
            }

            if (blob.EncryptedKeyHierarchy == null ||
                blob.EncryptedKeyHierarchy.Length == 0)
            {
                throw new SecurityException(
                    "Corrupt KeyBlob.");
            }

            if (blob.GcmNonce == null ||
                blob.GcmTag == null)
            {
                throw new SecurityException(
                    "Invalid KeyBlob crypto state.");
            }
        }
    }
}