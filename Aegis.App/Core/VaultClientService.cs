using System.Security;
using System.Security.Cryptography;
using Aegis.App.Crypto;
using Aegis.App.Ipc;
using Aegis.App.Settings;
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

        public static async Task ConfirmTotpEnrollmentAsync(
            string username,
            string enrollmentId,
            string code)
        {
            ValidateUsername(username);

            await IpcClient.ConfirmTotpEnrollmentAsync(
                username,
                enrollmentId,
                code);
        }

        // =========================================================
        // REGISTER
        // =========================================================

        public static async Task<TotpEnrollment> RegisterAsync(
            byte[] userPassword,
            uint[] pcrs,
            string username,
            AegisSettings settings)
        {
            ArgumentNullException.ThrowIfNull(
                userPassword);

            ArgumentNullException.ThrowIfNull(
                pcrs);

            ArgumentNullException.ThrowIfNull(
                settings);

            ValidateUsername(
                username);

            ValidatePcrs(
                pcrs);

            ValidateRegistrationSettings(
                settings);

            FileLogger.ClientLog(
                $"REGISTER SETTINGS: " +
                $"PBKDF2={settings.Pbkdf2Iterations}, " +
                $"ArgonIterations={settings.Argon2Iterations}, " +
                $"ArgonMemoryMiB={settings.Argon2MemoryMiB}, " +
                $"ArgonParallelism={settings.Argon2Parallelism}, " +
                $"Fips={settings.Fips}, " +
                $"KdfTargetMs={settings.KdfTargetMilliseconds}",
                username);

            var cryptoSettings =
                new CryptoSettings
                {
                    Pbkdf2Iterations =
                        settings.Pbkdf2Iterations,

                    ArgonIterations =
                        settings.Argon2Iterations,

                    ArgonParallelism =
                        settings.Argon2Parallelism,

                    ArgonMemoryKb =
                        checked(
                            settings.Argon2MemoryMiB *
                            1024)
                };

            FileLogger.ClientLog(
                $"REGISTER CRYPTO SETTINGS: " +
                $"PBKDF2={cryptoSettings.Pbkdf2Iterations}, " +
                $"ArgonIterations={cryptoSettings.ArgonIterations}, " +
                $"ArgonMemoryKb={cryptoSettings.ArgonMemoryKb}, " +
                $"ArgonParallelism={cryptoSettings.ArgonParallelism}",
                username);

            return await IpcClient.RegisterAsync(
                username,
                userPassword,
                cryptoSettings,
                pcrs);
        }

        // =========================================================
        // LOGIN
        // =========================================================

        public static async Task<string?> BeginLoginAsync(
            string username,
            byte[] password)
        {
            ValidateUsername(username);

            return await IpcClient.BeginLoginAsync(
                username,
                password);
        }

        // =========================================================
        // LOGIN TOTP
        // =========================================================

        public async Task<bool> ConfirmLoginTotpAsync(
            string username,
            string authenticationId,
            string code)
        {
            ValidateUsername(username);

            var session =
                await IpcClient.ConfirmLoginTotpAsync(
                    username,
                    authenticationId,
                    code);

            if (session == null)
                return false;

            return true;
        }

        // =========================================================
        // FILE ENCRYPTION
        // =========================================================

        public async Task<FileOperationResult?> EncryptFile(
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
        // FILE DECRYPTION
        // =========================================================

        public async Task<FileOperationResult?> DecryptFile(
            string inputPath,
            IProgress<double>? progress = null,
            CancellationToken cancellationToken = default)
        {
            return await _ipc.DecryptFileAsync(
                inputPath,
                null,
                cancellationToken);
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
        // CHANGE PASSWORD
        // =========================================================

        public async Task ChangePasswordAsync(
            byte[] currentPassword,
            byte[] newPassword)
        {
            ArgumentNullException.ThrowIfNull(
                currentPassword);

            ArgumentNullException.ThrowIfNull(
                newPassword);

            if (currentPassword.Length == 0)
            {
                throw new ArgumentException(
                    "Current password is empty.",
                    nameof(currentPassword));
            }

            if (newPassword.Length == 0)
            {
                throw new ArgumentException(
                    "New password is empty.",
                    nameof(newPassword));
            }

            await _ipc.ChangePasswordAsync(
                currentPassword,
                newPassword);
        }

        // =========================================================
        // INTERNAL POLICY HELPERS
        // =========================================================

        private static CryptoSettings BuildCryptoSettings(
            AegisSettings settings)
        {
            ArgumentNullException.ThrowIfNull(
                settings);

            ValidateRegistrationSettings(
                settings);

            return new CryptoSettings
            {
                Pbkdf2Iterations =
                    settings.Pbkdf2Iterations,

                ArgonIterations =
                    settings.Argon2Iterations,

                ArgonParallelism =
                    settings.Argon2Parallelism,

                ArgonMemoryKb =
                    checked(
                        settings.Argon2MemoryMiB *
                        1024)
            };
        }

        private static void ValidateUsername(
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

        private static void ValidatePcrs(
            uint[] pcrs)
        {
            if (pcrs == null ||
                pcrs.Length == 0)
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

        private static void ValidateRegistrationSettings(
            AegisSettings settings)
        {
            ArgumentNullException.ThrowIfNull(
                settings);

            if (settings.Pbkdf2Iterations <
                600_000)
            {
                throw new SecurityException(
                    "PBKDF2 iteration count is below the minimum.");
            }

            if (settings.Argon2Iterations <
                1)
            {
                throw new SecurityException(
                    "Argon2 iteration count is invalid.");
            }

            if (settings.Argon2MemoryMiB <
                2048)
            {
                throw new SecurityException(
                    "Argon2 memory is below the minimum.");
            }

            if (settings.Argon2Parallelism <
                1)
            {
                throw new SecurityException(
                    "Argon2 parallelism is invalid.");
            }

            if (settings.KdfTargetMilliseconds <=
                0)
            {
                throw new SecurityException(
                    "KDF target time is invalid.");
            }
        }
    }
}