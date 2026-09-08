using System.Buffers.Binary;
using System.IO;
using System.IO.Pipes;
using System.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text.Json;
using Aegis.App.Crypto;
using Aegis.Contracts;

namespace Aegis.App.Ipc;

public sealed class IpcClient : IDisposable
{
    private const string PipeName =
        "AegisVaultPipe";

    private const int LengthPrefixSize =
        sizeof(int);

    private const int ConnectTimeoutMilliseconds =
        10_000;

    private readonly SemaphoreSlim _sendLock =
        new(1, 1);

    private bool _disposed;

    // =========================================================
    // REGISTER
    // =========================================================

    public static async Task<TotpEnrollment> RegisterAsync(
        string username,
        byte[] password,
        CryptoSettings settings,
        uint[] pcrs,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            username);

        ArgumentNullException.ThrowIfNull(
            password);

        ArgumentNullException.ThrowIfNull(
            settings);

        ArgumentNullException.ThrowIfNull(
            pcrs);

        if (password.Length == 0)
        {
            throw new ArgumentException(
                "Password is empty.",
                nameof(password));
        }

        byte[]? payload = null;

        try
        {
            var body =
                new RegisterRequest
                {
                    Username = username,
                    Password = password,
                    CryptoConfig = settings,
                    Pcrs = pcrs
                };

            payload =
                JsonSerializer.SerializeToUtf8Bytes(
                    body);

            var request =
                new IpcRequest
                {
                    Command = "register",
                    Payload = payload,
                    SessionId = null,
                    Counter = 0
                };

            IpcResponse response =
                await SendBootstrapAsync(
                    request,
                    cancellationToken);

            return DeserializeSuccess<TotpEnrollment>(
                response,
                "Registration failed.");
        }
        finally
        {
            Zero(payload);
        }
    }

    // =========================================================
    // BEGIN LOGIN
    // =========================================================

    public static async Task<string?> BeginLoginAsync(
        string username,
        byte[] password,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            username);

        ArgumentNullException.ThrowIfNull(
            password);

        if (password.Length == 0)
            return null;

        byte[]? payload = null;

        try
        {
            var body =
                new LoginRequest
                {
                    Username = username,
                    Password = password
                };

            payload =
                JsonSerializer.SerializeToUtf8Bytes(
                    body);

            var request =
                new IpcRequest
                {
                    Command = "login",
                    Payload = payload,
                    SessionId = null,
                    Counter = 0
                };

            IpcResponse response =
                await SendBootstrapAsync(
                    request,
                    cancellationToken);

            if (!response.Success)
                return null;

            LoginBeginResult result =
                DeserializeData<LoginBeginResult>(
                    response);

            return result.AuthenticationId;
        }
        finally
        {
            Zero(payload);
        }
    }

    // =========================================================
    // CONFIRM LOGIN TOTP
    // =========================================================

    public static async Task<ClientSession?> ConfirmLoginTotpAsync(
        string authenticationId,
        string code,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            authenticationId);

        ValidateTotpCode(
            code);

        byte[]? payload = null;
        byte[]? exportedSessionKey = null;

        try
        {
            var body =
                new ConfirmLoginTotpRequest
                {
                    AuthenticationId =
                        authenticationId,

                    Code =
                        code
                };

            payload =
                JsonSerializer.SerializeToUtf8Bytes(
                    body);

            var request =
                new IpcRequest
                {
                    Command =
                        "confirm-login-totp",

                    Payload =
                        payload,

                    SessionId =
                        null,

                    Counter =
                        0
                };

            IpcResponse response =
                await SendBootstrapAsync(
                    request,
                    cancellationToken);

            if (!response.Success)
                return null;

            LoginResult login =
                DeserializeData<LoginResult>(
                    response);

            if (string.IsNullOrWhiteSpace(
                    login.Username) ||
                string.IsNullOrWhiteSpace(
                    login.SessionId) ||
                login.SessionKey is null ||
                login.SessionKey.Length !=
                    IpcProtocol.SessionKeySize)
            {
                throw new SecurityException(
                    "Invalid session response.");
            }

            ValidateSessionId(
                login.SessionId);

            if (login.ExpiresUtc <=
                login.CreatedUtc)
            {
                throw new SecurityException(
                    "Invalid session response.");
            }

            exportedSessionKey =
                login.SessionKey;

            var session =
                new ClientSession(
                    login.Username,
                    login.SessionId,
                    exportedSessionKey,
                    login.CreatedUtc,
                    login.ExpiresUtc,
                    login.ProtocolVersion);

            ClientSessionManager.Set(
                session);

            return session;
        }
        finally
        {
            Zero(payload);

            Zero(exportedSessionKey);
        }
    }

    // =========================================================
    // CONFIRM TOTP ENROLLMENT
    // =========================================================

    public static async Task ConfirmTotpEnrollmentAsync(
        string code,
        string enrollmentId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            enrollmentId);

        ValidateTotpCode(
            code);

        byte[]? payload = null;

        try
        {
            var body =
                new ConfirmTotpEnrollmentRequest
                {
                    Code =
                        code,

                    EnrollmentId =
                        enrollmentId
                };

            payload =
                JsonSerializer.SerializeToUtf8Bytes(
                    body);

            var request =
                new IpcRequest
                {
                    Command =
                        "confirm-totp-enrollment",

                    Payload =
                        payload,

                    SessionId =
                        null,

                    Counter =
                        0
                };

            IpcResponse response =
                await SendBootstrapAsync(
                    request,
                    cancellationToken);

            ThrowIfFailed(
                response,
                "TOTP enrollment failed.");
        }
        finally
        {
            Zero(payload);
        }
    }

    // =========================================================
    // ENCRYPT FILE
    // =========================================================

    public async Task<FileOperationResult?> EncryptFileAsync(
        string inputPath,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            inputPath);

        _ = progress;

        EnsureNotDisposed();
        EnsureAuthenticated();

        byte[]? payload = null;

        try
        {
            var body =
                new EncryptFileRequest
                {
                    InputPath =
                        inputPath
                };

            payload =
                JsonSerializer.SerializeToUtf8Bytes(
                    body);

            var request =
                new IpcRequest
                {
                    Command = "encrypt",
                    Payload = payload
                };

            IpcResponse response =
                await SendAsync(
                    request,
                    cancellationToken);

            ThrowIfFailed(
                response,
                "File encryption failed.");

            return DeserializeData<FileOperationResult>(
                response);
        }
        finally
        {
            Zero(payload);
        }
    }

    // =========================================================
    // DECRYPT FILE
    // =========================================================

    public async Task<FileOperationResult?> DecryptFileAsync(
        string inputPath,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            inputPath);

        _ = progress;

        EnsureNotDisposed();
        EnsureAuthenticated();

        byte[]? payload = null;

        try
        {
            var body =
                new DecryptFileRequest
                {
                    InputPath =
                        inputPath,

                    OutputPath =
                        string.Empty
                };

            payload =
                JsonSerializer.SerializeToUtf8Bytes(
                    body);

            var request =
                new IpcRequest
                {
                    Command = "decrypt",
                    Payload = payload
                };

            IpcResponse response =
                await SendAsync(
                    request,
                    cancellationToken);

            ThrowIfFailed(
                response,
                "File decryption failed.");

            return DeserializeData<FileOperationResult>(
                response);
        }
        finally
        {
            Zero(payload);
        }
    }

    // =========================================================
    // CHANGE PASSWORD
    // =========================================================

    public async Task ChangePasswordAsync(
        byte[] currentPassword,
        byte[] newPassword,
        CancellationToken cancellationToken = default)
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

        EnsureNotDisposed();
        EnsureAuthenticated();

        byte[]? payload = null;

        try
        {
            var body =
                new ChangePasswordRequest
                {
                    CurrentPassword =
                        currentPassword,

                    NewPassword =
                        newPassword
                };

            payload =
                JsonSerializer.SerializeToUtf8Bytes(
                    body);

            var request =
                new IpcRequest
                {
                    Command =
                        "change-password",

                    Payload =
                        payload
                };

            IpcResponse response =
                await SendAsync(
                    request,
                    cancellationToken);

            ThrowIfFailed(
                response,
                "Password change failed.");
        }
        finally
        {
            Zero(payload);
        }
    }

    // =========================================================
    // LOGOUT
    // =========================================================

    public async Task LogoutAsync(
        CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();

        if (!ClientSessionManager.IsAuthenticated)
            return;

        try
        {
            var request =
                new IpcRequest
                {
                    Command =
                        "logout"
                };

            IpcResponse response =
                await SendAsync(
                    request,
                    cancellationToken);

            ThrowIfFailed(
                response,
                "Logout failed.");
        }
        finally
        {
            // Local session destruction is unconditional.
            ClientSessionManager.Clear();
        }
    }

    // =========================================================
    // BOOTSTRAP SEND
    // =========================================================

    private static async Task<IpcResponse> SendBootstrapAsync(
        IpcRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(
            request);

        byte[]? requestBytes = null;
        byte[]? responseBytes = null;

        try
        {
            requestBytes =
                JsonSerializer.SerializeToUtf8Bytes(
                    request);

            ValidateMessageSize(
                requestBytes.Length);

            await using NamedPipeClientStream client =
                CreateClient();

            await ConnectAsync(
                client,
                cancellationToken);

            await WriteMessageAsync(
                client,
                requestBytes,
                cancellationToken);

            responseBytes =
                await ReadMessageAsync(
                    client,
                    cancellationToken);

            return DeserializeResponse(
                responseBytes);
        }
        finally
        {
            Zero(requestBytes);
            Zero(responseBytes);
        }
    }

    // =========================================================
    // AUTHENTICATED SEND
    // =========================================================

    private async Task<IpcResponse> SendAsync(
        IpcRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(
            request);

        EnsureNotDisposed();

        await _sendLock.WaitAsync(
            cancellationToken);

        try
        {
            ClientSession session =
                ClientSessionManager.Current;

            ValidateClientSession(
                session);

            string sessionId =
                session.SessionId!;

            ulong counter =
                session.NextCounter();

            request.SessionId =
                sessionId;

            request.Counter =
                counter;

            byte[]? plaintext = null;
            byte[]? envelopeBytes = null;
            byte[]? responseBytes = null;
            byte[]? decrypted = null;
            byte[]? sessionKey = null;

            try
            {
                plaintext =
                    JsonSerializer.SerializeToUtf8Bytes(
                        request);

                ValidateMessageSize(
                    plaintext.Length);

                sessionKey =
                    session.SessionKey.Export();

                if (sessionKey.Length !=
                    IpcProtocol.SessionKeySize)
                {
                    throw new SecurityException(
                        "Invalid session key.");
                }

                SecureEnvelope envelope =
                    VaultTransport.EncryptOutgoing(
                        sessionKey,
                        plaintext,
                        sessionId,
                        counter,
                        request.Command);

                envelopeBytes =
                    JsonSerializer.SerializeToUtf8Bytes(
                        envelope);

                ValidateMessageSize(
                    envelopeBytes.Length);

                await using NamedPipeClientStream client =
                    CreateClient();

                await ConnectAsync(
                    client,
                    cancellationToken);

                await WriteMessageAsync(
                    client,
                    envelopeBytes,
                    cancellationToken);

                responseBytes =
                    await ReadMessageAsync(
                        client,
                        cancellationToken);

                SecureEnvelope responseEnvelope =
                    DeserializeEnvelope(
                        responseBytes);

                decrypted =
                    VaultTransport.DecryptResponse(
                        sessionKey,
                        responseEnvelope,
                        sessionId,
                        counter,
                        request.Command);

                return DeserializeResponse(
                    decrypted);
            }
            finally
            {
                Zero(plaintext);
                Zero(envelopeBytes);
                Zero(responseBytes);
                Zero(decrypted);
                Zero(sessionKey);
            }
        }
        finally
        {
            _sendLock.Release();
        }
    }

    // =========================================================
    // PIPE
    // =========================================================

    private static NamedPipeClientStream CreateClient()
    {
        return new NamedPipeClientStream(
            ".",
            PipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous);
    }

    private static async Task ConnectAsync(
        NamedPipeClientStream client,
        CancellationToken cancellationToken)
    {
        using var timeoutCts =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);

        timeoutCts.CancelAfter(
            ConnectTimeoutMilliseconds);

        try
        {
            await client.ConnectAsync(
                timeoutCts.Token);
        }
        catch (OperationCanceledException) when (
            !cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(
                "Unable to connect to the vault service.");
        }
    }

    private static async Task WriteMessageAsync(
        Stream stream,
        byte[] data,
        CancellationToken cancellationToken)
    {
        ValidateMessageSize(
            data.Length);

        Span<byte> length =
            stackalloc byte[
                LengthPrefixSize];

        BinaryPrimitives.WriteInt32LittleEndian(
            length,
            data.Length);

        byte[] lengthBytes =
            length.ToArray();

        try
        {
            await stream.WriteAsync(
                lengthBytes,
                cancellationToken);

            await stream.WriteAsync(
                data,
                cancellationToken);

            await stream.FlushAsync(
                cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                lengthBytes);
        }
    }

    private static async Task<byte[]> ReadMessageAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        byte[] lengthBuffer =
            new byte[LengthPrefixSize];

        try
        {
            await ReadExactAsync(
                stream,
                lengthBuffer,
                cancellationToken);

            int length =
                BinaryPrimitives.ReadInt32LittleEndian(
                    lengthBuffer);

            ValidateMessageSize(
                length);

            byte[] result =
                new byte[length];

            try
            {
                await ReadExactAsync(
                    stream,
                    result,
                    cancellationToken);

                return result;
            }
            catch
            {
                Zero(result);
                throw;
            }
        }
        finally
        {
            Zero(lengthBuffer);
        }
    }

    private static async Task ReadExactAsync(
        Stream stream,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        int offset = 0;

        while (offset < buffer.Length)
        {
            int read =
                await stream.ReadAsync(
                    buffer.AsMemory(offset),
                    cancellationToken);

            if (read == 0)
            {
                throw new EndOfStreamException(
                    "IPC connection closed unexpectedly.");
            }

            offset += read;
        }
    }

    // =========================================================
    // SESSION VALIDATION
    // =========================================================

    private static void EnsureAuthenticated()
    {
        ClientSession session =
            ClientSessionManager.Current;

        ValidateClientSession(
            session);
    }

    private static void ValidateClientSession(
        ClientSession session)
    {
        ArgumentNullException.ThrowIfNull(
            session);

        if (string.IsNullOrWhiteSpace(
                session.SessionId))
        {
            throw new SecurityException(
                "Invalid session.");
        }

        ValidateSessionId(
            session.SessionId);

        if (session.ExpiresUtc <=
            DateTime.UtcNow)
        {
            ClientSessionManager.Clear();

            throw new SecurityException(
                "Session expired.");
        }

        byte[] key =
            session.SessionKey.Export();

        try
        {
            if (key.Length !=
                IpcProtocol.SessionKeySize)
            {
                throw new SecurityException(
                    "Invalid session key.");
            }
        }
        finally
        {
            Zero(key);
        }
    }

    private static void ValidateSessionId(
        string sessionId)
    {
        if (sessionId.Length != 32)
        {
            throw new SecurityException(
                "Invalid session.");
        }

        foreach (char c in sessionId)
        {
            bool hex =
                c is >= '0' and <= '9'
                or >= 'A' and <= 'F'
                or >= 'a' and <= 'f';

            if (!hex)
            {
                throw new SecurityException(
                    "Invalid session.");
            }
        }
    }

    private static void ValidateTotpCode(
        string code)
    {
        if (string.IsNullOrWhiteSpace(code) ||
            code.Length != 6)
        {
            throw new SecurityException(
                "Invalid authentication code.");
        }

        foreach (char c in code)
        {
            if (c is < '0' or > '9')
            {
                throw new SecurityException(
                    "Invalid authentication code.");
            }
        }
    }

    private static void ValidateMessageSize(
        int length)
    {
        if (length <= 0 ||
            length > IpcProtocol.MaxMessageSize)
        {
            throw new SecurityException(
                "Invalid IPC message size.");
        }
    }

    // =========================================================
    // RESPONSE HANDLING
    // =========================================================

    private static IpcResponse DeserializeResponse(
        byte[] bytes)
    {
        try
        {
            return JsonSerializer.Deserialize<IpcResponse>(
                       bytes)
                   ?? throw new SecurityException(
                       "Invalid IPC response.");
        }
        catch (JsonException ex)
        {
            throw new SecurityException(
                "Invalid IPC response.",
                ex);
        }
    }

    private static SecureEnvelope DeserializeEnvelope(
        byte[] bytes)
    {
        try
        {
            return JsonSerializer.Deserialize<SecureEnvelope>(
                       bytes)
                   ?? throw new SecurityException(
                       "Invalid IPC envelope.");
        }
        catch (JsonException ex)
        {
            throw new SecurityException(
                "Invalid IPC envelope.",
                ex);
        }
    }

    private static T DeserializeData<T>(
        IpcResponse response)
    {
        if (!response.Success)
        {
            throw new IpcException(
                response.ErrorCode,
                GetSafeErrorMessage(
                    response.ErrorCode));
        }

        if (string.IsNullOrWhiteSpace(
                response.Data))
        {
            throw new SecurityException(
                "Server returned an empty response.");
        }

        try
        {
            return JsonSerializer.Deserialize<T>(
                       response.Data)
                   ?? throw new SecurityException(
                       "Invalid server response.");
        }
        catch (JsonException ex)
        {
            throw new SecurityException(
                "Invalid server response.",
                ex);
        }
    }

    private static void ThrowIfFailed(
        IpcResponse response,
        string fallback)
    {
        if (response.Success)
            return;

        string message =
            GetSafeErrorMessage(
                response.ErrorCode);

        if (string.IsNullOrWhiteSpace(message))
            message = fallback;

        throw response.ErrorCode switch
        {
            IpcErrorCode.AuthenticationFailed =>
                new AuthenticationException(message),

            IpcErrorCode.AuthorizationFailed =>
                new SecurityException(message),

            IpcErrorCode.ValidationFailure =>
                new ArgumentException(message),

            IpcErrorCode.SecurityFailure =>
                new SecurityException(message),

            IpcErrorCode.CryptographicFailure =>
                new CryptographicException(message),

            IpcErrorCode.FileFailure =>
                new IOException(message),

            IpcErrorCode.Cancelled =>
                new OperationCanceledException(message),

            IpcErrorCode.SessionExpired =>
                new SecurityException(message),

            IpcErrorCode.InternalFailure =>
                new InvalidOperationException(message),

            _ =>
                new IpcException(
                    response.ErrorCode,
                    fallback)
        };
    }

    private static string GetSafeErrorMessage(
        IpcErrorCode code)
    {
        return code switch
        {
            IpcErrorCode.AuthenticationFailed =>
                "Authentication failed.",

            IpcErrorCode.AuthorizationFailed =>
                "The operation is not authorized.",

            IpcErrorCode.ValidationFailure =>
                "The request data is invalid.",

            IpcErrorCode.SecurityFailure =>
                "A security validation failed.",

            IpcErrorCode.CryptographicFailure =>
                "The cryptographic operation could not be completed.",

            IpcErrorCode.FileFailure =>
                "The file operation could not be completed.",

            IpcErrorCode.Cancelled =>
                "The operation was cancelled.",

            IpcErrorCode.SessionExpired =>
                "The session has expired.",

            IpcErrorCode.InternalFailure =>
                "An unexpected server error occurred.",

            _ =>
                "The operation could not be completed."
        };
    }

    private static T DeserializeSuccess<T>(
        IpcResponse response,
        string fallback)
    {
        ThrowIfFailed(
            response,
            fallback);

        return DeserializeData<T>(
            response);
    }

    // =========================================================
    // DISPOSAL
    // =========================================================

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;

        _sendLock.Dispose();

        GC.SuppressFinalize(this);
    }

    private void EnsureNotDisposed()
    {
        ObjectDisposedException.ThrowIf(
            _disposed,
            this);
    }

    // =========================================================
    // MEMORY
    // =========================================================

    private static void Zero(
        byte[]? data)
    {
        if (data is { Length: > 0 })
        {
            CryptographicOperations.ZeroMemory(
                data);
        }
    }
}