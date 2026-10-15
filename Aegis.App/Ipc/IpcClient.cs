using Aegis.App.Crypto;
using Aegis.Contracts;
using Aegis.Contracts.IPC;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text.Json;

namespace Aegis.App.Ipc;

public sealed class IpcClient : IDisposable
{
    private const string PipeName =
        "AegisVaultPipe";

    private const string BootstrapLogUsername =
        "bootstrap";

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
                    username,
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
                    username,
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
    //
    // Username is explicitly supplied.
    //
    // DO NOT use:
    //
    // ClientSessionManager.Current.Username
    //
    // This happens before authentication is established and
    // Current could still contain the previous account.
    //

    public static async Task<ClientSession?> ConfirmLoginTotpAsync(
        string username,
        string authenticationId,
        string code,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            username);

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
                    username,
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
        string username,
        string enrollmentId,
        string code,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            username);

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
                    EnrollmentId =
                        enrollmentId,

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
                    username,
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
            ClientSessionManager.Clear();
        }
    }

    // =========================================================
    // BOOTSTRAP SEND
    // =========================================================

    private static async Task<IpcResponse> SendBootstrapAsync(
        IpcRequest request,
        string? logUsername,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(
            request);

        byte[]? requestBytes = null;
        byte[]? responseBytes = null;

        // ---------------------------------------------------------
        // Normalize exactly once.
        //
        // No null/empty username ever reaches FileLogger.
        //
        // IMPORTANT:
        // We deliberately do NOT fall back to
        // ClientSessionManager.Current.Username.
        // ---------------------------------------------------------

        string logIdentity =
            NormalizeLogUsername(
                logUsername);

        try
        {
            FileLogger.ClientLog(
                $"CLIENT: SendBootstrapAsync START " +
                $"Command={request.Command}",
                logIdentity);

            // ---------------------------------------------------------
            // Serialize request
            // ---------------------------------------------------------

            FileLogger.ClientLog(
                "CLIENT: bootstrap serializing request...",
                logIdentity);

            requestBytes =
                JsonSerializer.SerializeToUtf8Bytes(
                    request);

            FileLogger.ClientLog(
                $"CLIENT: bootstrap request serialized. " +
                $"Length={requestBytes.Length}",
                logIdentity);

            ValidateMessageSize(
                requestBytes.Length);

            // ---------------------------------------------------------
            // Connect
            // ---------------------------------------------------------

            await using NamedPipeClientStream client =
                CreateClient();

            FileLogger.ClientLog(
                "CLIENT: bootstrap connecting to pipe...",
                logIdentity);

            await ConnectAsync(
                client,
                cancellationToken);

            FileLogger.ClientLog(
                $"CLIENT: bootstrap pipe connected. " +
                $"Connected={client.IsConnected}",
                logIdentity);

            // ---------------------------------------------------------
            // Send request
            // ---------------------------------------------------------

            FileLogger.ClientLog(
                "CLIENT: bootstrap writing request...",
                logIdentity);

            await WriteMessageAsync(
                client,
                requestBytes,
                cancellationToken);

            FileLogger.ClientLog(
                "CLIENT: bootstrap request written.",
                logIdentity);

            // ---------------------------------------------------------
            // Read response
            // ---------------------------------------------------------

            FileLogger.ClientLog(
                "CLIENT: bootstrap waiting for response...",
                logIdentity);

            responseBytes =
                await ReadMessageAsync(
                    client,
                    cancellationToken);

            FileLogger.ClientLog(
                $"CLIENT: bootstrap response received. " +
                $"Length={responseBytes.Length}",
                logIdentity);

            // ---------------------------------------------------------
            // Deserialize response
            // ---------------------------------------------------------

            FileLogger.ClientLog(
                "CLIENT: bootstrap deserializing response...",
                logIdentity);

            IpcResponse response =
                DeserializeResponse(
                    responseBytes);

            FileLogger.ClientLog(
                $"CLIENT: bootstrap response deserialized. " +
                $"Success={response.Success}, " +
                $"ErrorCode={response.ErrorCode}",
                logIdentity);

            FileLogger.ClientLog(
                "CLIENT: SendBootstrapAsync COMPLETE.",
                logIdentity);

            return response;
        }
        catch (OperationCanceledException ex)
        {
            FileLogger.Log(
                ex,
                "IpcClient bootstrap operation cancelled.",
                logIdentity);

            throw;
        }
        catch (Exception ex)
        {
            FileLogger.Log(
                ex,
                $"IpcClient bootstrap failed. " +
                $"Command={request.Command}",
                logIdentity);

            throw;
        }
        finally
        {
            Zero(requestBytes);
            Zero(responseBytes);
        }
    }

    // =========================================================
    // LOGGING IDENTITY
    // =========================================================

    private static string NormalizeLogUsername(
        string? username)
    {
        if (string.IsNullOrWhiteSpace(
                username))
        {
            return BootstrapLogUsername;
        }

        return username.Trim();
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
                Debug.WriteLine(
                    $"CLIENT: SendAsync START " +
                    $"Command={request.Command}, " +
                    $"Counter={counter}");

                Debug.WriteLine(
                    "CLIENT: serializing request...");

                plaintext =
                    JsonSerializer.SerializeToUtf8Bytes(
                        request);

                Debug.WriteLine(
                    $"CLIENT: request serialized. " +
                    $"Length={plaintext.Length}");

                ValidateMessageSize(
                    plaintext.Length);

                Debug.WriteLine(
                    "CLIENT: exporting session key...");

                sessionKey =
                    session.SessionKey.Export();

                Debug.WriteLine(
                    $"CLIENT: session key exported. " +
                    $"Length={sessionKey.Length}");

                if (sessionKey.Length !=
                    IpcProtocol.SessionKeySize)
                {
                    throw new SecurityException(
                        "Invalid session key.");
                }

                Debug.WriteLine(
                    "CLIENT: encrypting request...");

                SecureEnvelope envelope =
                    VaultTransport.EncryptOutgoing(
                        sessionKey,
                        plaintext,
                        sessionId,
                        counter,
                        request.Command);

                Debug.WriteLine(
                    "CLIENT: request encrypted.");

                Debug.WriteLine(
                    "CLIENT: serializing request envelope...");

                envelopeBytes =
                    JsonSerializer.SerializeToUtf8Bytes(
                        envelope);

                Debug.WriteLine(
                    $"CLIENT: request envelope serialized. " +
                    $"Length={envelopeBytes.Length}");

                ValidateMessageSize(
                    envelopeBytes.Length);

                await using NamedPipeClientStream client =
                    CreateClient();

                Debug.WriteLine(
                    "CLIENT: connecting to pipe...");

                await ConnectAsync(
                    client,
                    cancellationToken);

                Debug.WriteLine(
                    $"CLIENT: pipe connected. " +
                    $"Connected={client.IsConnected}");

                Debug.WriteLine(
                    "CLIENT: writing request...");

                await WriteMessageAsync(
                    client,
                    envelopeBytes,
                    cancellationToken);

                Debug.WriteLine(
                    "CLIENT: request written successfully.");

                Debug.WriteLine(
                    "CLIENT: waiting for response...");

                responseBytes =
                    await ReadMessageAsync(
                        client,
                        cancellationToken);

                Debug.WriteLine(
                    $"CLIENT: response received successfully. " +
                    $"Length={responseBytes.Length}");

                Debug.WriteLine(
                    "CLIENT: deserializing response envelope...");

                SecureEnvelope responseEnvelope =
                    DeserializeEnvelope(
                        responseBytes);

                Debug.WriteLine(
                    "CLIENT: response envelope deserialized.");

                Debug.WriteLine(
                    "CLIENT: decrypting response...");

                decrypted =
                    VaultTransport.DecryptResponse(
                        sessionKey,
                        responseEnvelope,
                        sessionId,
                        counter,
                        request.Command);

                Debug.WriteLine(
                    $"CLIENT: response decrypted successfully. " +
                    $"Length={decrypted.Length}");

                Debug.WriteLine(
                    "CLIENT: deserializing IpcResponse...");

                IpcResponse response =
                    DeserializeResponse(
                        decrypted);

                Debug.WriteLine(
                    $"CLIENT: IpcResponse deserialized. " +
                    $"Success={response.Success}, " +
                    $"ErrorCode={response.ErrorCode}");

                Debug.WriteLine(
                    "CLIENT: SendAsync COMPLETE.");

                return response;
            }
            catch (OperationCanceledException ex)
            {
                Debug.WriteLine(
                    $"CLIENT: SendAsync CANCELED: {ex}");

                throw;
            }
            catch (Exception ex)
            {
                Debug.WriteLine(
                    $"CLIENT: SendAsync FAILED: {ex}");

                throw;
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
            IpcErrorMessages.Get(
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

            IpcErrorCode.FileAlreadyEncrypted =>
                new IpcException(
                    IpcErrorCode.FileAlreadyEncrypted,
                    message),

            IpcErrorCode.FileNotEncrypted =>
                new IpcException(
                    IpcErrorCode.FileNotEncrypted,
                    message),

            IpcErrorCode.FileNotFound =>
                new IpcException(
                    IpcErrorCode.FileNotFound,
                    message),

            IpcErrorCode.InvalidFileFormat =>
                new IpcException(
                    IpcErrorCode.InvalidFileFormat,
                    message),

            IpcErrorCode.UnsupportedFileVersion =>
                new IpcException(
                    IpcErrorCode.UnsupportedFileVersion,
                    message),

            IpcErrorCode.FileIntegrityFailure =>
                new IpcException(
                    IpcErrorCode.FileIntegrityFailure,
                    message),

            IpcErrorCode.SessionExpired =>
                new IpcException(
                    IpcErrorCode.SessionExpired,
                    message),

            IpcErrorCode.Cancelled =>
                new OperationCanceledException(message),

            IpcErrorCode.InternalFailure =>
                new IpcException(
                    IpcErrorCode.InternalFailure,
                    message),

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

            IpcErrorCode.FileAlreadyEncrypted =>
                "The selected file is already encrypted.",

            IpcErrorCode.FileNotEncrypted =>
                "The selected file is not encrypted.",

            IpcErrorCode.FileNotFound =>
                "The selected file could not be found.",

            IpcErrorCode.InvalidFileFormat =>
                "The selected file is not a valid Aegis file.",

            IpcErrorCode.UnsupportedFileVersion =>
                "The selected file uses an unsupported file version.",

            IpcErrorCode.FileIntegrityFailure =>
                "The file failed its integrity check.",

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