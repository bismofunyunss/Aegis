using Aegis.App.Crypto;
using Aegis.App.Helpers;
using Aegis.Contracts;
using System.IO;
using System.IO.Pipes;
using System.Security;
using System.Security.Cryptography;
using System.Text.Json;


namespace Aegis.App.Ipc;

public sealed class IpcClient
{
    private const string PipeName = "AegisVaultPipe";

    private ClientSession? _session;

    private readonly SemaphoreSlim _sendLock =
        new(1, 1);


    public void SetSession(
        ClientSession session)
    {
        ArgumentNullException.ThrowIfNull(
            session);

        _session?.Dispose();

        _session = session;
    }

    public async Task ConfirmTotpEnrollmentAsync(
        string code,
        string enrollmentId)
    {
        byte[]? payload = null;

        try
        {
            var request =
                new ConfirmTotpEnrollmentRequest
                {
                    Code = code,
                    EnrollmentId = enrollmentId
                };

            payload =
                JsonSerializer.SerializeToUtf8Bytes(
                    request);

            var ipcRequest =
                new IpcRequest
                {
                    Command =
                        "confirm-totp-enrollment",

                    Counter = 0,

                    Payload =
                        payload
                };

            var response =
                await SendBootstrapAsync(
                    ipcRequest);

            if (response == null ||
                !response.Success)
            {
                throw new SecurityException(
                    response?.Error ??
                    "TOTP verification failed.");
            }
        }
        finally
        {
            if (payload != null)
            {
                CryptographicOperations.ZeroMemory(
                    payload);
            }
        }
    }

    // =========================================================
    // REGISTER
    // =========================================================

    public async Task<TotpEnrollment> RegisterAsync(
        string username,
        byte[] password,
        CryptoSettings config,
        uint[] pcrs)
    {
        byte[]? payload = null;

        try
        {
            var register =
                new RegisterRequest
                {
                    Username = username,
                    Password = password,
                    CryptoConfig = config,
                    Pcrs = pcrs
                };

            payload =
                JsonSerializer.SerializeToUtf8Bytes(
                    register);

            var request =
                new IpcRequest
                {
                    Command = "register",
                    Counter = 0,
                    Payload = payload
                };

            var response =
                await SendBootstrapAsync(
                    request);

            if (response == null)
            {
                throw new CryptographicException(
                    "No response received from server.");
            }

            if (!response.Success)
            {
                Console.WriteLine(response.Error);
                throw new InvalidOperationException(
                    $"Server encryption failed: {response.Error}");
            }

            if (string.IsNullOrEmpty(response.Data))
            {
                throw new CryptographicException(
                    "Server did not return TOTP enrollment data.");
            }

            var enrollment =
                JsonSerializer.Deserialize<TotpEnrollment>(
                    response.Data);

            if (enrollment == null)
            {
                throw new CryptographicException(
                    "Invalid TOTP enrollment response.");
            }

            return enrollment;
        }
        finally
        {
            if (payload != null)
            {
                CryptographicOperations.ZeroMemory(
                    payload);
            }
        }
    }

    // =========================================================
    // LOGIN
    // =========================================================

    public async Task<string?> BeginLoginAsync(
        string username,
        byte[] password)
    {
        var request =
            new IpcRequest
            {
                Command = "login",
                Counter = 0,
                Payload =
                    JsonSerializer.SerializeToUtf8Bytes(
                        new LoginRequest
                        {
                            Username = username,
                            Password = password
                        })
            };

        var response =
            await SendBootstrapAsync(request);

        if (response == null ||
            !response.Success)
        {
            return null;
        }

        var result =
            JsonSerializer.Deserialize<LoginBeginResult>(
                response.Data)
            ?? throw new InvalidDataException(
                "Invalid login response.");

        return result.AuthenticationId;
    }

    public async Task<ClientSession?> ConfirmLoginTotpAsync(
        string authenticationId,
        string code)
    {
        if (string.IsNullOrWhiteSpace(authenticationId))
            throw new ArgumentException(
                "Authentication ID is required.",
                nameof(authenticationId));

        if (string.IsNullOrWhiteSpace(code))
            throw new ArgumentException(
                "TOTP code is required.",
                nameof(code));

        var request =
            new IpcRequest
            {
                Command = "confirm-login-totp",
                Counter = 0,
                Payload =
                    JsonSerializer.SerializeToUtf8Bytes(
                        new ConfirmLoginTotpRequest
                        {
                            AuthenticationId =
                                authenticationId,

                            Code =
                                code
                        })
            };

        var response =
            await SendBootstrapAsync(request);

        if (response == null ||
            !response.Success)
        {
            return null;
        }

        var login =
            JsonSerializer.Deserialize<LoginResult>(
                response.Data)
            ?? throw new InvalidDataException();

        return new ClientSession(
            login.Username,
            login.SessionId,
            login.SessionKey,
            login.CreatedUtc,
            login.ExpiresUtc,
            login.ProtocolVersion);
    }

    public async Task<FileOperationResult?> EncryptFileAsync(
        string inputPath,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        EnsureAuthenticated();

        var request =
            new IpcRequest
            {
                Command = "encrypt",
                Payload =
                    JsonSerializer.SerializeToUtf8Bytes(
                        new EncryptFileRequest
                        {
                            InputPath = inputPath
                        })
            };

        var response =
            await SendAsync(
                request,
                cancellationToken);

        if (!response.Success)
        {
            throw new InvalidOperationException(
                $"Server encryption failed: {response.Error}");
        }

        return JsonSerializer.Deserialize<FileOperationResult>(
            response.Data);
    }

    public async Task<FileOperationResult?> DecryptFileAsync(
        string inputPath,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        EnsureAuthenticated();

        var request =
            new IpcRequest
            {
                Command = "decrypt",
                Payload =
                    JsonSerializer.SerializeToUtf8Bytes(
                        new DecryptFileRequest
                        {
                            InputPath = inputPath
                        })
            };

        var response =
            await SendAsync(
                request,
                cancellationToken);

        if (!response.Success)
        {
            throw new InvalidOperationException(
                $"Server decryption failed: {response.Error}");
        }

        return JsonSerializer.Deserialize<FileOperationResult>(
            response.Data);
    }

    public async Task LogoutAsync(
        CancellationToken cancellationToken = default)
    {
        if (_session == null)
            return;

        string sessionId =
            _session.SessionId;

        try
        {
            var request =
                new IpcRequest
                {
                    Command = "logout",
                    SessionId = sessionId,
                    Payload = null
                };

            var response =
                await SendAsync(
                    request,
                    cancellationToken);

            if (!response.Success)
            {
                throw new SecurityException(
                    response.Error ??
                    "Server logout failed.");
            }
        }
        finally
        {
            _session?.Dispose();
            _session = null;
        }
    }

    // =========================================================
    // BOOTSTRAP SEND
    // =========================================================

    private async Task<IpcResponse?> SendBootstrapAsync(
    IpcRequest request,
    CancellationToken ct = default)
    {
        byte[]? plaintext = null;
        byte[]? responseBytes = null;

        try
        {
            plaintext =
                JsonSerializer.SerializeToUtf8Bytes(
                    request);

            using var client =
                new NamedPipeClientStream(
                    ".",
                    PipeName,
                    PipeDirection.InOut,
                    PipeOptions.Asynchronous);

            await client.ConnectAsync(ct);

            // =================================================
            // SEND REQUEST LENGTH
            // =================================================

            byte[] lengthPrefix =
                BitConverter.GetBytes(
                    plaintext.Length);

            await client.WriteAsync(
                lengthPrefix,
                ct);

            // =================================================
            // SEND REQUEST BODY
            // =================================================

            await client.WriteAsync(
                plaintext,
                ct);

            await client.FlushAsync(
                ct);

            // =================================================
            // READ RESPONSE LENGTH
            // =================================================

            byte[] responseLength =
                new byte[4];

            await HelperMethods.ReadExactAsync(
                client,
                responseLength,
                responseLength.Length);

            int len =
                BitConverter.ToInt32(
                    responseLength,
                    0);

            if (len <= 0 ||
                len > 16 * 1024 * 1024)
            {
                throw new SecurityException(
                    $"Invalid response size: {len}");
            }

            // =================================================
            // READ RESPONSE BODY
            // =================================================

            responseBytes =
                new byte[len];

            await HelperMethods.ReadExactAsync(
                client,
                responseBytes,
                responseBytes.Length);

            return JsonSerializer.Deserialize<IpcResponse>(
                responseBytes);
        }
        finally
        {
            if (plaintext != null)
            {
                CryptographicOperations.ZeroMemory(
                    plaintext);
            }

            if (responseBytes != null)
            {
                CryptographicOperations.ZeroMemory(
                    responseBytes);
            }
        }
    }

    // =========================================================
    // AUTHENTICATED SEND
    // =========================================================

    private async Task<IpcResponse> SendAsync(
      IpcRequest request,
      CancellationToken ct = default)
    {
        await _sendLock.WaitAsync(ct);

        try
        {
            ClientSession session =
                ClientSessionManager.Current;

            request.Counter =
                session.NextCounter();

            request.SessionId =
                session.SessionId;

            byte[]? plaintext = null;
            byte[]? payload = null;
            byte[]? responseBytes = null;
            byte[]? decrypted = null;

            try
            {
                plaintext =
                    JsonSerializer.SerializeToUtf8Bytes(
                        request);

                var envelope =
                    VaultTransportClient.EncryptOutgoing(
                        session.SessionKey.Export(),
                        plaintext,
                        session.SessionId,
                        request.Counter,
                        request.Command);

                payload =
                    JsonSerializer.SerializeToUtf8Bytes(
                        envelope);

                await using var client =
                    new NamedPipeClientStream(
                        ".",
                        PipeName,
                        PipeDirection.InOut,
                        PipeOptions.Asynchronous);

                await client.ConnectAsync(ct);

                byte[] lengthPrefix =
                    BitConverter.GetBytes(
                        payload.Length);

                await client.WriteAsync(
                    lengthPrefix,
                    ct);

                await client.WriteAsync(
                    payload,
                    ct);

                await client.FlushAsync(
                    ct);

                byte[] responseLength =
                    new byte[4];

                await HelperMethods.ReadExactAsync(
                    client,
                    responseLength,
                    responseLength.Length);

                int len =
                    BitConverter.ToInt32(
                        responseLength,
                        0);

                if (len <= 0 ||
                    len > 16 * 1024 * 1024)
                {
                    throw new SecurityException(
                        $"Invalid response size: {len}");
                }

                responseBytes =
                    new byte[len];

                await HelperMethods.ReadExactAsync(
                    client,
                    responseBytes,
                    responseBytes.Length);

                var responseEnvelope =
                    JsonSerializer.Deserialize<SecureEnvelope>(
                        responseBytes)
                    ?? throw new SecurityException(
                        "Invalid response envelope.");

                decrypted =
                    VaultTransportClient.Decrypt(
                        session.SessionKey.Export(),
                        responseEnvelope,
                        session.SessionId,
                        request.Counter,
                        request.Command);

                return JsonSerializer.Deserialize<IpcResponse>(
                           decrypted)
                       ?? throw new SecurityException(
                           "Invalid response.");
            }
            finally
            {
                if (plaintext != null)
                    CryptographicOperations.ZeroMemory(
                        plaintext);

                if (payload != null)
                    CryptographicOperations.ZeroMemory(
                        payload);

                if (responseBytes != null)
                    CryptographicOperations.ZeroMemory(
                        responseBytes);

                if (decrypted != null)
                    CryptographicOperations.ZeroMemory(
                        decrypted);
            }
        }
        finally
        {
            _sendLock.Release();
        }
    }

    private void EnsureAuthenticated()
    {
        ClientSession session =
            ClientSessionManager.Current;

        if (string.IsNullOrWhiteSpace(
                session.SessionId))
        {
            throw new InvalidOperationException(
                "Invalid session.");
        }

        _ = session.SessionKey;
    }
}