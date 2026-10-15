using System.Buffers.Binary;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Aegis.Contracts;

namespace Aegis.App.Ipc;

internal static class VaultTransport
{
    private const int AesKeySize = 32;

    private static ReadOnlySpan<byte> DirectionalKeyDomain =>
        "Aegis.IPC.v1"u8;

    // =========================================================
    // ENCRYPT OUTGOING
    // App -> Core
    // =========================================================

    internal static SecureEnvelope EncryptOutgoing(
        ReadOnlySpan<byte> sessionKey,
        ReadOnlySpan<byte> plaintext,
        string sessionId,
        ulong counter,
        string command)
    {
        ValidateSessionKey(sessionKey);
        ValidateMetadata(
            sessionId,
            counter,
            command);

        if (plaintext.Length > IpcProtocol.MaxMessageSize)
        {
            throw new SecurityException(
                "IPC message is too large.");
        }

        byte[] directionalKey =
            DeriveDirectionalKey(
                sessionKey,
                IpcProtocol.C2SKeyInfo);

        byte[] nonce =
            RandomNumberGenerator.GetBytes(
                IpcProtocol.NonceSize);

        byte[] ciphertext =
            new byte[plaintext.Length];

        byte[] tag =
            new byte[IpcProtocol.TagSize];

        byte[]? aad = null;

        try
        {
            aad =
                BuildAad(
                    IpcProtocol.DirectionClientToServer,
                    sessionId,
                    counter,
                    command);

            using var aes =
                new AesGcm(
                    directionalKey,
                    IpcProtocol.TagSize);

            aes.Encrypt(
                nonce,
                plaintext,
                ciphertext,
                tag,
                aad);

            return new SecureEnvelope
            {
                ProtocolVersion =
                    IpcProtocol.Version,

                Direction =
                    IpcProtocol.DirectionClientToServer,

                SessionId =
                    sessionId,

                Counter =
                    counter,

                Command =
                    command,

                Nonce =
                    nonce,

                Ciphertext =
                    ciphertext,

                Tag =
                    tag
            };
        }
        catch
        {
            CryptographicOperations.ZeroMemory(
                nonce);

            CryptographicOperations.ZeroMemory(
                ciphertext);

            CryptographicOperations.ZeroMemory(
                tag);

            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                directionalKey);

            if (aad is not null)
            {
                CryptographicOperations.ZeroMemory(
                    aad);
            }
        }
    }

    // =========================================================
    // DECRYPT RESPONSE
    // Core -> App
    // =========================================================

    internal static byte[] DecryptResponse(
        ReadOnlySpan<byte> sessionKey,
        SecureEnvelope envelope,
        string expectedSessionId,
        ulong expectedCounter,
        string expectedCommand)
    {
        ValidateSessionKey(sessionKey);

        ValidateEnvelope(
            envelope,
            IpcProtocol.DirectionServerToClient,
            expectedSessionId,
            expectedCounter,
            expectedCommand);

        byte[] directionalKey =
            DeriveDirectionalKey(
                sessionKey,
                IpcProtocol.S2CKeyInfo);

        byte[] plaintext =
            new byte[envelope.Ciphertext.Length];

        byte[]? aad = null;

        try
        {
            aad =
                BuildAad(
                    IpcProtocol.DirectionServerToClient,
                    envelope.SessionId,
                    envelope.Counter,
                    envelope.Command);

            using var aes =
                new AesGcm(
                    directionalKey,
                    IpcProtocol.TagSize);

            aes.Decrypt(
                envelope.Nonce,
                envelope.Ciphertext,
                envelope.Tag,
                plaintext,
                aad);

            return plaintext;
        }
        catch (CryptographicException ex)
        {
            CryptographicOperations.ZeroMemory(
                plaintext);

            throw new SecurityException(
                "IPC authentication failed.",
                ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                directionalKey);

            if (aad is not null)
            {
                CryptographicOperations.ZeroMemory(
                    aad);
            }
        }
    }

    // =========================================================
    // DIRECTIONAL KEY DERIVATION
    // =========================================================

    private static byte[] DeriveDirectionalKey(
        ReadOnlySpan<byte> sessionKey,
        string info)
    {
        byte[] domain =
            DirectionalKeyDomain.ToArray();

        byte[] infoBytes =
            Encoding.UTF8.GetBytes(
                info);

        byte[] input =
            new byte[
                domain.Length +
                infoBytes.Length +
                1];

        byte[] output =
            new byte[AesKeySize];

        try
        {
            domain.CopyTo(
                input.AsSpan(0));

            infoBytes.CopyTo(
                input.AsSpan(domain.Length));

            input[^1] = 0x01;

            using var hmac =
                new HMACSHA256(
                    sessionKey.ToArray());

            byte[] expanded =
                hmac.ComputeHash(input);

            try
            {
                expanded.AsSpan(
                    0,
                    AesKeySize)
                    .CopyTo(output);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    expanded);
            }

            return output;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(
                output);

            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                domain);

            CryptographicOperations.ZeroMemory(
                infoBytes);

            CryptographicOperations.ZeroMemory(
                input);
        }
    }

    // =========================================================
    // AAD
    // MUST MATCH CORE EXACTLY
    // =========================================================

    private static byte[] BuildAad(
        string direction,
        string sessionId,
        ulong counter,
        string command)
    {
        byte[] directionBytes =
            Encoding.UTF8.GetBytes(
                direction);

        byte[] sessionIdBytes =
            Encoding.ASCII.GetBytes(
                sessionId);

        byte[] commandBytes =
            Encoding.UTF8.GetBytes(
                command);

        try
        {
            if (directionBytes.Length > byte.MaxValue)
            {
                throw new SecurityException(
                    "Invalid IPC direction.");
            }

            if (sessionIdBytes.Length > byte.MaxValue)
            {
                throw new SecurityException(
                    "Invalid IPC session.");
            }

            if (commandBytes.Length >
                ushort.MaxValue)
            {
                throw new SecurityException(
                    "Invalid IPC command.");
            }

            int length =
                sizeof(int) +
                sizeof(byte) +
                directionBytes.Length +
                sizeof(byte) +
                sessionIdBytes.Length +
                sizeof(ulong) +
                sizeof(ushort) +
                commandBytes.Length;

            byte[] aad =
                new byte[length];

            int offset = 0;

            BinaryPrimitives.WriteInt32LittleEndian(
                aad.AsSpan(offset, sizeof(int)),
                IpcProtocol.Version);

            offset += sizeof(int);

            aad[offset++] =
                checked((byte)directionBytes.Length);

            directionBytes.CopyTo(
                aad.AsSpan(offset));

            offset += directionBytes.Length;

            aad[offset++] =
                checked((byte)sessionIdBytes.Length);

            sessionIdBytes.CopyTo(
                aad.AsSpan(offset));

            offset += sessionIdBytes.Length;

            BinaryPrimitives.WriteUInt64LittleEndian(
                aad.AsSpan(offset, sizeof(ulong)),
                counter);

            offset += sizeof(ulong);

            BinaryPrimitives.WriteUInt16LittleEndian(
                aad.AsSpan(offset, sizeof(ushort)),
                checked((ushort)commandBytes.Length));

            offset += sizeof(ushort);

            commandBytes.CopyTo(
                aad.AsSpan(offset));

            return aad;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                directionBytes);

            CryptographicOperations.ZeroMemory(
                sessionIdBytes);

            CryptographicOperations.ZeroMemory(
                commandBytes);
        }
    }

    // =========================================================
    // ENVELOPE VALIDATION
    // =========================================================

    private static void ValidateEnvelope(
        SecureEnvelope envelope,
        string expectedDirection,
        string expectedSessionId,
        ulong expectedCounter,
        string expectedCommand)
    {
        ArgumentNullException.ThrowIfNull(
            envelope);

        if (envelope.ProtocolVersion !=
            IpcProtocol.Version)
        {
            throw new SecurityException(
                "Invalid IPC protocol.");
        }

        if (!string.Equals(
                envelope.Direction,
                expectedDirection,
                StringComparison.Ordinal))
        {
            throw new SecurityException(
                "Invalid IPC direction.");
        }

        if (!string.Equals(
                envelope.SessionId,
                expectedSessionId,
                StringComparison.Ordinal))
        {
            throw new SecurityException(
                "Invalid IPC session.");
        }

        if (envelope.Counter != expectedCounter)
        {
            throw new SecurityException(
                "Invalid IPC counter.");
        }

        if (!string.Equals(
                envelope.Command,
                expectedCommand,
                StringComparison.Ordinal))
        {
            throw new SecurityException(
                "Invalid IPC command.");
        }

        ValidateSessionId(
            envelope.SessionId);

        if (envelope.Counter == 0)
        {
            throw new SecurityException(
                "Invalid IPC counter.");
        }

        if (envelope.Nonce is null ||
            envelope.Nonce.Length !=
            IpcProtocol.NonceSize)
        {
            throw new SecurityException(
                "Invalid IPC nonce.");
        }

        if (envelope.Tag is null ||
            envelope.Tag.Length !=
            IpcProtocol.TagSize)
        {
            throw new SecurityException(
                "Invalid IPC tag.");
        }

        if (envelope.Ciphertext is null ||
            envelope.Ciphertext.Length >
            IpcProtocol.MaxCiphertextSize)
        {
            throw new SecurityException(
                "Invalid IPC ciphertext.");
        }

        ValidateCommand(
            envelope.Command);
    }

    // =========================================================
    // VALIDATION
    // =========================================================

    private static void ValidateSessionKey(
        ReadOnlySpan<byte> sessionKey)
    {
        if (sessionKey.Length !=
            IpcProtocol.SessionKeySize)
        {
            throw new SecurityException(
                "Invalid IPC session key.");
        }
    }

    private static void ValidateMetadata(
        string sessionId,
        ulong counter,
        string command)
    {
        ValidateSessionId(
            sessionId);

        if (counter == 0)
        {
            throw new SecurityException(
                "Invalid IPC counter.");
        }

        ValidateCommand(
            command);
    }

    private static void ValidateSessionId(
        string? sessionId)
    {
        if (string.IsNullOrWhiteSpace(
                sessionId) ||
            sessionId.Length != 32)
        {
            throw new SecurityException(
                "Invalid IPC session.");
        }

        foreach (char c in sessionId)
        {
            bool isHex =
                c is >= '0' and <= '9'
                or >= 'A' and <= 'F'
                or >= 'a' and <= 'f';

            if (!isHex)
            {
                throw new SecurityException(
                    "Invalid IPC session.");
            }
        }
    }

    private static void ValidateCommand(
        string? command)
    {
        if (string.IsNullOrWhiteSpace(
                command) ||
            command.Length > 128)
        {
            throw new SecurityException(
                "Invalid IPC command.");
        }

        foreach (char c in command)
        {
            if (char.IsControl(c))
            {
                throw new SecurityException(
                    "Invalid IPC command.");
            }
        }
    }
}
