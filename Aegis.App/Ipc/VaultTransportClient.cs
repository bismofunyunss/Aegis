using Aegis.Contracts;
using System.Buffers.Binary;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.App.Ipc;

public static class VaultTransportClient
{
    private static readonly byte[] AeadDomain =
        Encoding.ASCII.GetBytes("Aegis-IPC-v1");


    public static SecureEnvelope EncryptOutgoing(
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

        if (plaintext.Length >
            IpcProtocol.MaxMessageSize)
        {
            throw new SecurityException(
                "IPC message is too large.");
        }

        byte[] directionalKey =
            DeriveDirectionalKey(
                sessionKey,
                IpcProtocol.C2SKeyInfo);

        try
        {
            byte[] nonce =
                RandomNumberGenerator.GetBytes(
                    IpcProtocol.NonceSize);

            byte[] ciphertext =
                new byte[plaintext.Length];

            byte[] tag =
                new byte[IpcProtocol.TagSize];

            byte[] aad =
                BuildAad(
                    IpcProtocol.Version,
                    IpcProtocol.DirectionClientToServer,
                    sessionId,
                    counter,
                    command);

            try
            {
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
            finally
            {
                CryptographicOperations.ZeroMemory(
                    aad);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                directionalKey);
        }
    }


    public static byte[] DecryptIncoming(
        ReadOnlySpan<byte> sessionKey,
        SecureEnvelope envelope,
        string expectedSessionId,
        ulong expectedCounter,
        string expectedCommand)
    {
        ValidateSessionKey(sessionKey);

        ValidateMetadata(
            expectedSessionId,
            expectedCounter,
            expectedCommand);

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

        try
        {
            byte[] plaintext =
                new byte[
                    envelope.Ciphertext.Length];

            byte[] aad =
                BuildAad(
                    envelope.ProtocolVersion,
                    envelope.Direction,
                    envelope.SessionId,
                    envelope.Counter,
                    envelope.Command);

            try
            {
                using var aes =
                    new AesGcm(
                        directionalKey,
                        IpcProtocol.TagSize);

                try
                {
                    aes.Decrypt(
                        envelope.Nonce,
                        envelope.Ciphertext,
                        envelope.Tag,
                        plaintext,
                        aad);
                }
                catch (CryptographicException)
                {
                    CryptographicOperations.ZeroMemory(
                        plaintext);

                    throw new SecurityException(
                        "IPC authentication failed.");
                }

                return plaintext;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    aad);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                directionalKey);
        }
    }


    private static byte[] DeriveDirectionalKey(
        ReadOnlySpan<byte> sessionKey,
        string info)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            info);

        byte[] infoBytes =
            Encoding.UTF8.GetBytes(info);

        byte[] expandInput =
            new byte[
                AeadDomain.Length +
                infoBytes.Length +
                1];

        byte[] hmacKey =
            sessionKey.ToArray();

        byte[] output =
            new byte[
                IpcProtocol.SessionKeySize];

        try
        {
            int offset = 0;

            /*
             * Domain separation:
             *
             * Aegis.IPC.v1 || info || 0x01
             *
             * This is equivalent to a single-block
             * HKDF-Expand operation where the already
             * random 256-bit session key is used as
             * the PRK.
             */

            AeadDomain.CopyTo(
                expandInput,
                offset);

            offset +=
                AeadDomain.Length;

            infoBytes.CopyTo(
                expandInput,
                offset);

            offset +=
                infoBytes.Length;

            expandInput[offset] =
                0x01;

            using var hmac =
                new HMACSHA3_256(hmacKey);

            byte[] result =
                hmac.ComputeHash(
                    expandInput);

            try
            {
                Buffer.BlockCopy(
                    result,
                    0,
                    output,
                    0,
                    output.Length);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    result);
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
                infoBytes);

            CryptographicOperations.ZeroMemory(
                expandInput);

            CryptographicOperations.ZeroMemory(
                hmacKey);
        }
    }


    private static byte[] BuildAad(
        int protocolVersion,
        string direction,
        string sessionId,
        ulong counter,
        string command)
    {
        ValidateMetadata(
            sessionId,
            counter,
            command);

        if (direction.Length >
            byte.MaxValue)
        {
            throw new SecurityException(
                "Invalid IPC direction.");
        }

        byte[] directionBytes =
            Encoding.ASCII.GetBytes(
                direction);

        byte[] sessionIdBytes =
            Encoding.ASCII.GetBytes(
                sessionId);

        byte[] commandBytes =
            Encoding.UTF8.GetBytes(
                command);

        try
        {
            if (directionBytes.Length >
                byte.MaxValue)
            {
                throw new SecurityException(
                    "Invalid IPC direction.");
            }

            if (sessionIdBytes.Length >
                byte.MaxValue)
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

            /*
             * Canonical AAD layout:
             *
             * Int32  protocol version
             * Byte   direction length
             * Bytes  direction
             * Byte   session ID length
             * Bytes  session ID
             * UInt64 counter
             * UInt16 command length
             * Bytes  command
             */

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
                protocolVersion);

            offset +=
                sizeof(int);

            aad[offset++] =
                checked((byte)directionBytes.Length);

            directionBytes.CopyTo(
                aad.AsSpan(offset));

            offset +=
                directionBytes.Length;

            aad[offset++] =
                checked((byte)sessionIdBytes.Length);

            sessionIdBytes.CopyTo(
                aad.AsSpan(offset));

            offset +=
                sessionIdBytes.Length;

            BinaryPrimitives.WriteUInt64LittleEndian(
                aad.AsSpan(offset, sizeof(ulong)),
                counter);

            offset +=
                sizeof(ulong);

            BinaryPrimitives.WriteUInt16LittleEndian(
                aad.AsSpan(offset, sizeof(ushort)),
                checked((ushort)commandBytes.Length));

            offset +=
                sizeof(ushort);

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
        ArgumentNullException.ThrowIfNull(
            sessionId);

        ArgumentNullException.ThrowIfNull(
            command);

        if (sessionId.Length != 32)
        {
            throw new SecurityException(
                "Invalid IPC session.");
        }

        ValidateHexSessionId(
            sessionId);

        if (counter == 0)
        {
            throw new SecurityException(
                "Invalid IPC counter.");
        }

        if (string.IsNullOrWhiteSpace(command) ||
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
                "Unsupported IPC protocol.");
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

        if (envelope.Counter !=
            expectedCounter)
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
                "Invalid IPC authentication tag.");
        }

        if (envelope.Ciphertext is null)
        {
            throw new SecurityException(
                "Invalid IPC ciphertext.");
        }

        if (envelope.Ciphertext.Length >
            IpcProtocol.MaxCiphertextSize)
        {
            throw new SecurityException(
                "Invalid IPC ciphertext.");
        }

        ValidateMetadata(
            envelope.SessionId,
            envelope.Counter,
            envelope.Command);
    }


    private static void ValidateHexSessionId(
        string sessionId)
    {
        foreach (char c in sessionId)
        {
            bool valid =
                c is >= '0' and <= '9'
                or >= 'A' and <= 'F'
                or >= 'a' and <= 'f';

            if (!valid)
            {
                throw new SecurityException(
                    "Invalid IPC session.");
            }
        }
    }
}
