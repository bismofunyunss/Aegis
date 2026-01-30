using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Aegis.App.Ipc
{
    internal static class VaultTransportClient
    {
        public static SecureEnvelope EncryptOutgoing(
            byte[] key,
            byte[] plaintext,
            string sessionId,
            ulong counter,
            string command)
        {
            byte[] nonce =
                RandomNumberGenerator.GetBytes(12);

            byte[] ciphertext =
                new byte[plaintext.Length];

            byte[] tag =
                new byte[16];

            byte[] aad =
                Encoding.UTF8.GetBytes(
                    $"{sessionId}:{counter}:{command}");

            using var aes =
                new AesGcm(key, 16);

            aes.Encrypt(
                nonce,
                plaintext,
                ciphertext,
                tag,
                aad);

            return new SecureEnvelope
            {
                SessionId = sessionId,
                Counter = counter,
                Command = command,

                Nonce = nonce,
                Ciphertext = ciphertext,
                Tag = tag
            };
        }

        public static byte[] Decrypt(
    byte[] key,
    SecureEnvelope env,
    string sessionId,
    ulong counter,
    string command)
        {
            byte[] plaintext = new byte[env.Ciphertext.Length];
            byte[] aad = Encoding.UTF8.GetBytes(
    $"{sessionId}:{counter}:{command}");

            using var aes = new AesGcm(key, 16);
            aes.Decrypt(env.Nonce, env.Ciphertext, env.Tag, plaintext, aad);

            return plaintext;
        }
    }
}
