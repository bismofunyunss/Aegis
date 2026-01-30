using Aegis.App.Crypto;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Tpm2Lib;

namespace Aegis.App.PcrUtils
{
    internal class PcrUtilities
    {
        public static Dictionary<uint, byte[]> ReadPcrs(
Tpm2 tpm,
uint[] pcrs)
        {
            var selection = new PcrSelection(
                TpmAlgId.Sha256,
                pcrs.Select(p => (uint)p).ToArray()
            );

            tpm.PcrRead(
                new[] { selection },
                out _,
                out Tpm2bDigest[] values
            );

            var result = new Dictionary<uint, byte[]>();
            for (int i = 0; i < pcrs.Length; i++)
            {
                result[pcrs[i]] = values[i].buffer;
            }

            return result;
        }

        public static byte[] SerializeBaseline(Dictionary<uint, byte[]> pcrs)
        {
            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);

            bw.Write(pcrs.Count);
            foreach (var kv in pcrs.OrderBy(k => k.Key))
            {
                bw.Write(kv.Key);
                bw.Write(kv.Value.Length);
                bw.Write(kv.Value);
            }

            return ms.ToArray();
        }

        public static byte[] EncryptBaseline(SecureMasterKey masterKey, byte[] baseline)
        {
            if (masterKey == null) throw new ArgumentNullException(nameof(masterKey));
            if (baseline == null) throw new ArgumentNullException(nameof(baseline));

            // 1️⃣ Generate a random salt for HKDF key derivation
            byte[] salt = RandomNumberGenerator.GetBytes(128);

            // 2️⃣ Derive AES key from masterKey + salt
            byte[] key = masterKey.DeriveKey(salt, "PCR-BASELINE"u8, 32);

            // 3️⃣ Generate nonce for AES-GCM
            byte[] nonce = RandomNumberGenerator.GetBytes(12);

            byte[] ciphertext = new byte[baseline.Length];
            byte[] tag = new byte[16];

            using var aesGcm = new AesGcm(key, 16);
            aesGcm.Encrypt(nonce, baseline, ciphertext, tag);

            // 4️⃣ Persist salt + nonce + tag + ciphertext
            return salt.Concat(nonce).Concat(tag).Concat(ciphertext).ToArray();
        }

        public static byte[] DecryptBaseline(SecureMasterKey masterKey, byte[] encryptedBaseline)
        {
            if (masterKey == null) throw new ArgumentNullException(nameof(masterKey));
            if (encryptedBaseline == null || encryptedBaseline.Length < 128 + 12 + 16)
                throw new ArgumentException("Invalid encrypted baseline");

            // 1️⃣ Extract salt, nonce, tag, ciphertext
            byte[] salt = encryptedBaseline.Take(128).ToArray();
            byte[] nonce = encryptedBaseline.Skip(128).Take(12).ToArray();
            byte[] tag = encryptedBaseline.Skip(128 + 12).Take(16).ToArray();
            byte[] ciphertext = encryptedBaseline.Skip(128 + 12 + 16).ToArray();

            // 2️⃣ Derive AES key from masterKey + extracted salt
            byte[] key = masterKey.DeriveKey(salt, "PCR-BASELINE"u8, 32);

            // 3️⃣ Decrypt
            byte[] plaintext = new byte[ciphertext.Length];
            using var aesGcm = new AesGcm(key, 16);
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);

            return plaintext;
        }


        /// <summary>
        /// Deserialize the decrypted baseline into a dictionary of PCR index -> PCR value.
        /// </summary>
        /// <param name="serializedBaseline">Serialized baseline</param>
        /// <returns>Dictionary of PCR index -> PCR value (byte[])</returns>
        public static Dictionary<uint, byte[]> DeserializeBaseline(byte[] serializedBaseline)
        {
            if (serializedBaseline == null || serializedBaseline.Length == 0)
                throw new ArgumentException(nameof(serializedBaseline));

            var dict = new Dictionary<uint, byte[]>();
            using var ms = new MemoryStream(serializedBaseline);
            using var br = new BinaryReader(ms);

            // Read count
            int count = br.ReadInt32();

            for (int i = 0; i < count; i++)
            {
                uint pcrIndex = br.ReadUInt32();
                int valueLen = br.ReadInt32();
                byte[] value = br.ReadBytes(valueLen);

                if (value.Length != valueLen)
                    throw new InvalidDataException("Serialized baseline corrupted");

                dict[pcrIndex] = value;
            }

            return dict;
        }
    }
}
