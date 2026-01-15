using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Aegis.App.TPM
{
    using System;
    using Tpm2Lib;
    using System.Security.Cryptography;

    public static class TpmBaseline
    {
        /// <summary>
        /// Capture a PCR baseline for the given PCR indices.
        /// </summary>
        /// <param name="tpm">Your TPM instance</param>
        /// <param name="pcrs">Array of PCR indices to monitor</param>
        /// <returns>Array of PCR values in same order as pcrs</returns>
        public static byte[][] CaptureBaseline(Tpm2 tpm, uint[] pcrs)
        {
            if (tpm == null) throw new ArgumentNullException(nameof(tpm));
            if (pcrs == null || pcrs.Length == 0) throw new ArgumentException("No PCRs specified", nameof(pcrs));

            // Prepare PCR selection
            PcrSelection[] selIn = new PcrSelection[] { new PcrSelection(TpmAlgId.Sha256, pcrs) };

            // Read PCRs
            tpm.PcrRead(selIn, out PcrSelection[] selOut, out Tpm2bDigest[] pcrValues);

            // Copy the values into a byte[][] array
            byte[][] baseline = new byte[pcrValues.Length][];
            for (int i = 0; i < pcrValues.Length; i++)
            {
                baseline[i] = (byte[])pcrValues[i].buffer.Clone();
            }

            return baseline;
        }

        /// <summary>
        /// Save the baseline securely (example: encrypted with master key)
        /// </summary>
        public static void SaveBaseline(byte[][] baseline, byte[] masterKey, string filePath)
        {
            using var aes = new AesGcm(masterKey);
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] ciphertext = new byte[baseline.Length * 32]; // assuming SHA-256
            byte[] tag = new byte[16];

            // Flatten the baseline for encryption
            byte[] flat = new byte[baseline.Length * 32];
            for (int i = 0; i < baseline.Length; i++)
            {
                Array.Copy(baseline[i], 0, flat, i * 32, 32);
            }

            aes.Encrypt(nonce, flat, ciphertext, tag);

            // Save file (nonce + tag + ciphertext)
            using var fs = System.IO.File.Create(filePath);
            fs.Write(nonce, 0, nonce.Length);
            fs.Write(tag, 0, tag.Length);
            fs.Write(ciphertext, 0, ciphertext.Length);
        }

        /// <summary>
        /// Load the baseline from storage and decrypt
        /// </summary>
        public static byte[][] LoadBaseline(byte[] masterKey, string filePath, int pcrCount)
        {
            byte[] data = System.IO.File.ReadAllBytes(filePath);
            byte[] nonce = new byte[12];
            byte[] tag = new byte[16];
            byte[] ciphertext = new byte[data.Length - 28];

            Array.Copy(data, 0, nonce, 0, 12);
            Array.Copy(data, 12, tag, 0, 16);
            Array.Copy(data, 28, ciphertext, 0, ciphertext.Length);

            using var aes = new AesGcm(masterKey);
            byte[] flat = new byte[ciphertext.Length];
            aes.Decrypt(nonce, ciphertext, tag, flat);

            // Unflatten into PCR array
            byte[][] baseline = new byte[pcrCount][];
            for (int i = 0; i < pcrCount; i++)
            {
                baseline[i] = new byte[32];
                Array.Copy(flat, i * 32, baseline[i], 0, 32);
            }

            return baseline;
        }
    }

}
