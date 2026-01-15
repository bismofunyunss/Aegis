using Aegis.App.PcrUtils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Tpm2Lib;

namespace Aegis.App.TPM
{
    internal class TpmProtection
    {
        /// <summary>
        /// Checks if the TPM is present and performs a full self-test.
        /// </summary>
        public static bool IsTpmOperational(Tpm2 tpm)
        {
            if (tpm == null)
                return false;

            try
            {
                // Run full TPM self-test: 1 = full, 0 = partial
                tpm.SelfTest(1);

                // Simple presence check: calling GetCapability should succeed
                tpm.GetCapability(Cap.TpmProperties, 0, 1, out _);

                return true;
            }
            catch
            {
                // TPM error → possibly tampered or unavailable
                return false;
            }
        }

        /// <summary>
        /// Verify PCR values against a known baseline.
        /// </summary>
        /// <param name="tpm">TPM instance</param>
        /// <param name="pcrs">Array of PCR indices to check</param>
        /// <param name="baseline">Array of expected PCR values (must match length of pcrs)</param>
        /// <returns>True if all PCRs match baseline</returns>
        public static bool VerifyPcrs(Tpm2 tpm, uint[] pcrs, byte[][] baseline)
        {
            if (tpm == null || pcrs == null || baseline == null || pcrs.Length != baseline.Length)
                return false;

            try
            {
                // Prepare selection for reading PCRs
                var selIn = new PcrSelection[] { new PcrSelection(TpmAlgId.Sha256, pcrs) };

                // Read PCRs from TPM
                tpm.PcrRead(selIn, out PcrSelection[] selOut, out Tpm2bDigest[] pcrValues);

                for (int i = 0; i < pcrs.Length; i++)
                {
                    byte[] actual = pcrValues[i].buffer;
                    byte[] expected = baseline[i];

                    // Compare securely
                    if (!CryptographicOperations.FixedTimeEquals(actual, expected))
                        return false;
                }

                return true;
            }
            catch
            {
                return false; // TPM error → treat as tampered
            }
        }

        /// <summary>
        /// Throws a SecurityException if TPM is not operational or PCRs do not match baseline.
        /// </summary>
        public static void EnforceTpmIntegrity(
           Tpm2 tpm,
           uint[] pcrs,
           Dictionary<uint, byte[]> baseline)
        {
            var current = PcrUtilities.ReadPcrs(tpm, pcrs);

            foreach (var pcr in pcrs)
            {
                if (!baseline.TryGetValue(pcr, out var expected))
                    throw new SecurityException($"Missing PCR {pcr} in baseline");

                if (!CryptographicOperations.FixedTimeEquals(
                        current[pcr],
                        expected))
                {
                    throw new SecurityException($"PCR {pcr} mismatch");
                }
            }
        }

        public static Dictionary<uint, byte[]> DeserializeBaseline(uint[] pcrs, byte[] serializedBaseline)
        {
            if (pcrs == null) throw new ArgumentNullException(nameof(pcrs));
            if (serializedBaseline == null) throw new ArgumentNullException(nameof(serializedBaseline));

            var result = new Dictionary<uint, byte[]>();

            int offset = 0;
            foreach (var pcr in pcrs)
            {
                if (offset + 32 > serializedBaseline.Length) // assuming SHA-256 PCRs
                    throw new InvalidOperationException("Serialized baseline is too short");

                byte[] value = new byte[32];
                Array.Copy(serializedBaseline, offset, value, 0, 32);
                result[pcr] = value;

                offset += 32;
            }

            return result;
        }

    }
}
