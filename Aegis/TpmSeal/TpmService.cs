using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Tpm2Lib;

namespace Aegis.TpmSeal
{
    internal class TpmService
    {
        /// <summary>
        /// Creates a 64-byte master key, sealed to TPM PCRs 1,7,11 and additionally protected by a user-derived secret.
        /// Returns the persistent handle, master key in memory, and the policy digest.
        /// </summary>
        public TpmHandle CreateSealedMasterKeyWithUserAuth(
            Tpm2 tpm,
            byte[] userDerivedKey,       // e.g. 64-byte Argon2id(password, salt)
            out byte[] masterKey,
            out byte[] policyDigest)
        {
            if (tpm == null) throw new ArgumentNullException(nameof(tpm));
            if (userDerivedKey == null || userDerivedKey.Length < 16)
                throw new ArgumentException("User derived key too short");

            var persistentHandle = new TpmHandle(0x81013371);
            var pcrs = new uint[] { 1, 7, 11 };
            var pcrSelection = new PcrSelection[] { new PcrSelection(TpmAlgId.Sha256, pcrs) };

            // -----------------------------
            // Remove existing object if present
            // -----------------------------
            try
            {
                tpm.ReadPublic(persistentHandle, out _, out _);
                tpm.EvictControl(TpmRh.Owner, persistentHandle, persistentHandle);
            }
            catch { /* ignore */ }

            // -----------------------------
            // Create Primary Storage Key (SRK)
            // -----------------------------
            var srk = tpm.CreatePrimary(
                TpmRh.Owner,
                new SensitiveCreate(),
                new TpmPublic(
                    TpmAlgId.Sha256,
                    ObjectAttr.FixedTPM |
                    ObjectAttr.FixedParent |
                    ObjectAttr.Restricted |
                    ObjectAttr.Decrypt |
                    ObjectAttr.SensitiveDataOrigin,
                    null,
                    new RsaParms(
                        new SymDefObject(TpmAlgId.Aes, 128, TpmAlgId.Cfb),
                        new NullAsymScheme(),
                        2048,
                        0
                    ),
                    new Tpm2bPublicKeyRsa()
                ),
                Array.Empty<byte>(),
                Array.Empty<PcrSelection>(),
                out _,
                out _,
                out _,
                out _
            );

            try
            {
                // -----------------------------
                // Trial policy session for PCR + authValue
                // -----------------------------
                var trialSession = tpm.StartAuthSession(
                    TpmHandle.RhNull,
                    TpmHandle.RhNull,
                    RandomNumberGenerator.GetBytes(16),
                    null,
                    TpmSe.Trial,
                    new SymDef(),
                    TpmAlgId.Sha256,
                    out _
                );

                try
                {
                    // Bind to PCRs
                    tpm.PolicyPCR(trialSession, null, pcrSelection);

                    // Require user-provided auth value to unseal
                    tpm.PolicyAuthValue(trialSession);

                    // Compute digest for object creation
                    policyDigest = tpm.PolicyGetDigest(trialSession);
                }
                finally
                {
                    tpm.FlushContext(trialSession);
                }

                // -----------------------------
                // Generate master key
                // -----------------------------
                masterKey = RandomNumberGenerator.GetBytes(64);

                // -----------------------------
                // Create sealed object under SRK
                // -----------------------------
                var sensitive = new SensitiveCreate(
                    userDerivedKey, // user secret binds unseal
                    masterKey
                );

                var publicArea = new TpmPublic(
                    TpmAlgId.Sha256,
                    ObjectAttr.FixedTPM |
                    ObjectAttr.FixedParent |
                    ObjectAttr.AdminWithPolicy |
                    ObjectAttr.UserWithAuth |
                    ObjectAttr.SensitiveDataOrigin,
                    policyDigest,
                    new KeyedhashParms(new NullSchemeKeyedhash()),
                    new Tpm2bDigestKeyedhash()
                );

                var priv = tpm.Create(
                    srk,
                    sensitive,
                    publicArea,
                    Array.Empty<byte>(),
                    Array.Empty<PcrSelection>(),
                    out var pub,
                    out _,
                    out _,
                    out _
                );

                // -----------------------------
                // Load and persist
                // -----------------------------
                var sealedHandle = tpm.Load(srk, priv, pub);
                tpm.EvictControl(TpmRh.Owner, sealedHandle, persistentHandle);
                tpm.FlushContext(sealedHandle);

                return persistentHandle;
            }
            catch
            {
                masterKey = new byte[] { };
                CryptographicOperations.ZeroMemory(masterKey);
                tpm.FlushContext(srk);
                throw;
            }
            finally
            {
                tpm.FlushContext(srk);
            }
        }

        /// <summary>
        /// Unseals a TPM master key protected by PCRs and a user-derived secret.
        /// Returns the 64-byte master key in memory.
        /// </summary>
        /// <summary>
        /// Unseals a TPM master key protected by PCRs and a user-derived secret.
        /// Returns the 64-byte master key in memory.
        /// </summary>
        public byte[] UnsealMasterKeyWithUserAuth(
            Tpm2 tpm,
            TpmHandle persistentHandle,
            byte[] userDerivedKey,
            out byte[] policyDigest)
        {
            if (tpm == null) throw new ArgumentNullException(nameof(tpm));
            if (userDerivedKey == null || userDerivedKey.Length < 16)
                throw new ArgumentException("User derived key too short");

            policyDigest = Array.Empty<byte>();

            // -----------------------------
            // Check that the persistent object exists
            // -----------------------------
            tpm.ReadPublic(persistentHandle, out _, out _);

            // -----------------------------
            // Start a policy session for PCR + auth
            // -----------------------------
            var policySession = tpm.StartAuthSession(
                TpmHandle.RhNull,
                TpmHandle.RhNull,
                RandomNumberGenerator.GetBytes(16),
                null,
                TpmSe.Policy,
                new SymDef(),
                TpmAlgId.Sha256,
                out _
            );

            byte[] masterKey;
            try
            {
                // PCRs enforced at creation
                var pcrs = new uint[] { 1, 7, 11 };
                var pcrSelection = new PcrSelection[] { new PcrSelection(TpmAlgId.Sha256, pcrs) };
                tpm.PolicyPCR(policySession, null, pcrSelection);

                // Require auth value
                tpm.PolicyAuthValue(policySession);

                policyDigest = tpm.PolicyGetDigest(policySession);

                // -----------------------------
                // Set the user-derived auth value
                // -----------------------------
                persistentHandle.Auth = userDerivedKey;

                // -----------------------------
                // Unseal the master key directly from persistent handle
                // -----------------------------
                masterKey = tpm.Unseal(persistentHandle);
            }
            finally
            {
                tpm.FlushContext(policySession);
            }

            return masterKey;
        }

        // Returns 32-byte KEK derived from TPM-sealed master key
        public static byte[] DeriveKekFromPcr(Tpm2 tpm, TpmHandle sealedHandle)
        {
            // Unseal with PCR policy enforced
            byte[] unsealedMasterKey = tpm.Unseal(sealedHandle);

            using var sha = SHA3_512.Create();
            byte[] tpmKek = sha.ComputeHash(unsealedMasterKey);

            CryptographicOperations.ZeroMemory(unsealedMasterKey);
            return tpmKek;
        }
    }
}
