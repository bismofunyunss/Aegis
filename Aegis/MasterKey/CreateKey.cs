using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Tpm2Lib;

namespace Aegis.MasterKey
{
    internal class CreateKey
    {
        public TpmHandle GetOrCreateSrk(Tpm2 tpm)
        {
            var srkHandle = new TpmHandle(0x81066645);

            try
            {
                tpm.ReadPublic(srkHandle, out _, out _);
                return srkHandle;
            }
            catch
            {
                var srkTemplate = new TpmPublic(
                    TpmAlgId.Sha256,
                    ObjectAttr.Restricted | ObjectAttr.Decrypt |
                    ObjectAttr.FixedTPM | ObjectAttr.FixedParent |
                    ObjectAttr.SensitiveDataOrigin | ObjectAttr.UserWithAuth,
                    new byte[0],
                    new RsaParms(
                        new SymDefObject(TpmAlgId.Aes, 128, TpmAlgId.Cfb),
                        new NullAsymScheme(),
                        2048,
                        0),
                    new Tpm2bPublicKeyRsa()
                );

                var sensCreate = new SensitiveCreate(
                    new byte[0],
                    new byte[0]);

                var transientHandle = tpm.CreatePrimary(
                    TpmRh.Owner,
                    sensCreate,
                    srkTemplate,
                    new byte[0],
                    new PcrSelection[0],
                    out TpmPublic pub,
                    out _,
                    out byte[] _,
                    out TkCreation _);

                tpm.EvictControl(
                    TpmRh.Owner,
                    transientHandle,
                    srkHandle);

                tpm.FlushContext(transientHandle);
                return srkHandle;
            }
        }

        public byte[] SealMasterKey(
            Tpm2 tpm,
            TpmHandle parent,
            byte[] masterKey)
        {
            var pcrSelection = new[]
            {
                new PcrSelection(TpmAlgId.Sha256, new uint[] { 1, 7, 11 })
            };

            var sensitive = new SensitiveCreate(
                new byte[0], // No password
                masterKey // 64‑byte secret
            );

            var publicArea = new TpmPublic(
                TpmAlgId.Sha256,
                ObjectAttr.FixedTPM |
                ObjectAttr.FixedParent |
                ObjectAttr.UserWithAuth |
                ObjectAttr.NoDA,
                new byte[0],
                new KeyedhashParms(
                    new NullSchemeKeyedhash()),
                new Tpm2bDigestKeyedhash()
            );

            var sealedPrivate = tpm.Create(
                parent,
                sensitive,
                publicArea,
                new byte[0],
                pcrSelection,
                out TpmPublic pub,
                out _,
                out _,
                out _);

            // Store these blobs (disk / registry / etc)
            return sealedPrivate.buffer;
        }

        public byte[] GenerateMasterKey()
        {
            byte[] key = new byte[64];
            RandomNumberGenerator.Fill(key);
            return key;
        }

        /// <summary>
        /// Creates a 64-byte master key, sealed to TPM PCRs 1,7,11 and additionally protected by a user-derived secret.
        /// Returns the persistent handle, master key in memory, and the policy digest.
        /// </summary>
        public TpmHandle CreateSealedMasterKeyWithUserAuth(
            Tpm2 tpm,
            byte[] userDerivedKey, // e.g. 64-byte Argon2id(password, salt)
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
            catch
            {
                /* ignore */
            }

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
    }
}
