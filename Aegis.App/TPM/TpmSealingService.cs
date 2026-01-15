using Aegis.App.Core;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Tpm2Lib;

namespace Aegis.App.TPM
{
    public sealed class TpmSealService
    {
            private readonly Tpm2 _tpm;
            private readonly uint[] _pcrs;
            private readonly uint _nvIndex;

            // base offset for logical 1-based counter
            private ulong _nvBase = 0;

            public TpmSealService(Tpm2 tpm, string username, uint[] pcrs = null)
            {
                _tpm = tpm ?? throw new ArgumentNullException(nameof(tpm));
                _pcrs = pcrs ?? new uint[] { 1, 7, 11 };
                _nvIndex = DeriveNvIndex(username);

                EnsureNvCounterExists();
            }

            /// <summary>
            /// Derives a per-user NV index (3000–3999)
            /// </summary>
            public static uint DeriveNvIndex(string username)
            {
                byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(username));
                uint idx = ((uint)hash[0] << 16 | (uint)hash[1] << 8 | hash[2]) % 1000;
                return 3000 + idx;
            }

            /// <summary>
            /// Ensure NV counter exists and record its base for logical counter
            /// </summary>
            private void EnsureNvCounterExists()
            {
                var nvHandle = TpmHandle.NV(_nvIndex);

                try
                {
                    _tpm.NvReadPublic(nvHandle, out _);
                    // Record the current value as base for logical 1-based counter
                    _nvBase = GetNvCounter() - 1;
                    return;
                }
                catch (TpmException ex) when (ex.RawResponse == TpmRc.Handle || ex.RawResponse == TpmRc.Value)
                {
                    // NV index not defined → define it
                }

                var nvPublic = new NvPublic(
                    nvHandle,
                    TpmAlgId.Sha256,
                    NvAttr.Counter | NvAttr.Authread | NvAttr.Authwrite | NvAttr.NoDa,
                    Array.Empty<byte>(),
                    8
                );

                _tpm.NvDefineSpace(TpmRh.Owner, Array.Empty<byte>(), nvPublic);

                // Increment once to initialize TPM counter
                _tpm.NvIncrement(nvHandle, nvHandle);

                // Logical base is the first TPM value minus 1
                _nvBase = GetNvCounter() - 1;
            }

            /// <summary>
            /// Get TPM counter (raw)
            /// </summary>
            public ulong GetNvCounter()
            {
                var nvHandle = TpmHandle.NV(_nvIndex);
                byte[] data = _tpm.NvRead(nvHandle, nvHandle, 8, 0);
                return BinaryPrimitives.ReadUInt64BigEndian(data);
            }

            /// <summary>
            /// Get logical 1-based counter
            /// </summary>
            public ulong GetLogicalCounter()
            {
                return GetNvCounter() - _nvBase;
            }

            /// <summary>
            /// Increment TPM counter and return logical 1-based value
            /// </summary>
            public ulong IncrementLogicalCounter()
            {
                var nvHandle = TpmHandle.NV(_nvIndex);
                _tpm.NvIncrement(nvHandle, nvHandle);
                return GetLogicalCounter();
            }

            /// <summary>
            /// Throw if a sealed blob's counter is ahead of TPM NV counter (rollback detection)
            /// </summary>
            public void EnforceRollback(KeyBlob blob)
            {
                if (blob == null) throw new ArgumentNullException(nameof(blob));

                ulong tpmCounter = GetLogicalCounter();
                if (tpmCounter < blob.NvCounter)
                    throw new SecurityException(
                        $"Rollback detected (TPM={tpmCounter}, Blob={blob.NvCounter})"
                    );
            }

            public TpmHandle CreateOrLoadSrk(uint handle = 0x81000001)
        {
            var srkHandle = new TpmHandle(handle);

            try
            {
                _tpm.ReadPublic(srkHandle, out _, out _);
                return srkHandle; // already exists
            }
            catch
            {
                var srkPublic = new TpmPublic(
                    TpmAlgId.Rsa,
                    ObjectAttr.Restricted |
                    ObjectAttr.Decrypt |
                    ObjectAttr.FixedTPM |
                    ObjectAttr.FixedParent |
                    ObjectAttr.SensitiveDataOrigin |
                    ObjectAttr.UserWithAuth |
                    ObjectAttr.NoDA,
                    new byte[0],
                    new RsaParms(
                        new SymDefObject(TpmAlgId.Aes, 128, TpmAlgId.Cfb),
                        new NullAsymScheme(),
                        2048,
                        0),
                    new Tpm2bPublicKeyRsa()
                );

                var srk = _tpm.CreatePrimary(
                    TpmRh.Owner,
                    new SensitiveCreate(),
                    srkPublic,
                    Array.Empty<byte>(),
                    Array.Empty<PcrSelection>(),
                    out _,
                    out _,
                    out _,
                    out _
                );

                _tpm.EvictControl(TpmRh.Owner, srk, srkHandle);
                _tpm.FlushContext(srk);

                return srkHandle;
            }
        }

        /// <summary>
        /// Seal a secret to the TPM with PCR policy.
        /// Returns both private + public blobs as a byte[] for storage.
        /// </summary>
        public SealedKeyMetadata Seal(byte[] secret, TpmHandle srk)
        {
            if (secret == null || secret.Length == 0)
                throw new ArgumentException(nameof(secret));

            // Ensure the NV counter exists
            EnsureNvCounterExists();

            var session = _tpm.StartAuthSession(
                TpmRh.Null,
                TpmRh.Null,
                RandomNumberGenerator.GetBytes(16),
                Array.Empty<byte>(),
                TpmSe.Policy,
                new SymDef(),
                TpmAlgId.Sha256,
                out _
            );

            try
            {
                var pcrSel = new[] { new PcrSelection(TpmAlgId.Sha256, _pcrs) };

                // ✅ Let TPM handle the hash internally
                _tpm.PolicyPCR(session, null, pcrSel);
                _tpm.PolicyAuthValue(session);

                var sensitive = new SensitiveCreate(
                    Array.Empty<byte>(),
                    secret
                );

                byte[] policyDigest = _tpm.PolicyGetDigest(session);

                var publicArea = new TpmPublic(
                    TpmAlgId.Sha256,  // 🔹 nameAlg MUST be SHA256
                    ObjectAttr.FixedTPM |
                    ObjectAttr.FixedParent |
                    ObjectAttr.AdminWithPolicy |
                    ObjectAttr.NoDA,
                    policyDigest,
                    new KeyedhashParms(new NullSchemeKeyedhash()),
                    new Tpm2bDigestKeyedhash()
                );

                // ✅ Use SRK as parent
                TpmPrivate privateBlob = _tpm.Create(
                    srk,
                    sensitive,
                    publicArea,
                    Array.Empty<byte>(),  // outsideInfo
                    Array.Empty<PcrSelection>(),
                    out _,
                    out _,
                    out _,
                    out _
                );

                // **Increment NV counter after successful seal**
                var value = IncrementLogicalCounter();

                return new SealedKeyMetadata
                {
                    PrivateBlob = privateBlob.buffer,
                    PolicyDigest = policyDigest,
                    Pcrs = _pcrs,
                    NvCounterValue = value,
                };
            }
            finally
            {
                _tpm.FlushContext(session);
            }
        }




        /// <summary>
        /// Unseals the secret from TPM if PCR policy is satisfied.
        /// </summary>
        public byte[] Unseal(SealedKeyMetadata meta)
        {
            var privateBlob = new TpmPrivate(meta.PrivateBlob);

            var session = _tpm.StartAuthSession(
                TpmRh.Null,
                TpmRh.Null,
                RandomNumberGenerator.GetBytes(16),
                Array.Empty<byte>(),
                TpmSe.Policy,
                new SymDef(),
                TpmAlgId.Sha256,
                out _
            );

            try
            {
                var pcrSelection = new[]
                {
            new PcrSelection(TpmAlgId.Sha256, meta.Pcrs)
        };

                _tpm.PolicyPCR(session, null, pcrSelection);
                _tpm.PolicyAuthValue(session);

                var publicArea = new TpmPublic(
                    TpmAlgId.Sha256,
                    ObjectAttr.FixedTPM |
                    ObjectAttr.FixedParent |
                    ObjectAttr.AdminWithPolicy |
                    ObjectAttr.NoDA,
                    meta.PolicyDigest,
                    new KeyedhashParms(new NullSchemeKeyedhash()),
                    new Tpm2bDigestKeyedhash()
                );

                TpmHandle handle = _tpm.Load(
                    TpmRh.Owner,
                    privateBlob,
                    publicArea
                );

                byte[] secret = _tpm.Unseal(handle);
                _tpm.FlushContext(handle);
                return secret;
            }
            finally
            {
                _tpm.FlushContext(session);
            }
        }


        public sealed class SealedKeyMetadata
        {
            public byte[] PrivateBlob { get; init; }
            public byte[] PolicyDigest { get; init; }
            public uint[] Pcrs { get; init; }
            public ulong NvCounterValue { get; set; }

        }
    }
}
