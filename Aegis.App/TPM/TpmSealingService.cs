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
            _pcrs = pcrs ?? new uint[] { 0, 2, 4, 7, 11 };
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
        public KeyBlob Seal(byte[] secret, TpmHandle srk, TpmNvCounter counter)
        {
            if (secret == null || secret.Length == 0)
                throw new ArgumentException(nameof(secret));

            // Start a TPM policy session for PCR auth
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
                // Define PCR selection for this blob
                var pcrSel = new[] { new PcrSelection(TpmAlgId.Sha256, _pcrs) };
                _tpm.PolicyPCR(session, null, pcrSel);
                _tpm.PolicyAuthValue(session);

                var sensitive = new SensitiveCreate(Array.Empty<byte>(), secret);
                byte[] policyDigest = _tpm.PolicyGetDigest(session);

                var publicArea = new TpmPublic(
                    TpmAlgId.Sha256,
                    ObjectAttr.FixedTPM |
                    ObjectAttr.FixedParent |
                    ObjectAttr.AdminWithPolicy |
                    ObjectAttr.NoDA,
                    policyDigest,
                    new KeyedhashParms(new NullSchemeKeyedhash()),
                    new Tpm2bDigestKeyedhash()
                );

                // Use SRK as parent
                TpmPrivate privateBlob = _tpm.Create(
                    srk,
                    sensitive,
                    publicArea,
                    Array.Empty<byte>(), // outsideInfo
                    Array.Empty<PcrSelection>(),
                    out _,
                    out _,
                    out _,
                    out _
                );

                // ✅ Increment the NV counter AFTER successful seal
                ulong newCounter = counter.IncrementCounter();

                // ✅ Return blob with updated counter
                return new KeyBlob()
                {
                    PrivateBlob = privateBlob.buffer,
                    PolicyDigest = policyDigest,
                    Pcrs = _pcrs,
                    NvCounter = newCounter
                };
            }
            finally
            {
                _tpm.FlushContext(session);
            }
        }


        public byte[] Unseal(KeyBlob blob, TpmHandle srk, TpmNvCounter counter)
        {
            if (blob == null)
                throw new ArgumentNullException(nameof(blob));

            // ✅ Enforce rollback before unsealing
            counter.EnforceRollback(blob);

            var privateBlob = new TpmPrivate(blob.PrivateBlob);

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
                var pcrSelection = new[] { new PcrSelection(TpmAlgId.Sha256, blob.Pcrs) };
                _tpm.PolicyPCR(session, null, pcrSelection);
                _tpm.PolicyAuthValue(session);

                var publicArea = new TpmPublic(
                    TpmAlgId.Sha256,
                    ObjectAttr.FixedTPM |
                    ObjectAttr.FixedParent |
                    ObjectAttr.AdminWithPolicy |
                    ObjectAttr.NoDA,
                    blob.PolicyDigest,
                    new KeyedhashParms(new NullSchemeKeyedhash()),
                    new Tpm2bDigestKeyedhash()
                );

                TpmHandle handle = _tpm.Load(srk, privateBlob, publicArea);

                byte[] secret = _tpm.Unseal(handle);
                _tpm.FlushContext(handle);

                return secret;
            }
            finally
            {
                _tpm.FlushContext(session);
            }
        }
    }

    public class TpmNvCounter
    {
        private readonly Tpm2 _tpm;
        private readonly uint[] _pcrs;
        private readonly uint _nvIndex;

        public TpmNvCounter(Tpm2 tpm, string username, uint[] pcrs = null)
        {
            _tpm = tpm ?? throw new ArgumentNullException(nameof(tpm));
            _pcrs = pcrs ?? new uint[] { 0, 2, 4, 7, 11 };
            _nvIndex = DeriveNvIndex(username);

            EnsureNvCounterExists();
        }

        /// <summary>
        /// Derive a per-user NV index (safe Tpm2Lib index)
        /// </summary>
        public static uint DeriveNvIndex(string username)
        {
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(username));

            // Use 16-bit value from hash, avoid low reserved indices
            uint offset = (uint)(BinaryPrimitives.ReadUInt16BigEndian(hash) % 0x7FFF);

            return 3000 + offset; // TpmHandle.NV() maps to owner NV space automatically
        }

        /// <summary>
        /// Ensure NV counter exists in TPM
        /// </summary>
        private void EnsureNvCounterExists()
        {
            var nvHandle = TpmHandle.NV(_nvIndex);

            try
            {
                _tpm.NvReadPublic(nvHandle, out _);
                // Already exists → nothing to do
                return;
            }
            catch (TpmException ex) when (ex.RawResponse == TpmRc.Handle || ex.RawResponse == TpmRc.Value)
            {
                // NV not defined → define below
            }

            var nvPublic = new NvPublic(
                nvHandle,
                TpmAlgId.Sha256,
                NvAttr.Counter | NvAttr.Authread | NvAttr.Authwrite | NvAttr.NoDa,
                Array.Empty<byte>(), // policy: none
                8 // 8-byte counter
            );

            try
            {
                _tpm.NvDefineSpace(TpmRh.Owner, Array.Empty<byte>(), nvPublic);
            }
            catch (TpmException ex) when (ex.RawResponse == TpmRc.NvDefined)
            {
                // Another thread/process defined it → OK
            }

            // Increment once to initialize
            _tpm.NvIncrement(TpmRh.Owner, nvHandle);
        }

        /// <summary>
        /// Read the TPM counter value (raw 64-bit)
        /// </summary>
        public ulong GetNvCounter()
        {
            var nvHandle = TpmHandle.NV(_nvIndex);
            byte[] data = _tpm.NvRead(TpmRh.Owner, nvHandle, 8, 0);
            return BinaryPrimitives.ReadUInt64BigEndian(data);
        }

        /// <summary>
        /// Increment TPM counter and return the new value
        /// </summary>
        public ulong IncrementCounter()
        {
            var nvHandle = TpmHandle.NV(_nvIndex);
            _tpm.NvIncrement(TpmRh.Owner, nvHandle);
            return GetNvCounter();
        }

        /// <summary>
        /// Enforce rollback protection: throw if blob counter > TPM counter
        /// </summary>
        public void EnforceRollback(KeyBlob blob)
        {
            if (blob == null) throw new ArgumentNullException(nameof(blob));

            ulong tpmCounter = GetNvCounter();
            if (tpmCounter < blob.NvCounter)
                throw new SecurityException(
                    $"Rollback detected (TPM={tpmCounter}, Blob={blob.NvCounter})"
                );
        }
    }

}
