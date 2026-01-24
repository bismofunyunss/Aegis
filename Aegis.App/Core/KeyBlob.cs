using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Tpm2Lib;

namespace Aegis.App.Core
{
    public class KeyBlob
    {
        public byte[] LoginCiphertext { get; set; } = Array.Empty<byte>();
        public byte[] LoginNonce { get; set; } = Array.Empty<byte>();
        public byte[] LoginTag { get; set; } = Array.Empty<byte>();
        public byte[] PasswordSalt { get; set; } = Array.Empty<byte>();
        public byte[] HelloSalt { get; set; } = Array.Empty<byte>();
        public byte[] SealedKek { get; set; } = Array.Empty<byte>();
        public byte[] PolicyDigest { get; set; } = Array.Empty<byte>();
        public uint[] Pcrs { get; set; } = Array.Empty<uint>();
        public ulong NvCounter { get; set; }
        public byte[] HkdfSalt { get; set; } = Array.Empty<byte>();
        public byte[] PcrBaseLine { get; set; } = Array.Empty<byte>();
        public byte[] PrivateBlob { get; set; } = Array.Empty<byte>();
        public byte[] RecoveryCiphertext { get; set; } = Array.Empty<byte>();
        public byte[] RecoveryNonce { get; set; } = Array.Empty<byte>();
        public byte[] RecoveryTag { get; set; } = Array.Empty<byte>();
        public byte[] GcmSalt { get; set; } = Array.Empty<byte>();
        public byte[] PublicBlob { get; set; } = Array.Empty<byte>();
    }

}