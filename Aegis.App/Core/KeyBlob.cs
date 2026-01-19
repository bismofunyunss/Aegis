using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Aegis.App.Core
{
    public class KeyBlob
    {
        public byte[] RecoveryCiphertext { get; set; } // AES-GCM or AES-KW encrypted master key
        public byte[] RecoveryTag { get; set; }
        public byte[] RecoveryNonce { get; set; }
        public byte[] PasswordSalt { get; set; }
        public byte[] HelloSalt { get; set; }
        public byte[] SealedKek { get; set; } // currently stored in SealedKeyMetadata
        public byte[] PolicyDigest { get; set; } // currently stored in SealedKeyMetadata
        public uint[] Pcrs { get; set; } // currently stored in SealedKeyMetadata
        public ulong NvCounter { get; set; } // currently stored in SealedKeyMetadata
        public byte[] HkdfSalt { get; set; }
        public byte[] PcrBaseLine { get; set; }
        public byte[] LoginCiphertext { get; set; }
        public byte[] LoginNonce { get; set; }
        public byte[] LoginTag { get; set; }
        public byte[] GcmSalt { get; set; }
        public byte[] PrivateBlob { get; set; }
    }
}