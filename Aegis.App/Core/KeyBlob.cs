using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Aegis.App.Core
{
    public class KeyBlob
    {
        public byte[] Ciphertext { get; set; }    // wrapped master key
        public byte[] Tag { get; set; }           // optional AES-GCM tag
        public byte[] Nonce { get; set; }         // optional AES-GCM nonce
        public byte[] PasswordSalt { get; set; }
        public byte[] HelloSalt { get; set; }
        public byte[] SealedKek { get; set; }     // TPM-sealed KEK
        public byte[] PolicyDigest { get; set; }
        public uint[] Pcrs { get; set; }
        public byte[] PcrBaseLine { get; set; }
        public ulong NvCounter { get; set; }
        public byte[] HkdfSalt { get; set; }
    }

}