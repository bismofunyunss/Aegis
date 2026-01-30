using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Aegis.App.Ipc
{
    public sealed class SecureEnvelope
    {
        public string SessionId { get; set; } = string.Empty;

        public ulong Counter { get; set; }

        public string Command { get; set; } = string.Empty;

        public byte[] Nonce { get; set; } = [];

        public byte[] Ciphertext { get; set; } = [];

        public byte[] Tag { get; set; } = [];
    }
}
