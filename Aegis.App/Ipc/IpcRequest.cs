using Aegis.Contracts;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Aegis.App.Ipc
{
    public sealed class IpcRequest
    {
        public string Command { get; set; }
        public string Username { get; set; }
        public byte[] Password { get; set; }

        public CryptoSettings? CryptoConfig { get; set; }

        public byte[]? Payload { get; set; }
        public uint[]? Pcrs { get; set; }

        public string? SessionId { get; set; }
        public ulong Counter { get; set; }
    }
}
