using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Aegis.App.Ipc
{
    public sealed class IpcResponse
    {
        public bool Success { get; set; }
        public string Error { get; set; }
        public string Data { get; set; }
    }
}
